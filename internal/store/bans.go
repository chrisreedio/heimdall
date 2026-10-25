// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

// Ban statuses (migration 0026 describes each).
const (
	BanShadow   = "shadow"
	BanProposed = "proposed"
	BanRejected = "rejected"
	BanLapsed   = "lapsed"
	BanPending  = "pending"
	BanActive   = "active"
	BanLifting  = "lifting"
	BanEnded    = "ended"
)

// BanOpen are the statuses of a ban that isn't over: at most one per target.
var BanOpen = []string{BanProposed, BanPending, BanActive, BanLifting}

// Ban is one proposed, shadow or real ban (internal/bans). Breakdown and
// Evidence are the bans package's JSON.
type Ban struct {
	ID                   int64
	Target, Kind, Action string
	Status, Mode         string
	Score                float64
	Breakdown, Evidence  json.RawMessage
	Orgs                 []int64
	Offense              int
	Duration             time.Duration
	CreatedAt, UpdatedAt time.Time
	DecidedBy            string
	DecidedAt            time.Time
	Note                 string
	StartedAt, ExpiresAt time.Time
	ListID, ItemID       string
	Attempts             int
	LastError            string
	NextTryAt            time.Time
	EndedAt              time.Time
	EndReason            string
}

// Open reports whether the ban isn't over.
func (b Ban) Open() bool { return containsString(BanOpen, b.Status) }

const banCols = `id, target, kind, action, status, mode, score, breakdown, evidence, orgs, offense, duration_s,
	created_at, updated_at, decided_by, decided_at, note, started_at, expires_at, list_id, item_id, attempts,
	last_error, next_try_at, ended_at, end_reason`

type rowScanner interface{ Scan(...any) error }

func scanBan(r rowScanner) (Ban, error) {
	var b Ban
	var breakdown, evidence, orgs, created, updated, decided, started, expires, next, ended string
	var dur int64
	err := r.Scan(&b.ID, &b.Target, &b.Kind, &b.Action, &b.Status, &b.Mode, &b.Score, &breakdown, &evidence, &orgs,
		&b.Offense, &dur, &created, &updated, &b.DecidedBy, &decided, &b.Note, &started, &expires, &b.ListID, &b.ItemID,
		&b.Attempts, &b.LastError, &next, &ended, &b.EndReason)
	if err != nil {
		return b, err
	}
	b.Breakdown, b.Evidence = json.RawMessage(breakdown), json.RawMessage(evidence)
	json.Unmarshal([]byte(orgs), &b.Orgs)
	b.Duration = time.Duration(dur) * time.Second
	b.CreatedAt, b.UpdatedAt, b.DecidedAt = parseTime(created), parseTime(updated), banTime(decided)
	b.StartedAt, b.ExpiresAt, b.NextTryAt, b.EndedAt = banTime(started), banTime(expires), banTime(next), banTime(ended)
	return b, nil
}

func banTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	return parseTime(s)
}

func banTS(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeLayout)
}

func jsonOr(raw json.RawMessage, def string) string {
	if len(raw) == 0 || !json.Valid(raw) {
		return def
	}
	return string(raw)
}

// BanAudit is one row of the ban audit log: a decision or a Cloudflare
// write, and how it went.
type BanAudit struct {
	ID     int64
	At     time.Time
	Actor  string // "user:3", "cli:alice", "heimdall"
	Action string // propose, approve, reject, unban, pause, resume, zone.on, zone.off, cf.list.create, ...
	BanID  int64
	ZoneID string
	Target string
	Result string // ok, error
	Detail map[string]any
}

func addBanAudit(ctx context.Context, tx *sql.Tx, a BanAudit) error {
	detail := []byte("{}")
	if len(a.Detail) > 0 {
		var err error
		if detail, err = json.Marshal(a.Detail); err != nil {
			return err
		}
	}
	if a.Result == "" {
		a.Result = "ok"
	}
	var ban sql.NullInt64
	if a.BanID != 0 {
		ban = sql.NullInt64{Int64: a.BanID, Valid: true}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO ban_audit (at, actor, action, ban_id, zone_id, target, result, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, a.At.UTC().Format(timeLayout), a.Actor, a.Action, ban, a.ZoneID, a.Target, a.Result, string(detail))
	return err
}

// AddBanAudit records a decision or a Cloudflare write.
func (s *Store) AddBanAudit(ctx context.Context, a BanAudit) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return addBanAudit(ctx, tx, a) })
}

// BanAudits returns the newest audit rows, at most limit.
func (s *Store) BanAudits(ctx context.Context, limit int) ([]BanAudit, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, at, actor, action, coalesce(ban_id, 0), zone_id, target, result, detail
		FROM ban_audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BanAudit
	for rows.Next() {
		var a BanAudit
		var at, detail string
		if err := rows.Scan(&a.ID, &at, &a.Actor, &a.Action, &a.BanID, &a.ZoneID, &a.Target, &a.Result, &detail); err != nil {
			return nil, err
		}
		a.At = parseTime(at)
		json.Unmarshal([]byte(detail), &a.Detail)
		out = append(out, a)
	}
	return out, rows.Err()
}

// AddBan stores a new ban (proposed, pending or shadow) and its audit row.
// A target with an open ban already gets ErrExists.
func (s *Store) AddBan(ctx context.Context, b Ban, actor string, now time.Time) (int64, error) {
	var id int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		id, err = insertBan(ctx, tx, b, now)
		if err != nil {
			return err
		}
		return addBanAudit(ctx, tx, BanAudit{At: now, Actor: actor, Action: "ban." + b.Status, BanID: id, Target: b.Target,
			Detail: map[string]any{"action": b.Action, "score": b.Score, "mode": b.Mode, "days": int(b.Duration.Hours() / 24)}})
	})
	return id, err
}

func insertBan(ctx context.Context, tx *sql.Tx, b Ban, now time.Time) (int64, error) {
	orgs, _ := json.Marshal(b.Orgs)
	if b.Orgs == nil {
		orgs = []byte("[]")
	}
	if b.Offense < 1 {
		b.Offense = 1
	}
	ts := now.UTC().Format(timeLayout)
	res, err := tx.ExecContext(ctx, `INSERT INTO bans (target, kind, action, status, mode, score, breakdown, evidence, orgs,
		offense, duration_s, created_at, updated_at, decided_by, decided_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		b.Target, b.Kind, b.Action, b.Status, b.Mode, b.Score, jsonOr(b.Breakdown, "[]"), jsonOr(b.Evidence, "{}"), string(orgs),
		b.Offense, int64(b.Duration/time.Second), ts, ts, b.DecidedBy, banTS(b.DecidedAt), banTS(b.ExpiresAt))
	if err != nil {
		if isUnique(err) {
			return 0, fmt.Errorf("ban for %s: %w", b.Target, ErrExists)
		}
		return 0, err
	}
	return res.LastInsertId()
}

// RecordShadow records what shadow mode would have banned. While an
// earlier shadow record for the target hasn't run out (its would-be
// expiry), that record is refreshed instead, so one attacker is one row.
// It reports whether a new row was added.
func (s *Store) RecordShadow(ctx context.Context, b Ban, now time.Time) (int64, bool, error) {
	var id int64
	added := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT id FROM bans WHERE target = ? AND status = ? AND expires_at > ?
			ORDER BY id DESC LIMIT 1`, b.Target, BanShadow, now.UTC().Format(timeLayout)).Scan(&id)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			b.Status = BanShadow
			if id, err = insertBan(ctx, tx, b, now); err != nil {
				return err
			}
			added = true
			return nil
		case err != nil:
			return err
		}
		orgs, _ := json.Marshal(b.Orgs)
		if b.Orgs == nil {
			orgs = []byte("[]")
		}
		_, err = tx.ExecContext(ctx, `UPDATE bans SET score = max(score, ?), breakdown = ?, evidence = ?, orgs = ?, action = ?,
			updated_at = ? WHERE id = ?`, b.Score, jsonOr(b.Breakdown, "[]"), jsonOr(b.Evidence, "{}"), string(orgs), b.Action,
			now.UTC().Format(timeLayout), id)
		return err
	})
	return id, added, err
}

// BanQuery selects bans.
type BanQuery struct {
	Statuses []string // empty: all
	Since    time.Time
	Limit    int // 0: 500
}

// Bans returns bans, newest first.
func (s *Store) Bans(ctx context.Context, q BanQuery) ([]Ban, error) {
	if q.Limit <= 0 {
		q.Limit = 500
	}
	where, args := []string{"1 = 1"}, []any{}
	if len(q.Statuses) > 0 {
		where = append(where, "status IN (?"+strings.Repeat(", ?", len(q.Statuses)-1)+")")
		for _, st := range q.Statuses {
			args = append(args, st)
		}
	}
	if !q.Since.IsZero() {
		where = append(where, "updated_at >= ?")
		args = append(args, q.Since.UTC().Format(timeLayout))
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+banCols+` FROM bans WHERE `+strings.Join(where, " AND ")+
		` ORDER BY id DESC LIMIT ?`, append(args, q.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		b, err := scanBan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// BanByID returns one ban.
func (s *Store) BanByID(ctx context.Context, id int64) (Ban, error) {
	b, err := scanBan(s.db.QueryRowContext(ctx, `SELECT `+banCols+` FROM bans WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return b, fmt.Errorf("ban %d: %w", id, ErrNotFound)
	}
	return b, err
}

// OpenBan returns the target's open ban, if any.
func (s *Store) OpenBan(ctx context.Context, target string) (Ban, bool, error) {
	b, err := scanBan(s.db.QueryRowContext(ctx, `SELECT `+banCols+` FROM bans WHERE target = ? AND status IN (?, ?, ?, ?)`,
		target, BanProposed, BanPending, BanActive, BanLifting))
	if errors.Is(err, sql.ErrNoRows) {
		return b, false, nil
	}
	return b, err == nil, err
}

// BanOffenses counts the target's earlier real bans since a time (ones
// that went into the list and weren't lifted by hand as a mistake), for
// the doubling duration. LastRejected is when a proposal for it was last
// rejected (zero if never).
func (s *Store) BanOffenses(ctx context.Context, target string, since time.Time) (n int, lastRejected time.Time, err error) {
	var rej sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT
		  coalesce(sum(started_at <> '' AND end_reason <> 'unbanned' AND created_at >= ?), 0),
		  max(CASE WHEN status = 'rejected' THEN decided_at END)
		FROM bans WHERE target = ?`, since.UTC().Format(timeLayout), target).Scan(&n, &rej)
	if rej.Valid && rej.String != "" {
		lastRejected = parseTime(rej.String)
	}
	return n, lastRejected, err
}

// errBanState is a transition the ban's status doesn't allow.
var errBanState = errors.New("not in a state that allows that")

// moveBan changes a ban's status from one of from to to, setting the extra
// columns, and records the audit row, in one transaction.
func (s *Store) moveBan(ctx context.Context, id int64, from []string, to string, set map[string]any, a BanAudit) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var status, target string
		if err := tx.QueryRowContext(ctx, `SELECT status, target FROM bans WHERE id = ?`, id).Scan(&status, &target); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("ban %d: %w", id, ErrNotFound)
			}
			return err
		}
		if !containsString(from, status) {
			return fmt.Errorf("ban %d is %s: %w", id, status, errBanState)
		}
		cols := []string{"status = ?", "updated_at = ?"}
		args := []any{to, a.At.UTC().Format(timeLayout)}
		for _, k := range sortedKeys(set) {
			cols = append(cols, k+" = ?")
			args = append(args, set[k])
		}
		if _, err := tx.ExecContext(ctx, `UPDATE bans SET `+strings.Join(cols, ", ")+` WHERE id = ?`, append(args, id)...); err != nil {
			if isUnique(err) {
				return fmt.Errorf("ban for %s: another is already open: %w", target, ErrExists)
			}
			return err
		}
		a.BanID, a.Target = id, target
		if a.Detail == nil {
			a.Detail = map[string]any{}
		}
		a.Detail["from"] = status
		return addBanAudit(ctx, tx, a)
	})
}

func sortedKeys(m map[string]any) []string {
	return slices.Sorted(maps.Keys(m))
}

// IsBanState reports whether err is a transition the ban's status refused.
func IsBanState(err error) bool { return errors.Is(err, errBanState) }

// DecideBan approves (proposed → pending) or rejects a proposal.
func (s *Store) DecideBan(ctx context.Context, id int64, approve bool, actor, note string, now time.Time) error {
	note = strings.TrimSpace(note)
	if len(note) > 500 {
		note = note[:500]
	}
	set := map[string]any{"decided_by": actor, "decided_at": now.UTC().Format(timeLayout), "note": note}
	if approve {
		return s.moveBan(ctx, id, []string{BanProposed}, BanPending, set, BanAudit{At: now, Actor: actor, Action: "approve"})
	}
	set["ended_at"], set["end_reason"] = now.UTC().Format(timeLayout), "rejected"
	return s.moveBan(ctx, id, []string{BanProposed}, BanRejected, set, BanAudit{At: now, Actor: actor, Action: "reject"})
}

// Unban lifts a ban by hand: an active one is queued for removal from the
// list, one not yet written simply ends.
func (s *Store) Unban(ctx context.Context, id int64, actor string, now time.Time) error {
	b, err := s.BanByID(ctx, id)
	if err != nil {
		return err
	}
	a := BanAudit{At: now, Actor: actor, Action: "unban"}
	switch b.Status {
	case BanActive:
		return s.moveBan(ctx, id, []string{BanActive}, BanLifting, map[string]any{"end_reason": "unbanned", "next_try_at": ""}, a)
	case BanPending:
		return s.moveBan(ctx, id, []string{BanPending}, BanEnded,
			map[string]any{"end_reason": "unbanned", "ended_at": now.UTC().Format(timeLayout)}, a)
	case BanLifting:
		return nil // already on its way out
	}
	return fmt.Errorf("ban %d is %s: %w", id, b.Status, errBanState)
}

// CancelBan ends a ban that hasn't been written (pending or proposed),
// e.g. because IP awareness vouches for the address now.
func (s *Store) CancelBan(ctx context.Context, id int64, reason, actor string, now time.Time) error {
	return s.moveBan(ctx, id, []string{BanPending, BanProposed}, BanEnded,
		map[string]any{"end_reason": reason, "ended_at": now.UTC().Format(timeLayout)},
		BanAudit{At: now, Actor: actor, Action: "cancel", Detail: map[string]any{"reason": reason}})
}

// BanApplied marks a pending ban as in the list: its time starts now.
func (s *Store) BanApplied(ctx context.Context, id int64, listID, itemID string, now time.Time) error {
	b, err := s.BanByID(ctx, id)
	if err != nil {
		return err
	}
	return s.moveBan(ctx, id, []string{BanPending}, BanActive, map[string]any{
		"list_id": listID, "item_id": itemID, "started_at": now.UTC().Format(timeLayout),
		"expires_at": now.Add(b.Duration).UTC().Format(timeLayout), "attempts": 0, "last_error": "", "next_try_at": "",
	}, BanAudit{At: now, Actor: "heimdall", Action: "cf.item.add", Detail: map[string]any{"list": listID, "item": itemID}})
}

// BanLifted marks a lifting ban as removed from the list.
func (s *Store) BanLifted(ctx context.Context, id int64, now time.Time) error {
	return s.moveBan(ctx, id, []string{BanLifting}, BanEnded, map[string]any{
		"ended_at": now.UTC().Format(timeLayout), "attempts": 0, "last_error": "", "next_try_at": "",
	}, BanAudit{At: now, Actor: "heimdall", Action: "cf.item.delete"})
}

// BanWriteFailed records a failed Cloudflare write for a ban: its state
// stays, and it's retried after next.
func (s *Store) BanWriteFailed(ctx context.Context, id int64, action string, werr error, next, now time.Time) error {
	msg := werr.Error()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var target string
		if err := tx.QueryRowContext(ctx, `UPDATE bans SET attempts = attempts + 1, last_error = ?, next_try_at = ?, updated_at = ?
			WHERE id = ? RETURNING target`, msg, banTS(next), now.UTC().Format(timeLayout), id).Scan(&target); err != nil {
			return err
		}
		return addBanAudit(ctx, tx, BanAudit{At: now, Actor: "heimdall", Action: action, BanID: id, Target: target,
			Result: "error", Detail: map[string]any{"error": msg}})
	})
}

// BanWaiting notes why a pending ban isn't written yet (a cap, a pause),
// without counting it as a failure.
func (s *Store) BanWaiting(ctx context.Context, id int64, why string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE bans SET last_error = ? WHERE id = ? AND status = ?`, why, id, BanPending)
	return err
}

// ExpireBans moves active bans whose time is up to lifting.
func (s *Store) ExpireBans(ctx context.Context, now time.Time) (int, error) {
	ts := now.UTC().Format(timeLayout)
	n := 0
	err := s.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `UPDATE bans SET status = ?, end_reason = 'expired', updated_at = ?
			WHERE status = ? AND expires_at <> '' AND expires_at <= ? RETURNING id, target`, BanLifting, ts, BanActive, ts)
		if err != nil {
			return err
		}
		var done []BanAudit
		for rows.Next() {
			a := BanAudit{At: now, Actor: "heimdall", Action: "expire"}
			if err := rows.Scan(&a.BanID, &a.Target); err != nil {
				rows.Close()
				return err
			}
			done = append(done, a)
		}
		rows.Close()
		for _, a := range done {
			if err := addBanAudit(ctx, tx, a); err != nil {
				return err
			}
		}
		n = len(done)
		return nil
	})
	return n, err
}

// LapseProposals closes proposals nobody decided on since before.
func (s *Store) LapseProposals(ctx context.Context, before, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE bans SET status = ?, end_reason = 'lapsed', ended_at = ?, updated_at = ?
		WHERE status = ? AND created_at < ?`, BanLapsed, now.UTC().Format(timeLayout), now.UTC().Format(timeLayout),
		BanProposed, before.UTC().Format(timeLayout))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// BanCounts are what the caps compare against.
type BanCounts struct {
	Active       int // active, plus pending ones about to be (the global cap)
	StartedSince int // went into the list since the time asked
}

// CountBans counts active and recently started bans.
func (s *Store) CountBans(ctx context.Context, since time.Time) (BanCounts, error) {
	var c BanCounts
	err := s.db.QueryRowContext(ctx, `SELECT coalesce(sum(status IN ('active', 'lifting')), 0),
		coalesce(sum(started_at <> '' AND started_at >= ?), 0) FROM bans`, since.UTC().Format(timeLayout)).Scan(&c.Active, &c.StartedSince)
	return c, err
}

// ── Zones ──────────────────────────────────────────────────────────────────

// Ban zone states.
const (
	BanZoneOK    = "ok"
	BanZoneError = "error"
	BanZoneOff   = "off"
)

// BanZone is one zone's opt-in and where its rules stand.
type BanZone struct {
	ZoneID, Zone string
	Enabled      bool
	State, Note  string
	RulesetID    string
	Rules        map[string]string // action → rule ID
	UpdatedBy    string
	UpdatedAt    time.Time
	AppliedAt    time.Time
}

// BanZones returns every zone that was ever opted in, by name.
func (s *Store) BanZones(ctx context.Context) (map[string]BanZone, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT zone_id, zone, enabled, state, note, ruleset_id, rules, updated_by, updated_at, applied_at
		FROM ban_zones ORDER BY zone`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]BanZone{}
	for rows.Next() {
		var z BanZone
		var rules, updated, applied string
		if err := rows.Scan(&z.ZoneID, &z.Zone, &z.Enabled, &z.State, &z.Note, &z.RulesetID, &rules, &z.UpdatedBy, &updated, &applied); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(rules), &z.Rules)
		z.UpdatedAt, z.AppliedAt = parseTime(updated), banTime(applied)
		out[z.ZoneID] = z
	}
	return out, rows.Err()
}

// SetBanZone turns the ban rules on or off for a zone. The rules are
// written (or removed) by the next Cloudflare sync, so the state resets.
func (s *Store) SetBanZone(ctx context.Context, zoneID, zone string, enabled bool, actor string, now time.Time) error {
	ts := now.UTC().Format(timeLayout)
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ban_zones (zone_id, zone, enabled, state, updated_by, updated_at)
			VALUES (?, ?, ?, '', ?, ?)
			ON CONFLICT (zone_id) DO UPDATE SET zone = excluded.zone, enabled = excluded.enabled, state = '', note = '',
			  updated_by = excluded.updated_by, updated_at = excluded.updated_at`, zoneID, zone, enabled, actor, ts); err != nil {
			return err
		}
		action := "zone.off"
		if enabled {
			action = "zone.on"
		}
		return addBanAudit(ctx, tx, BanAudit{At: now, Actor: actor, Action: action, ZoneID: zoneID, Target: zone})
	})
}

// SetBanZoneState records where a zone's rules stand after a sync.
func (s *Store) SetBanZoneState(ctx context.Context, zoneID, state, note, rulesetID string, rules map[string]string, now time.Time) error {
	b, _ := json.Marshal(rules)
	if rules == nil {
		b = []byte("{}")
	}
	if len(note) > 500 {
		note = note[:500]
	}
	applied := ""
	if state == BanZoneOK || state == BanZoneOff {
		applied = now.UTC().Format(timeLayout)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE ban_zones SET state = ?, note = ?, ruleset_id = ?, rules = ?,
		applied_at = CASE WHEN ? <> '' THEN ? ELSE applied_at END WHERE zone_id = ?`,
		state, note, rulesetID, string(b), applied, applied, zoneID)
	return err
}

// ── Small state ────────────────────────────────────────────────────────────

// BanStateGet reads a named value into out; false when it was never set.
func (s *Store) BanStateGet(ctx context.Context, key string, out any) (bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM ban_state WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(v), out)
}

// BanStateSet stores a named value.
func (s *Store) BanStateSet(ctx context.Context, key string, v any, now time.Time) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO ban_state (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, key, string(b), now.UTC().Format(timeLayout))
	return err
}

// BanPause is the "pause all" switch: while Paused, Heimdall writes
// nothing to Cloudflare.
type BanPause struct {
	Paused bool      `json:"paused"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
	Note   string    `json:"note,omitempty"`
}

const banPauseKey = "pause"

// BanPaused reads the switch.
func (s *Store) BanPaused(ctx context.Context) (BanPause, error) {
	var p BanPause
	_, err := s.BanStateGet(ctx, banPauseKey, &p)
	return p, err
}

// SetBanPaused flips the switch and audits it.
func (s *Store) SetBanPaused(ctx context.Context, paused bool, actor, note string, now time.Time) error {
	if err := s.BanStateSet(ctx, banPauseKey, BanPause{Paused: paused, By: actor, At: now.UTC(), Note: note}, now); err != nil {
		return err
	}
	action := "resume"
	if paused {
		action = "pause"
	}
	return s.AddBanAudit(ctx, BanAudit{At: now, Actor: actor, Action: action, Detail: map[string]any{"note": note}})
}

// ── Inputs ─────────────────────────────────────────────────────────────────

// LoginDays counts, per address, the distinct UTC days with a failure
// since a time, on every host (persistence across days).
func (s *Store) LoginDays(ctx context.Context, since time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ip, count(DISTINCT day) FROM login_failures WHERE last_at >= ? GROUP BY ip`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var ip string
		var n int
		if err := rows.Scan(&ip, &n); err != nil {
			return nil, err
		}
		out[ip] = n
	}
	return out, rows.Err()
}

// LoginSuccess is a day on which an address failed and then logged in.
type LoginSuccess struct {
	Host     IngestHost
	Day, IP  string
	Failures int
	Last     time.Time
}

// LoginSuccessesSince lists (host, day, address) rows with "then
// succeeded" set, last seen since a time.
func (s *Store) LoginSuccessesSince(ctx context.Context, since time.Time) ([]LoginSuccess, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name, f.day, f.ip, f.failures, f.last_at
		FROM login_failures f JOIN hosts h ON h.id = f.host_id JOIN organizations o ON o.id = h.org_id
		WHERE f.succeeded = 1 AND f.last_at >= ? ORDER BY f.last_at`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoginSuccess
	for rows.Next() {
		var r LoginSuccess
		var last int64
		if err := rows.Scan(&r.Host.ID, &r.Host.OrgID, &r.Host.OrgSlug, &r.Host.Name, &r.Day, &r.IP, &r.Failures, &last); err != nil {
			return nil, err
		}
		r.Last = time.Unix(last, 0).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// SignInIPs lists the addresses anyone signed in to Heimdall from since a
// time (open sessions and audited sign-ins), in any org.
func (s *Store) SignInIPs(ctx context.Context, since time.Time) ([]string, error) {
	ts := since.UTC().Format(timeLayout)
	rows, err := s.db.QueryContext(ctx, `
		SELECT ip FROM sessions WHERE ip <> '' AND last_seen_at >= ?
		UNION
		SELECT ip FROM audit_log WHERE ip <> '' AND at >= ? AND action IN (`+signInActions+`)`, ts, ts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// AnomalyKeySeen reports whether the host ever had an anomaly (open or
// acknowledged) for the rule with this dedupe key, so an event raises one
// anomaly even after it's acknowledged.
func (s *Store) AnomalyKeySeen(ctx context.Context, hostID int64, rule, key string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM anomalies WHERE host_id = ? AND rule = ? AND json_extract(detail, '$.key') = ?`,
		hostID, rule, key).Scan(&n)
	return n > 0, err
}
