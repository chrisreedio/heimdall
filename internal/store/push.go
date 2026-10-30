// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

// Web Push (internal/push): the hub's VAPID key, browsers' subscriptions,
// users' notification settings, and notices held for quiet hours or the
// daily digest. Reads use the read pool; the few writes are single short
// statements on the writer.

// PushVAPIDKey returns the hub's VAPID private key, storing one from
// generate the first time it's asked for.
func (s *Store) PushVAPIDKey(ctx context.Context, generate func() ([]byte, error), now time.Time) ([]byte, error) {
	var key []byte
	err := s.rd.QueryRowContext(ctx, `SELECT private_key FROM push_vapid WHERE id = 1`).Scan(&key)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	fresh, err := generate()
	if err != nil {
		return nil, err
	}
	// Another caller may have stored one first: keep whichever is there.
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO push_vapid (id, private_key, created_at) VALUES (1, ?, ?)`,
			fresh, now.UTC().Format(timeLayout)); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT private_key FROM push_vapid WHERE id = 1`).Scan(&key)
	})
	return key, err
}

// PushSubscription is one browser's subscription.
type PushSubscription struct {
	ID          int64
	UserID      int64
	SessionHash []byte
	Endpoint    string
	P256DH      []byte
	Auth        []byte
	Label       string // the device ("iPhone Safari")
	CreatedAt   time.Time
	LastOKAt    time.Time // zero until a push service took a message
	LastError   string
}

// SavePushSubscription stores a subscription made in a session, or moves
// an endpoint the hub already has to this user and session (a browser
// keeps its endpoint across sign-ins).
func (s *Store) SavePushSubscription(ctx context.Context, userID int64, sessionHash [32]byte, endpoint string,
	p256dh, auth []byte, label string, now time.Time) error {
	if len(label) > 64 {
		label = label[:64]
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO push_subscriptions (user_id, session_hash, endpoint, p256dh, auth, label, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (endpoint) DO UPDATE SET user_id = excluded.user_id, session_hash = excluded.session_hash,
			p256dh = excluded.p256dh, auth = excluded.auth, label = excluded.label, created_at = excluded.created_at,
			last_ok_at = '', last_error = ''`,
		userID, sessionHash[:], endpoint, p256dh, auth, label, now.UTC().Format(timeLayout))
	return err
}

// DeletePushSubscription removes a user's subscription by endpoint
// (turning notifications off on that device). Unknown is not an error.
func (s *Store) DeletePushSubscription(ctx context.Context, userID int64, endpoint string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint = ?`, userID, endpoint)
	return err
}

// DeleteSessionPushSubscriptions removes the subscriptions made in one
// session (turning notifications off on this device).
func (s *Store) DeleteSessionPushSubscriptions(ctx context.Context, sessionHash [32]byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE session_hash = ?`, sessionHash[:])
	return err
}

// DropPushSubscription removes a subscription its push service no longer
// knows (404 or 410).
func (s *Store) DropPushSubscription(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE id = ?`, id)
	return err
}

// MarkPushResult records how a send went: errText "" for a success.
func (s *Store) MarkPushResult(ctx context.Context, id int64, now time.Time, errText string) error {
	if len(errText) > 200 {
		errText = errText[:200]
	}
	if errText == "" {
		_, err := s.db.ExecContext(ctx, `UPDATE push_subscriptions SET last_ok_at = ?, last_error = '' WHERE id = ?`,
			now.UTC().Format(timeLayout), id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE push_subscriptions SET last_error = ? WHERE id = ?`, errText, id)
	return err
}

const pushSubCols = `ps.id, ps.user_id, ps.session_hash, ps.endpoint, ps.p256dh, ps.auth, ps.label, ps.created_at, ps.last_ok_at, ps.last_error`

func scanPushSub(sc interface{ Scan(...any) error }) (PushSubscription, error) {
	var p PushSubscription
	var created, ok string
	err := sc.Scan(&p.ID, &p.UserID, &p.SessionHash, &p.Endpoint, &p.P256DH, &p.Auth, &p.Label, &created, &ok, &p.LastError)
	p.CreatedAt, p.LastOKAt = parseTime(created), parseTime(ok)
	return p, err
}

// UserPushSubscriptions lists a user's subscriptions, newest first.
func (s *Store) UserPushSubscriptions(ctx context.Context, userID int64) ([]PushSubscription, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT `+pushSubCols+` FROM push_subscriptions ps
		WHERE ps.user_id = ? ORDER BY ps.created_at DESC, ps.id DESC LIMIT 100`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PushSubscription
	for rows.Next() {
		p, err := scanPushSub(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PushRecipient is a user who has at least one live subscription.
type PushRecipient struct {
	UserID   int64
	Settings PushSettings
	Subs     []PushSubscription
}

// PushRecipients lists users with subscriptions the hub may send to: the
// user isn't disabled and the session the subscription was made in is
// still signed in (a kept session, or one used within idle; idle 0 means
// no idle limit).
func (s *Store) PushRecipients(ctx context.Context, now time.Time, idle time.Duration) ([]PushRecipient, error) {
	idleCut := ""
	if idle > 0 {
		idleCut = now.Add(-idle).UTC().Format(timeLayout)
	}
	rows, err := s.rd.QueryContext(ctx, `SELECT `+pushSubCols+` FROM push_subscriptions ps
		JOIN users u ON u.id = ps.user_id JOIN sessions se ON se.id_hash = ps.session_hash
		WHERE u.disabled_at IS NULL AND se.expires_at > ? AND (se.kept = 1 OR ? = '' OR se.last_seen_at > ?)
		ORDER BY ps.user_id, ps.id`, now.UTC().Format(timeLayout), idleCut, idleCut)
	if err != nil {
		return nil, err
	}
	var out []PushRecipient
	for rows.Next() {
		p, err := scanPushSub(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if n := len(out); n == 0 || out[n-1].UserID != p.UserID {
			out = append(out, PushRecipient{UserID: p.UserID})
		}
		out[len(out)-1].Subs = append(out[len(out)-1].Subs, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Settings, err = s.PushSettings(ctx, out[i].UserID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// PushSettings is a user's notification settings.
type PushSettings struct {
	Modes      map[string]string // event kind -> "immediate", "digest" or "off"; absent = the kind's default
	Quiet      bool              // hold notices during quiet hours
	QuietStart int               // hour, 0-23, in TimeZone
	QuietEnd   int
	TimeZone   string // IANA name, from the browser; "" = UTC
	Detail     string // lock-screen detail: "host" or "hidden"
	DigestDay  string // local date of the last daily digest
}

// DefaultPushSettings are a new user's: quiet from 10 PM to 7 AM, kind
// and host on the lock screen.
var DefaultPushSettings = PushSettings{Quiet: true, QuietStart: 22, QuietEnd: 7, Detail: "host"}

// PushSettings returns a user's settings, or the defaults.
func (s *Store) PushSettings(ctx context.Context, userID int64) (PushSettings, error) {
	p := DefaultPushSettings
	var modes string
	err := s.rd.QueryRowContext(ctx, `SELECT modes, quiet, quiet_start, quiet_end, time_zone, detail, digest_day
		FROM push_settings WHERE user_id = ?`, userID).
		Scan(&modes, &p.Quiet, &p.QuietStart, &p.QuietEnd, &p.TimeZone, &p.Detail, &p.DigestDay)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal([]byte(modes), &p.Modes); err != nil {
		p.Modes = nil
	}
	return p, nil
}

// SetPushSettings stores a user's settings (DigestDay is left as it is).
func (s *Store) SetPushSettings(ctx context.Context, userID int64, p PushSettings) error {
	if p.Modes == nil {
		p.Modes = map[string]string{}
	}
	modes, err := json.Marshal(p.Modes)
	if err != nil {
		return err
	}
	if p.Detail != "hidden" {
		p.Detail = "host"
	}
	if p.QuietStart < 0 || p.QuietStart > 23 || p.QuietEnd < 0 || p.QuietEnd > 23 {
		return &ValidationError{"quiet", "hours must be 0 to 23"}
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO push_settings (user_id, modes, quiet, quiet_start, quiet_end, time_zone, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (user_id) DO UPDATE SET modes = excluded.modes, quiet = excluded.quiet,
			quiet_start = excluded.quiet_start, quiet_end = excluded.quiet_end, time_zone = excluded.time_zone,
			detail = excluded.detail`,
		userID, string(modes), p.Quiet, p.QuietStart, p.QuietEnd, p.TimeZone, p.Detail)
	return err
}

// SetPushTimeZoneIfUnset records the browser's time zone when the user
// subscribes, unless they've set one already.
func (s *Store) SetPushTimeZoneIfUnset(ctx context.Context, userID int64, tz string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO push_settings (user_id, time_zone) VALUES (?, ?)
		ON CONFLICT (user_id) DO UPDATE SET time_zone = excluded.time_zone WHERE push_settings.time_zone = ''`,
		userID, tz)
	return err
}

// SetPushDigestDay records the local date of a user's last daily digest.
func (s *Store) SetPushDigestDay(ctx context.Context, userID int64, day string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO push_settings (user_id, digest_day) VALUES (?, ?)
		ON CONFLICT (user_id) DO UPDATE SET digest_day = excluded.digest_day`, userID, day)
	return err
}

// PushHeld is a notice waiting for the end of quiet hours or the digest.
type PushHeld struct {
	ID      int64
	Kind    string
	OrgSlug string
	Host    string
	Hosts   int // more than one host: how many
	Count   int
	Ref     int64
	At      time.Time
}

// HoldPush keeps a notice for later: for the digest, or until quiet hours end.
func (s *Store) HoldPush(ctx context.Context, userID int64, digest bool, h PushHeld) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO push_held (user_id, digest, kind, org_slug, host, hosts, count, ref, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, digest, h.Kind, h.OrgSlug, h.Host, h.Hosts, h.Count, h.Ref, h.At.UTC().Format(timeLayout))
	return err
}

// PushHeldUsers lists the users with notices held for quiet hours (digest
// false) or the digest (true).
func (s *Store) PushHeldUsers(ctx context.Context, digest bool) (map[int64]bool, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT DISTINCT user_id FROM push_held WHERE digest = ?`, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// TakePushHeld removes and returns a user's held notices, oldest first.
func (s *Store) TakePushHeld(ctx context.Context, userID int64, digest bool) ([]PushHeld, error) {
	rows, err := s.db.QueryContext(ctx, `DELETE FROM push_held WHERE user_id = ? AND digest = ?
		RETURNING id, kind, org_slug, host, hosts, count, ref, created_at`, userID, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PushHeld
	for rows.Next() {
		var h PushHeld
		var at string
		if err := rows.Scan(&h.ID, &h.Kind, &h.OrgSlug, &h.Host, &h.Hosts, &h.Count, &h.Ref, &at); err != nil {
			return nil, err
		}
		h.At = parseTime(at)
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// RETURNING gives no order; the oldest first reads best.
	slices.SortFunc(out, func(a, b PushHeld) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

// ── What notifications watch ───────────────────────────────────────────────

// PushHost is a host, for notifications: where it is and its name.
type PushHost struct {
	ID      int64
	OrgID   int64
	OrgSlug string
	Name    string
}

// HostKEVCounts returns each host's open known-exploited findings, as the
// dashboard counts them (finding_counts).
func (s *Store) HostKEVCounts(ctx context.Context) (map[int64]int, map[int64]PushHost, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name, sum(fc.kev)
		FROM finding_counts fc JOIN hosts h ON h.id = fc.host_id JOIN organizations o ON o.id = h.org_id
		GROUP BY h.id HAVING sum(fc.kev) > 0`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	counts, hosts := map[int64]int{}, map[int64]PushHost{}
	for rows.Next() {
		var h PushHost
		var n int
		if err := rows.Scan(&h.ID, &h.OrgID, &h.OrgSlug, &h.Name, &n); err != nil {
			return nil, nil, err
		}
		counts[h.ID], hosts[h.ID] = n, h
	}
	return counts, hosts, rows.Err()
}

// NewsMatch is a threat-news incident confirmed on a host.
type NewsMatch struct {
	ItemID int64
	Host   PushHost
}

// NewsMatches lists every incident confirmed on a host.
func (s *Store) NewsMatches(ctx context.Context) ([]NewsMatch, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT m.item_id, h.id, h.org_id, o.slug, h.name
		FROM news_matches m JOIN hosts h ON h.id = m.host_id JOIN organizations o ON o.id = h.org_id
		WHERE m.kind = 'confirmed'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NewsMatch
	for rows.Next() {
		var m NewsMatch
		if err := rows.Scan(&m.ItemID, &m.Host.ID, &m.Host.OrgID, &m.Host.OrgSlug, &m.Host.Name); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// PushHostState is what the daily digest counts about a host.
type PushHostState struct {
	PushHost
	PendingSecurity  int
	CollectorVersion string
}

// PushHostStates lists every host that has reported, with its pending
// security updates and collector version.
func (s *Store) PushHostStates(ctx context.Context) ([]PushHostState, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name, coalesce(s.collector_version, ''),
		       (SELECT count(*) FROM packages p WHERE p.snapshot_id = s.id AND p.pending_security = 1)
		FROM hosts h JOIN organizations o ON o.id = h.org_id JOIN snapshots s ON s.id = h.last_snapshot_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PushHostState
	for rows.Next() {
		var h PushHostState
		if err := rows.Scan(&h.ID, &h.OrgID, &h.OrgSlug, &h.Name, &h.CollectorVersion, &h.PendingSecurity); err != nil {
			return nil, err
		}
		h.CollectorVersion = strings.TrimSpace(h.CollectorVersion)
		out = append(out, h)
	}
	return out, rows.Err()
}
