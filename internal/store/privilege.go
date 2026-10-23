// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// PrivilegeRetention is how long privilege events are kept.
const PrivilegeRetention = 180 * 24 * time.Hour

// PrivilegeEvent is one privileged access a server's privilege watch
// recorded: when, which kind (sudo, su or root-ssh) and, only if the
// server opted in to usernames, who ("?" for a name that didn't validate).
type PrivilegeEvent struct {
	At   time.Time
	Kind string
	User string
}

// RecordPrivilege stores a host's reported events, skipping ones already
// stored (collectors resend the last 7 days on every push), and its watch
// state ("" if it didn't report one). It returns the events that were new
// and the state the host reported before this one ("" if none).
func (s *Store) RecordPrivilege(ctx context.Context, hostID int64, events []PrivilegeEvent, state string, now time.Time) (fresh []PrivilegeEvent, prev string, err error) {
	ts := now.UTC().Format(timeLayout)
	err = s.tx(ctx, func(tx *sql.Tx) error {
		for _, ev := range events {
			res, err := tx.ExecContext(ctx, `
				INSERT INTO privilege_events (host_id, at, kind, user, received_at) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT DO NOTHING`, hostID, ev.At.Unix(), ev.Kind, ev.User, ts)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				fresh = append(fresh, ev)
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM privilege_events WHERE host_id = ? AND at < ?`,
			hostID, now.Add(-PrivilegeRetention).Unix()); err != nil {
			return err
		}
		err := tx.QueryRowContext(ctx, `SELECT state FROM privilege_watch WHERE host_id = ?`, hostID).Scan(&prev)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if state == "" {
			return nil
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO privilege_watch (host_id, state, ever_on, updated_at) VALUES (?, ?, ?, ?)
			ON CONFLICT (host_id) DO UPDATE SET state = excluded.state,
			  ever_on = max(ever_on, excluded.ever_on), updated_at = excluded.updated_at`,
			hostID, state, state == "on", ts)
		return err
	})
	return fresh, prev, err
}

// PrivilegeSummary is what the host page shows about privileged access.
type PrivilegeSummary struct {
	State  string // last reported watch state; "" if never reported
	EverOn bool   // the host has reported "on" at least once
	Counts map[string]int
	Last   time.Time // newest event, zero if none
}

// PrivilegeSummary counts a host's events since a time.
func (s *Store) PrivilegeSummary(ctx context.Context, hostID int64, since time.Time) (PrivilegeSummary, error) {
	var sum PrivilegeSummary
	err := s.db.QueryRowContext(ctx, `SELECT state, ever_on FROM privilege_watch WHERE host_id = ?`, hostID).
		Scan(&sum.State, &sum.EverOn)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return sum, err
	}
	var last sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT max(at) FROM privilege_events WHERE host_id = ?`, hostID).Scan(&last); err != nil {
		return sum, err
	}
	if last.Valid {
		sum.Last = time.Unix(last.Int64, 0).UTC()
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT kind, count(*) FROM privilege_events WHERE host_id = ? AND at >= ? GROUP BY kind`, hostID, since.Unix())
	if err != nil {
		return sum, err
	}
	defer rows.Close()
	sum.Counts = map[string]int{}
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			return sum, err
		}
		sum.Counts[kind] = n
	}
	return sum, rows.Err()
}

// CountAnomaly adds to an open anomaly that counts things, identified by
// its rule and dedupe key (a.Detail["key"]), or raises a new one if none
// is open. detail["counts"] holds per-kind counts and detail["users"] the
// usernames seen; summarize writes the summary from them. A suppression on
// the rule stops both. It reports whether an anomaly was newly raised.
func (s *Store) CountAnomaly(ctx context.Context, hostID, snapshotID int64, a Anomaly, add map[string]int, users []string,
	summarize func(counts map[string]int, users []string) string, at time.Time) (bool, error) {
	ts := at.UTC().Format(timeLayout)
	key, _ := a.Detail["key"].(string)
	raised := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM anomaly_suppressions WHERE host_id = ? AND rule = ? AND until_at > ?`,
			hostID, a.Rule, ts).Scan(&n); err != nil || n > 0 {
			return err
		}
		var id int64
		var raw string
		err := tx.QueryRowContext(ctx, `
			SELECT id, detail FROM anomalies WHERE host_id = ? AND rule = ? AND acknowledged_at IS NULL
			  AND json_extract(detail, '$.key') = ? ORDER BY id DESC LIMIT 1`, hostID, a.Rule, key).Scan(&id, &raw)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var old struct {
			Counts map[string]int `json:"counts"`
			Users  []string       `json:"users"`
		}
		if err == nil {
			_ = json.Unmarshal([]byte(raw), &old) // a bad old detail just restarts the count
		}
		counts := map[string]int{}
		for k, v := range old.Counts {
			counts[k] = v
		}
		for k, v := range add {
			counts[k] += v
		}
		all := slices.Clone(old.Users)
		for _, u := range users {
			if !slices.Contains(all, u) && len(all) < 20 {
				all = append(all, u)
			}
		}
		slices.Sort(all)
		detail := map[string]any{}
		for k, v := range a.Detail {
			detail[k] = v
		}
		detail["counts"] = counts
		if len(all) > 0 {
			detail["users"] = all
		}
		a.Detail = detail
		a.Summary = summarize(counts, all)
		if id == 0 {
			raised = true
			return addAnomaly(ctx, tx, hostID, snapshotID, ts, a)
		}
		b, err := json.Marshal(detail)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE anomalies SET summary = ?, detail = ? WHERE id = ?`, a.Summary, string(b), id)
		return err
	})
	return raised, err
}
