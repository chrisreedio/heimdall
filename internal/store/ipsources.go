// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"time"
)

// IPSourceState is a synced IP label source's last sync.
type IPSourceState struct {
	Source      string
	LastAttempt time.Time
	LastSuccess time.Time // zero: never
	LastError   string
	Labels      int // ranges stored by the last good sync
}

// RecordIPSourceRun notes a sync attempt; runErr == nil marks it
// successful with n labels stored.
func (s *Store) RecordIPSourceRun(ctx context.Context, source string, at time.Time, n int, runErr error) error {
	ts := at.UTC().Format(timeLayout)
	var success sql.NullString
	msg := ""
	if runErr == nil {
		success = sql.NullString{String: ts, Valid: true}
	} else if msg = runErr.Error(); len(msg) > 500 {
		msg = msg[:500]
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ip_source_state (source, last_attempt_at, last_success_at, last_error, labels) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (source) DO UPDATE SET
			last_attempt_at = excluded.last_attempt_at,
			last_success_at = coalesce(excluded.last_success_at, ip_source_state.last_success_at),
			last_error = excluded.last_error,
			labels = CASE WHEN excluded.last_success_at IS NULL THEN ip_source_state.labels ELSE excluded.labels END`,
		source, ts, success, msg, n)
	return err
}

// IPSourceStates returns every synced source's last sync, by source.
func (s *Store) IPSourceStates(ctx context.Context) ([]IPSourceState, error) {
	rows, err := s.rd.QueryContext(ctx,
		`SELECT source, last_attempt_at, last_success_at, last_error, labels FROM ip_source_state ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPSourceState
	for rows.Next() {
		var st IPSourceState
		var attempt string
		var success sql.NullString
		if err := rows.Scan(&st.Source, &attempt, &success, &st.LastError, &st.Labels); err != nil {
			return nil, err
		}
		st.LastAttempt, st.LastSuccess = parseTime(attempt), parseNullTime(success)
		out = append(out, st)
	}
	return out, rows.Err()
}
