// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// AuditEntry records a security-relevant action. Entries are append-only.
type AuditEntry struct {
	Actor  string // "cli:<os user>", "user:<id>", "host:<id>"
	Action string // e.g. "host.add"
	OrgID  int64  // 0 if not org-scoped
	Target string
	Detail map[string]any
	IP     string
}

func audit(ctx context.Context, tx *sql.Tx, e AuditEntry) error {
	detail := []byte("{}")
	if len(e.Detail) > 0 {
		var err error
		if detail, err = json.Marshal(e.Detail); err != nil {
			return err
		}
	}
	var org sql.NullInt64
	if e.OrgID != 0 {
		org = sql.NullInt64{Int64: e.OrgID, Valid: true}
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO audit_log (actor, action, org_id, target, detail, ip) VALUES (?, ?, ?, ?, ?, ?)`,
		e.Actor, e.Action, org, e.Target, string(detail), e.IP)
	return err
}

// LastAuditAt returns when an action was last recorded (zero if never).
func (s *Store) LastAuditAt(ctx context.Context, action string) (time.Time, error) {
	var at sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT max(at) FROM audit_log WHERE action = ?`, action).Scan(&at)
	return parseNullTime(at), err
}

// CountOpenAnomalies counts unacknowledged anomalies across all hosts.
func (s *Store) CountOpenAnomalies(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM anomalies WHERE acknowledged_at IS NULL`).Scan(&n)
	return n, err
}
