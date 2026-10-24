// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// AI run kinds.
const (
	AIBrief = "brief" // the org's fleet brief
	AIHost  = "host"  // "explain this host"
)

var (
	// ErrAIBusy: a run for the same brief or host is still going.
	ErrAIBusy = errors.New("an analysis is already running")
	// ErrAITooSoon: the last run started too recently (rate limit).
	ErrAITooSoon = errors.New("an analysis started less than a minute ago")
)

// AIRun is one analysis run.
type AIRun struct {
	ID           int64
	OrgID        int64
	HostID       int64 // 0 for briefs
	Kind         string
	Status       string // running, ok, error
	CreatedAt    time.Time
	FinishedAt   time.Time
	RequestedBy  string
	Deployment   string
	Model        string
	InputTokens  int
	OutputTokens int
	Error        string
	Result       []byte // validated JSON (see internal/ai)
}

// AIRunsKept is how many runs are kept per org brief and per host.
const AIRunsKept = 10

// StartAIRun records a new running analysis, unless one for the same
// target is still running (and younger than stale) or the last one started
// less than minGap ago. The check and the insert are one transaction, so
// two clicks can't start two runs.
func (s *Store) StartAIRun(ctx context.Context, orgID, hostID int64, kind, actor, deployment string,
	now time.Time, minGap, stale time.Duration) (int64, error) {
	if (kind != AIBrief && kind != AIHost) || (kind == AIHost) != (hostID != 0) {
		return 0, &ValidationError{"kind", "invalid AI run kind"}
	}
	var id int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var status, created string
		err := tx.QueryRowContext(ctx, `SELECT status, created_at FROM ai_runs
			WHERE org_id = ? AND kind = ? AND coalesce(host_id, 0) = ? ORDER BY id DESC LIMIT 1`,
			orgID, kind, hostID).Scan(&status, &created)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return err
		default:
			age := now.Sub(parseTime(created))
			if status == "running" && age < stale {
				return ErrAIBusy
			}
			if age < minGap {
				return ErrAITooSoon
			}
		}
		var host sql.NullInt64
		if hostID != 0 {
			host = sql.NullInt64{Int64: hostID, Valid: true}
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO ai_runs (org_id, host_id, kind, status, created_at, requested_by, deployment)
			VALUES (?, ?, ?, 'running', ?, ?, ?)`, orgID, host, kind, now.UTC().Format(timeLayout), actor, deployment)
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// FinishAIRun stores a run's outcome and prunes old runs for its target.
func (s *Store) FinishAIRun(ctx context.Context, id int64, status, model string, in, out int, errMsg string, result []byte, at time.Time) error {
	if status != "ok" && status != "error" {
		return &ValidationError{"status", "invalid AI run status"}
	}
	if len(result) == 0 {
		result = []byte("{}")
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var orgID, hostID int64
		var kind string
		if err := tx.QueryRowContext(ctx, `SELECT org_id, coalesce(host_id, 0), kind FROM ai_runs WHERE id = ?`, id).
			Scan(&orgID, &hostID, &kind); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE ai_runs SET status = ?, model = ?, input_tokens = ?, output_tokens = ?,
			error = ?, result = ?, finished_at = ? WHERE id = ?`,
			status, model, in, out, errMsg, string(result), at.UTC().Format(timeLayout), id); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM ai_runs WHERE org_id = ? AND kind = ? AND coalesce(host_id, 0) = ?
			AND id NOT IN (SELECT id FROM ai_runs WHERE org_id = ? AND kind = ? AND coalesce(host_id, 0) = ?
			               ORDER BY id DESC LIMIT ?)`, orgID, kind, hostID, orgID, kind, hostID, AIRunsKept)
		return err
	})
}

// AIRuns lists the runs for an org's brief (hostID 0) or a host's
// explanations, newest first.
func (s *Store) AIRuns(ctx context.Context, orgID, hostID int64, limit int) ([]AIRun, error) {
	kind := AIBrief
	if hostID != 0 {
		kind = AIHost
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, org_id, coalesce(host_id, 0), kind, status, created_at, finished_at,
		requested_by, deployment, model, input_tokens, output_tokens, error, result
		FROM ai_runs WHERE org_id = ? AND kind = ? AND coalesce(host_id, 0) = ? ORDER BY id DESC LIMIT ?`,
		orgID, kind, hostID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AIRun
	for rows.Next() {
		var r AIRun
		var created, result string
		var finished sql.NullString
		if err := rows.Scan(&r.ID, &r.OrgID, &r.HostID, &r.Kind, &r.Status, &created, &finished, &r.RequestedBy,
			&r.Deployment, &r.Model, &r.InputTokens, &r.OutputTokens, &r.Error, &result); err != nil {
			return nil, err
		}
		r.CreatedAt, r.FinishedAt, r.Result = parseTime(created), parseNullTime(finished), []byte(result)
		out = append(out, r)
	}
	return out, rows.Err()
}

// LastAIBrief returns when the org's last brief run started (zero if never).
func (s *Store) LastAIBrief(ctx context.Context, orgID int64) (time.Time, error) {
	var at sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT max(created_at) FROM ai_runs WHERE org_id = ? AND kind = 'brief'`, orgID).Scan(&at)
	return parseNullTime(at), err
}

// FindingChange counts a host's findings that appeared or were resolved
// since a time: the "what changed" part of the fleet brief.
type FindingChange struct{ New, Resolved int }

// FindingChanges returns per-host finding changes in an org since t.
func (s *Store) FindingChanges(ctx context.Context, orgID int64, since time.Time) (map[int64]FindingChange, error) {
	ts := since.UTC().Format(timeLayout)
	rows, err := s.db.QueryContext(ctx, `SELECT f.host_id,
		sum(CASE WHEN f.first_seen_at >= ? THEN 1 ELSE 0 END),
		sum(CASE WHEN f.resolved_at >= ? THEN 1 ELSE 0 END)
		FROM findings f JOIN hosts h ON h.id = f.host_id
		WHERE h.org_id = ? AND (f.first_seen_at >= ? OR f.resolved_at >= ?) GROUP BY f.host_id`, ts, ts, orgID, ts, ts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]FindingChange{}
	for rows.Next() {
		var id int64
		var c FindingChange
		if err := rows.Scan(&id, &c.New, &c.Resolved); err != nil {
			return nil, err
		}
		out[id] = c
	}
	return out, rows.Err()
}
