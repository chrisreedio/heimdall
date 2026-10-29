// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Plan is a patch plan: hosts grouped into batches to patch and tick off.
// A ticked host is verified automatically by the first snapshot received
// afterwards that has no pending security updates.
type Plan struct {
	ID        int64
	Name      string
	OrgID     int64  // 0 = cross-org (admins only)
	OrgSlug   string // "" for cross-org
	CreatedAt time.Time
	ClosedAt  time.Time // zero while open
	Hosts     int
	Done      int
	Verified  int
}

type PlanItem struct {
	Host       IngestHost
	Batch      int
	DoneAt     time.Time // zero until ticked
	DoneBy     string    // email of who ticked it
	VerifiedAt time.Time // zero until a clean snapshot arrives after DoneAt
	// PendingSecurity is the host's current count of pending security updates.
	PendingSecurity int
}

// CreatePlan starts a plan, in one org or (orgSlug "") across orgs.
func (s *Store) CreatePlan(ctx context.Context, actor string, createdBy int64, orgSlug, name string) (Plan, error) {
	name, err := normalizeName("name", name)
	if err != nil {
		return Plan{}, err
	}
	p := Plan{Name: name, OrgSlug: orgSlug}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var org sql.NullInt64
		if orgSlug != "" {
			id, err := orgIDBySlug(ctx, tx, orgSlug)
			if err != nil {
				return err
			}
			org, p.OrgID = sql.NullInt64{Int64: id, Valid: true}, id
		}
		var by sql.NullInt64
		if createdBy != 0 {
			by = sql.NullInt64{Int64: createdBy, Valid: true}
		}
		var created string
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO patch_plans (org_id, name, created_by) VALUES (?, ?, ?) RETURNING id, created_at`,
			org, name, by).Scan(&p.ID, &created); err != nil {
			return err
		}
		p.CreatedAt = parseTime(created)
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "plan.create", OrgID: p.OrgID,
			Target: fmt.Sprint(p.ID), Detail: map[string]any{"name": name}})
	})
	return p, err
}

// PlanByID loads a plan's summary.
func (s *Store) PlanByID(ctx context.Context, id int64) (Plan, error) {
	plans, err := s.plans(ctx, `WHERE p.id = ?`, id)
	if err != nil {
		return Plan{}, err
	}
	if len(plans) == 0 {
		return Plan{}, fmt.Errorf("plan %d: %w", id, ErrNotFound)
	}
	return plans[0], nil
}

// ListPlans returns plans visible in the scope, open ones first.
func (s *Store) ListPlans(ctx context.Context, sc Scope) ([]Plan, error) {
	all, err := s.plans(ctx, ``)
	if err != nil {
		return nil, err
	}
	var out []Plan
	for _, p := range all {
		if sc.CanViewPlan(p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// CanViewPlan: org plans follow the org's roles; cross-org plans are admin-only.
func (sc Scope) CanViewPlan(p Plan) bool {
	if p.OrgID == 0 {
		return sc.Admin
	}
	return sc.CanView(p.OrgID)
}

// CanOperatePlan: creating, editing and ticking need operator.
func (sc Scope) CanOperatePlan(p Plan) bool {
	if p.OrgID == 0 {
		return sc.Admin
	}
	return sc.CanOperate(p.OrgID)
}

func (s *Store) plans(ctx context.Context, where string, args ...any) ([]Plan, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT p.id, p.name, coalesce(p.org_id, 0), coalesce(o.slug, ''), p.created_at, p.closed_at,
		       (SELECT count(*) FROM patch_plan_items i WHERE i.plan_id = p.id),
		       (SELECT count(*) FROM patch_plan_items i WHERE i.plan_id = p.id AND i.done_at IS NOT NULL),
		       (SELECT count(*) FROM patch_plan_items i WHERE i.plan_id = p.id AND i.verified_at IS NOT NULL)
		FROM patch_plans p LEFT JOIN organizations o ON o.id = p.org_id `+where+`
		ORDER BY p.closed_at IS NOT NULL, p.created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Plan
	for rows.Next() {
		var p Plan
		var created string
		var closed sql.NullString
		if err := rows.Scan(&p.ID, &p.Name, &p.OrgID, &p.OrgSlug, &created, &closed, &p.Hosts, &p.Done, &p.Verified); err != nil {
			return nil, err
		}
		p.CreatedAt, p.ClosedAt = parseTime(created), parseNullTime(closed)
		out = append(out, p)
	}
	return out, rows.Err()
}

// PlanItems lists a plan's hosts by batch.
func (s *Store) PlanItems(ctx context.Context, planID int64) ([]PlanItem, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name, i.batch, i.done_at, coalesce(u.email, ''), i.verified_at,
		       coalesce((SELECT count(*) FROM packages p WHERE p.snapshot_id = h.last_snapshot_id AND p.pending_security = 1), 0)
		FROM patch_plan_items i
		JOIN hosts h ON h.id = i.host_id
		JOIN organizations o ON o.id = h.org_id
		LEFT JOIN users u ON u.id = i.done_by
		WHERE i.plan_id = ? ORDER BY i.batch, o.slug, h.name`, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PlanItem
	for rows.Next() {
		var it PlanItem
		var done, verified sql.NullString
		if err := rows.Scan(&it.Host.ID, &it.Host.OrgID, &it.Host.OrgSlug, &it.Host.Name, &it.Batch, &done,
			&it.DoneBy, &verified, &it.PendingSecurity); err != nil {
			return nil, err
		}
		it.DoneAt, it.VerifiedAt = parseNullTime(done), parseNullTime(verified)
		out = append(out, it)
	}
	return out, rows.Err()
}

// AddToPlan puts a host in a batch (moving it if already in the plan). An
// org plan only accepts that org's hosts.
func (s *Store) AddToPlan(ctx context.Context, actor string, planID int64, host IngestHost, batch int) error {
	if batch < 1 || batch > 1000 {
		return &ValidationError{"batch", "must be between 1 and 1000"}
	}
	p, err := s.PlanByID(ctx, planID)
	if err != nil {
		return err
	}
	if !p.ClosedAt.IsZero() {
		return fmt.Errorf("plan %d is closed", planID)
	}
	if p.OrgID != 0 && host.OrgID != p.OrgID {
		return &ValidationError{"host", fmt.Sprintf("%s isn't in org %s", host.Name, p.OrgSlug)}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO patch_plan_items (plan_id, host_id, batch) VALUES (?, ?, ?)
			ON CONFLICT (plan_id, host_id) DO UPDATE SET batch = excluded.batch`, planID, host.ID, batch); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "plan.add", OrgID: host.OrgID,
			Target: fmt.Sprint(planID), Detail: map[string]any{"host": host.Name, "batch": batch}})
	})
}

// RemoveFromPlan takes a host out of a plan.
func (s *Store) RemoveFromPlan(ctx context.Context, actor string, planID int64, host IngestHost) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM patch_plan_items WHERE plan_id = ? AND host_id = ?`, planID, host.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%s isn't in plan %d: %w", host.Name, planID, ErrNotFound)
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "plan.remove", OrgID: host.OrgID,
			Target: fmt.Sprint(planID), Detail: map[string]any{"host": host.Name}})
	})
}

// SetPlanItemDone ticks (or unticks) a host. Unticking clears verification.
func (s *Store) SetPlanItemDone(ctx context.Context, actor string, userID, planID int64, host IngestHost, done bool, at time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var res sql.Result
		var err error
		if done {
			var by sql.NullInt64
			if userID != 0 {
				by = sql.NullInt64{Int64: userID, Valid: true}
			}
			res, err = tx.ExecContext(ctx, `
				UPDATE patch_plan_items SET done_at = ?, done_by = ?, verified_at = NULL
				WHERE plan_id = ? AND host_id = ?`, at.UTC().Format(timeLayout), by, planID, host.ID)
		} else {
			res, err = tx.ExecContext(ctx, `
				UPDATE patch_plan_items SET done_at = NULL, done_by = NULL, verified_at = NULL
				WHERE plan_id = ? AND host_id = ?`, planID, host.ID)
		}
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%s isn't in plan %d: %w", host.Name, planID, ErrNotFound)
		}
		action := map[bool]string{true: "plan.done", false: "plan.undone"}[done]
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: action, OrgID: host.OrgID,
			Target: fmt.Sprint(planID), Detail: map[string]any{"host": host.Name}})
	})
}

// ClosePlan closes (or reopens) a plan.
func (s *Store) ClosePlan(ctx context.Context, actor string, planID int64, closed bool, at time.Time) error {
	p, err := s.PlanByID(ctx, planID)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var ts sql.NullString
		if closed {
			ts = sql.NullString{String: at.UTC().Format(timeLayout), Valid: true}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE patch_plans SET closed_at = ? WHERE id = ?`, ts, planID); err != nil {
			return err
		}
		action := map[bool]string{true: "plan.close", false: "plan.reopen"}[closed]
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: action, OrgID: p.OrgID, Target: fmt.Sprint(planID)})
	})
}

// verifyPlanItems runs inside SaveSnapshot: ticked items for this host are
// verified once a snapshot received after the tick has no pending security
// updates.
func verifyPlanItems(ctx context.Context, tx *sql.Tx, hostID, snapshotID int64, received string) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE patch_plan_items SET verified_at = ?
		WHERE host_id = ? AND done_at IS NOT NULL AND verified_at IS NULL AND done_at <= ?
		  AND NOT EXISTS (SELECT 1 FROM packages WHERE snapshot_id = ? AND pending_security = 1)
		  AND plan_id IN (SELECT id FROM patch_plans WHERE closed_at IS NULL)`,
		received, hostID, received, snapshotID)
	return err
}
