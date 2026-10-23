// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AnomalyRules are the rule names the anomalies table accepts.
var AnomalyRules = []string{"silence", "replay", "clock_skew", "package_change", "package_downgrade",
	"kernel_no_reboot", "unexpected_reboot", "collector_changed", "peer_outlier"}

// AddAnomaly records an anomaly unless the host has an unexpired
// suppression for the rule, or an open anomaly with the same rule and
// dedupe key (detail["key"]). It reports whether one was recorded.
func (s *Store) AddAnomaly(ctx context.Context, hostID, snapshotID int64, a Anomaly, at time.Time) (bool, error) {
	ts := at.UTC().Format(timeLayout)
	added := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM anomaly_suppressions WHERE host_id = ? AND rule = ? AND until_at > ?`,
			hostID, a.Rule, ts).Scan(&n); err != nil || n > 0 {
			return err
		}
		if key, _ := a.Detail["key"].(string); key != "" {
			if err := tx.QueryRowContext(ctx, `
				SELECT count(*) FROM anomalies WHERE host_id = ? AND rule = ? AND acknowledged_at IS NULL
				  AND json_extract(detail, '$.key') = ?`, hostID, a.Rule, key).Scan(&n); err != nil || n > 0 {
				return err
			}
		}
		added = true
		return addAnomaly(ctx, tx, hostID, snapshotID, ts, a)
	})
	return added, err
}

// AnomalyView is an open anomaly with its host, for lists.
type AnomalyView struct {
	AnomalyRow
	Host IngestHost
}

// OpenAnomalies lists unacknowledged anomalies in the scope, newest first.
func (s *Store) OpenAnomalies(ctx context.Context, sc Scope) ([]AnomalyView, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.rule, a.severity, a.summary, a.detected_at, coalesce(a.snapshot_id, 0),
		       h.id, h.org_id, o.slug, h.name
		FROM anomalies a JOIN hosts h ON h.id = a.host_id JOIN organizations o ON o.id = h.org_id
		WHERE a.acknowledged_at IS NULL ORDER BY a.id DESC LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AnomalyView
	for rows.Next() {
		var v AnomalyView
		var at string
		if err := rows.Scan(&v.ID, &v.Rule, &v.Severity, &v.Summary, &at, &v.SnapshotID,
			&v.Host.ID, &v.Host.OrgID, &v.Host.OrgSlug, &v.Host.Name); err != nil {
			return nil, err
		}
		v.DetectedAt = parseTime(at)
		if sc.CanView(v.Host.OrgID) {
			out = append(out, v)
		}
	}
	return out, rows.Err()
}

// AnomalyHost returns the host an anomaly belongs to (for access checks).
func (s *Store) AnomalyHost(ctx context.Context, id int64) (IngestHost, error) {
	var h IngestHost
	err := s.db.QueryRowContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name FROM anomalies a
		JOIN hosts h ON h.id = a.host_id JOIN organizations o ON o.id = h.org_id WHERE a.id = ?`, id).
		Scan(&h.ID, &h.OrgID, &h.OrgSlug, &h.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return h, fmt.Errorf("anomaly %d: %w", id, ErrNotFound)
	}
	return h, err
}

// AckAnomaly acknowledges an open anomaly with a required note.
func (s *Store) AckAnomaly(ctx context.Context, actor string, userID, id int64, note string, at time.Time) error {
	note, err := normalizeName("note", note)
	if err != nil {
		return err
	}
	host, err := s.AnomalyHost(ctx, id)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var by sql.NullInt64
		if userID != 0 {
			by = sql.NullInt64{Int64: userID, Valid: true}
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE anomalies SET acknowledged_at = ?, acknowledged_by = ?, ack_note = ?
			WHERE id = ? AND acknowledged_at IS NULL`, at.UTC().Format(timeLayout), by, note, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("anomaly %d is already acknowledged", id)
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "anomaly.ack", OrgID: host.OrgID, Target: host.Name,
			Detail: map[string]any{"anomaly": id, "note": note}})
	})
}

// Suppress mutes one rule on one host until a time (always expires).
func (s *Store) Suppress(ctx context.Context, actor string, userID int64, host IngestHost, rule string, until time.Time, note string, now time.Time) error {
	if !containsString(AnomalyRules, rule) {
		return &ValidationError{"rule", fmt.Sprintf("%q must be one of %s", rule, strings.Join(AnomalyRules, ", "))}
	}
	if !until.After(now) || until.After(now.AddDate(1, 0, 0)) {
		return &ValidationError{"until", "must be in the future and within a year"}
	}
	note, err := normalizeName("note", note)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var by sql.NullInt64
		if userID != 0 {
			by = sql.NullInt64{Int64: userID, Valid: true}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO anomaly_suppressions (host_id, rule, until_at, note, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			host.ID, rule, until.UTC().Format(timeLayout), note, by, now.UTC().Format(timeLayout)); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "anomaly.suppress", OrgID: host.OrgID, Target: host.Name,
			Detail: map[string]any{"rule": rule, "until": until.UTC().Format(time.RFC3339), "note": note}})
	})
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ── Inputs for the rules ───────────────────────────────────────────────────

// SnapshotFacts are the fields anomaly rules compare between snapshots.
type SnapshotFacts struct {
	ID              int64
	ReceivedAt      time.Time
	Kernel          string
	UptimeSeconds   int64 // -1 if unknown
	CollectorSHA256 string
	CollectorVer    string
}

// RecentSnapshotFacts returns the host's newest snapshots (newest first).
func (s *Store) RecentSnapshotFacts(ctx context.Context, hostID int64, n int) ([]SnapshotFacts, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, received_at, coalesce(kernel, ''), coalesce(uptime_seconds, -1),
		       coalesce(lower(hex(collector_sha256)), ''), collector_version
		FROM snapshots WHERE host_id = ? ORDER BY received_at DESC, id DESC LIMIT ?`, hostID, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SnapshotFacts
	for rows.Next() {
		var f SnapshotFacts
		var at string
		if err := rows.Scan(&f.ID, &at, &f.Kernel, &f.UptimeSeconds, &f.CollectorSHA256, &f.CollectorVer); err != nil {
			return nil, err
		}
		f.ReceivedAt = parseTime(at)
		out = append(out, f)
	}
	return out, rows.Err()
}

// SnapshotCount counts a host's stored snapshots.
func (s *Store) SnapshotCount(ctx context.Context, hostID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM snapshots WHERE host_id = ?`, hostID).Scan(&n)
	return n, err
}

// CollectorTrust reports whether any collector is trusted, and whether sha is.
func (s *Store) CollectorTrust(ctx context.Context, sha string) (anyTrusted, trusted bool, err error) {
	var n, m int
	err = s.db.QueryRowContext(ctx, `
		SELECT count(*), coalesce(sum(lower(hex(sha256)) = ?), 0) FROM known_collectors`, sha).Scan(&n, &m)
	return n > 0, m > 0, err
}

// InOpenPlan reports whether the host is in an open patch plan.
func (s *Store) InOpenPlan(ctx context.Context, hostID int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT count(*) FROM patch_plan_items i JOIN patch_plans p ON p.id = i.plan_id
		WHERE i.host_id = ? AND p.closed_at IS NULL`, hostID).Scan(&n)
	return n > 0, err
}

// PeerPackages returns, for hosts sharing a tag with hostID (excluding
// it), how many have each of the given package names installed, plus the
// number of peers.
func (s *Store) PeerPackages(ctx context.Context, hostID int64, names []string) (map[string]int, int, error) {
	peersQ := `SELECT DISTINCT h.id FROM hosts h JOIN host_tags t ON t.host_id = h.id
		WHERE h.id != ? AND h.last_snapshot_id IS NOT NULL
		  AND t.tag IN (SELECT tag FROM host_tags WHERE host_id = ?)`
	var peers int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM (`+peersQ+`)`, hostID, hostID).Scan(&peers); err != nil || peers == 0 {
		return nil, 0, err
	}
	out := map[string]int{}
	if len(names) == 0 {
		return out, peers, nil
	}
	b, _ := json.Marshal(names)
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.name, count(DISTINCT h.id) FROM hosts h JOIN packages p ON p.snapshot_id = h.last_snapshot_id
		WHERE h.id IN (`+peersQ+`) AND p.name IN (SELECT value FROM json_each(?))
		GROUP BY p.name`, hostID, hostID, string(b))
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var n int
		if err := rows.Scan(&name, &n); err != nil {
			return nil, 0, err
		}
		out[name] = n
	}
	return out, peers, rows.Err()
}

// SilentHosts lists hosts that reported once but not since cutoff.
func (s *Store) SilentHosts(ctx context.Context, cutoff time.Time) ([]IngestHost, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name FROM hosts h JOIN organizations o ON o.id = h.org_id
		WHERE h.last_seen_at IS NOT NULL AND h.last_seen_at < ?`, cutoff.UTC().Format(timeLayout))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IngestHost
	for rows.Next() {
		var h IngestHost
		if err := rows.Scan(&h.ID, &h.OrgID, &h.OrgSlug, &h.Name); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
