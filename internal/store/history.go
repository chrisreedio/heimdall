// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SnapshotInfo is one stored snapshot of a host.
type SnapshotInfo struct {
	ID             int64
	ReceivedAt     time.Time
	Source         string
	Kernel         string
	OS             string
	UptimeSeconds  int64 // -1 if unknown
	Packages       int
	PendingUpdates int
}

// Snapshots lists a host's snapshots, newest first.
func (s *Store) Snapshots(ctx context.Context, hostID int64, limit int) ([]SnapshotInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.id, s.received_at, s.source, coalesce(s.kernel, ''), coalesce(s.os_pretty, coalesce(s.os_id, '')),
		       coalesce(s.uptime_seconds, -1),
		       (SELECT count(*) FROM packages p WHERE p.snapshot_id = s.id),
		       (SELECT count(*) FROM packages p WHERE p.snapshot_id = s.id AND p.pending_version IS NOT NULL)
		FROM snapshots s WHERE s.host_id = ? ORDER BY s.received_at DESC, s.id DESC LIMIT ?`, hostID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SnapshotInfo
	for rows.Next() {
		var si SnapshotInfo
		var at string
		if err := rows.Scan(&si.ID, &at, &si.Source, &si.Kernel, &si.OS, &si.UptimeSeconds, &si.Packages, &si.PendingUpdates); err != nil {
			return nil, err
		}
		si.ReceivedAt = parseTime(at)
		out = append(out, si)
	}
	return out, rows.Err()
}

// SnapshotPackages loads one snapshot's packages, checking it belongs to
// the host (so a URL can't read another host's snapshot).
func (s *Store) SnapshotPackages(ctx context.Context, hostID, snapshotID int64) ([]InventoryPackage, error) {
	var owner int64
	if err := s.db.QueryRowContext(ctx, `SELECT host_id FROM snapshots WHERE id = ?`, snapshotID).Scan(&owner); err != nil || owner != hostID {
		return nil, fmt.Errorf("snapshot %d: %w", snapshotID, ErrNotFound)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, version, arch, coalesce(source_name, ''), coalesce(source_version, ''), coalesce(pending_version, ''), pending_security
		FROM packages WHERE snapshot_id = ? ORDER BY name, arch`, snapshotID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InventoryPackage
	for rows.Next() {
		var p InventoryPackage
		var sec int64
		if err := rows.Scan(&p.Name, &p.Version, &p.Arch, &p.SourceName, &p.SourceVersion, &p.PendingVersion, &sec); err != nil {
			return nil, err
		}
		p.PendingSecurity = sec == 1
		out = append(out, p)
	}
	return out, rows.Err()
}

// HostsTagged lists hosts with a tag that have reported.
func (s *Store) HostsTagged(ctx context.Context, tag string) ([]IngestHost, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name FROM hosts h
		JOIN organizations o ON o.id = h.org_id
		JOIN host_tags t ON t.host_id = h.id
		WHERE t.tag = ? AND h.last_snapshot_id IS NOT NULL ORDER BY o.slug, h.name`, tag)
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

// Tags lists every tag in use with its host count.
func (s *Store) Tags(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tag, count(*) FROM host_tags GROUP BY tag ORDER BY tag`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		out[t] = n
	}
	return out, rows.Err()
}

// PruneSnapshots deletes snapshots older than olderThan, always keeping
// each host's newest keepPerHost (and its latest). It returns how many went.
func (s *Store) PruneSnapshots(ctx context.Context, olderThan time.Time, keepPerHost int) (int64, error) {
	keepPerHost = max(keepPerHost, 1)
	var n int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			DELETE FROM snapshots WHERE received_at < ?
			  AND id NOT IN (SELECT last_snapshot_id FROM hosts WHERE last_snapshot_id IS NOT NULL)
			  AND id NOT IN (
			      SELECT id FROM (
			          SELECT id, row_number() OVER (PARTITION BY host_id ORDER BY received_at DESC, id DESC) AS rn
			          FROM snapshots) WHERE rn <= ?)`,
			olderThan.UTC().Format(timeLayout), keepPerHost)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		if n > 0 {
			return audit(ctx, tx, AuditEntry{Actor: "heimdall", Action: "snapshots.prune", Detail: map[string]any{"deleted": n}})
		}
		return nil
	})
	return n, err
}
