// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/snapshot"
)

// IngestHost is the host an ingest token or import resolves to.
type IngestHost struct {
	ID       int64
	OrgID    int64
	OrgSlug  string
	Name     string
	TokenID  int64 // 0 for imports
	AutoName bool  // takes the hostname its collector reports
	EnvSlug  string
}

// HostByToken resolves a live (unrevoked) token hash to its host.
func (s *Store) HostByToken(ctx context.Context, hash [32]byte) (IngestHost, error) {
	var h IngestHost
	err := s.db.QueryRowContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name, t.id, h.auto_name
		FROM ingest_tokens t
		JOIN hosts h ON h.id = t.host_id
		JOIN organizations o ON o.id = h.org_id
		WHERE t.token_hash = ? AND t.revoked_at IS NULL`, hash[:]).
		Scan(&h.ID, &h.OrgID, &h.OrgSlug, &h.Name, &h.TokenID, &h.AutoName)
	if errors.Is(err, sql.ErrNoRows) {
		return IngestHost{}, ErrNotFound
	}
	return h, err
}

// HostByName resolves a host for `heimdall import`.
func (s *Store) HostByName(ctx context.Context, orgSlug, name string) (IngestHost, error) {
	name, err := normalizeHostName(name)
	if err != nil {
		return IngestHost{}, err
	}
	var h IngestHost
	err = s.db.QueryRowContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name, h.auto_name, e.slug
		FROM hosts h JOIN organizations o ON o.id = h.org_id JOIN environments e ON e.id = h.env_id
		WHERE o.slug = ? AND h.name = ?`, orgSlug, name).
		Scan(&h.ID, &h.OrgID, &h.OrgSlug, &h.Name, &h.AutoName, &h.EnvSlug)
	if errors.Is(err, sql.ErrNoRows) {
		return IngestHost{}, fmt.Errorf("host %q in org %q: %w", name, orgSlug, ErrNotFound)
	}
	return h, err
}

// SnapshotByPayload finds an earlier snapshot or heartbeat of the host with
// the same payload hash, i.e. a retry or a replay. id is the snapshot.
func (s *Store) SnapshotByPayload(ctx context.Context, hostID int64, hash [32]byte) (id int64, receivedAt time.Time, found bool, err error) {
	var received string
	// Heartbeats (unchanged reports) count too: their payloads were sent once.
	err = s.db.QueryRowContext(ctx, `
		SELECT id, received_at FROM snapshots WHERE host_id = ? AND payload_sha256 = ?
		UNION ALL
		SELECT snapshot_id, received_at FROM heartbeats WHERE host_id = ? AND payload_sha256 = ?
		LIMIT 1`, hostID, hash[:], hostID, hash[:]).
		Scan(&id, &received)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, time.Time{}, false, nil
	}
	if err != nil {
		return 0, time.Time{}, false, err
	}
	return id, parseTime(received), true, nil
}

// Anomaly is a rule hit to record; see docs/anomaly-signals.md.
type Anomaly struct {
	Rule     string // must match the anomalies.rule CHECK constraint
	Severity string // high, medium, low
	Summary  string
	Detail   map[string]any
}

type NewSnapshot struct {
	Host          IngestHost
	Source        string // "push" or "import"
	ReceivedAt    time.Time
	PayloadSHA256 [32]byte
	Snapshot      *snapshot.Snapshot
}

// Saved is where SaveReport put a report.
type Saved struct {
	SnapshotID  int64 // the new snapshot, or the latest one an unchanged report matched
	HeartbeatID int64 // set when the report was unchanged
	Unchanged   bool  // same inventory as the host's latest snapshot: stored as a heartbeat
}

// SaveSnapshot is SaveReport, returning the snapshot ID.
func (s *Store) SaveSnapshot(ctx context.Context, n NewSnapshot, anomalies []Anomaly) (int64, error) {
	saved, err := s.SaveReport(ctx, n, anomalies)
	return saved.SnapshotID, err
}

// SaveReport stores a validated report, marks the host as seen and records
// any anomalies, all in one transaction. A report whose inventory matches
// the host's latest snapshot (snapshot.InventoryHash) is stored as a small
// heartbeat row with its volatile facts, instead of a full new snapshot.
func (s *Store) SaveReport(ctx context.Context, n NewSnapshot, anomalies []Anomaly) (Saved, error) {
	snap := n.Snapshot
	inventory := snap.InventoryHash()
	unavailable := func(check string) bool { return slices.Contains(snap.Unavailable, check) }

	var collectorSHA []byte
	if snap.Collector.SHA256 != "" {
		var err error
		if collectorSHA, err = hex.DecodeString(snap.Collector.SHA256); err != nil {
			return Saved{}, fmt.Errorf("collector sha256: %w", err)
		}
	}
	var uptime, reboot sql.NullInt64
	if !unavailable("uptime") {
		uptime = sql.NullInt64{Int64: snap.UptimeSeconds, Valid: true}
	}
	if snap.RebootRequired != nil {
		reboot = sql.NullInt64{Int64: boolInt(*snap.RebootRequired), Valid: true}
	}
	received := n.ReceivedAt.UTC().Format(timeLayout)

	// Pending updates are stored on the installed package they upgrade.
	type pkgKey struct{ name, arch string }
	updates := make(map[pkgKey]snapshot.Update, len(snap.Updates))
	for _, u := range snap.Updates {
		updates[pkgKey{u.Name, u.Arch}] = u
	}
	pendingFor := func(p snapshot.Package) (snapshot.Update, bool) {
		if u, ok := updates[pkgKey{p.Name, p.Arch}]; ok {
			return u, true
		}
		u, ok := updates[pkgKey{p.Name, ""}] // apk reports updates without an arch
		return u, ok
	}

	var saved Saved
	err := s.tx(ctx, func(tx *sql.Tx) error {
		touch := func(snapshotID int64) error {
			if _, err := tx.ExecContext(ctx,
				`UPDATE hosts SET last_seen_at = ?, last_snapshot_id = ? WHERE id = ?`, received, snapshotID, n.Host.ID); err != nil {
				return err
			}
			if n.Host.TokenID != 0 {
				if _, err := tx.ExecContext(ctx,
					`UPDATE ingest_tokens SET last_used_at = ? WHERE id = ?`, received, n.Host.TokenID); err != nil {
					return err
				}
			}
			for _, a := range anomalies {
				if err := addAnomaly(ctx, tx, n.Host.ID, snapshotID, received, a); err != nil {
					return err
				}
			}
			return nil
		}

		// Unchanged since the latest snapshot: record a heartbeat only.
		var latestID int64
		var latestInventory []byte
		err := tx.QueryRowContext(ctx, `
			SELECT s.id, s.inventory_sha256 FROM hosts h JOIN snapshots s ON s.id = h.last_snapshot_id
			WHERE h.id = ?`, n.Host.ID).Scan(&latestID, &latestInventory)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if latestID != 0 && string(latestInventory) == string(inventory[:]) {
			var dup int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM snapshots WHERE host_id = ? AND payload_sha256 = ?`,
				n.Host.ID, n.PayloadSHA256[:]).Scan(&dup); err != nil {
				return err
			}
			if dup > 0 { // lost a race with an identical retry that stored the snapshot
				return fmt.Errorf("report already stored: %w", ErrExists)
			}
			err := tx.QueryRowContext(ctx, `
				INSERT INTO heartbeats (host_id, snapshot_id, source, received_at, collected_at, payload_sha256, uptime_seconds)
				VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`,
				n.Host.ID, latestID, n.Source, received, snap.CollectedAt.UTC().Format(timeLayout),
				n.PayloadSHA256[:], uptime).Scan(&saved.HeartbeatID)
			if isUnique(err) {
				return fmt.Errorf("report already stored: %w", ErrExists)
			}
			if err != nil {
				return err
			}
			saved.SnapshotID, saved.Unchanged = latestID, true
			// A plan item marked done after the fix was installed is
			// confirmed by the next report, changed or not.
			if err := verifyPlanItems(ctx, tx, n.Host.ID, latestID, received); err != nil {
				return err
			}
			return touch(latestID)
		}

		var id int64
		err = tx.QueryRowContext(ctx, `
			INSERT INTO snapshots (host_id, source, received_at, collected_at, collector_version,
				collector_sha256, payload_sha256, os_id, os_version, os_pretty, kernel, arch,
				uptime_seconds, reboot_required, package_manager, os_id_like, inventory_sha256)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			RETURNING id`,
			n.Host.ID, n.Source, received, snap.CollectedAt.UTC().Format(timeLayout), snap.Collector.Version,
			collectorSHA, n.PayloadSHA256[:], nullString(snap.OS.ID), nullString(snap.OS.VersionID),
			nullString(snap.OS.PrettyName), nullString(snap.Kernel.Release), nullString(snap.Kernel.Arch),
			uptime, reboot, nullString(snap.PackageManager), nullString(snap.OS.IDLike), inventory[:]).Scan(&id)
		if isUnique(err) {
			return fmt.Errorf("snapshot already stored: %w", ErrExists)
		}
		if err != nil {
			return err
		}
		saved.SnapshotID = id

		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO packages (snapshot_id, ecosystem, name, version, arch, source_name, source_version,
				pending_version, pending_security)
			VALUES (?, '', ?, ?, ?, ?, ?, ?, ?)`) // ecosystem is resolved by the hub in M2
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, p := range snap.Packages {
			var pending sql.NullString
			var security int64
			if u, ok := pendingFor(p); ok {
				pending = sql.NullString{String: u.Version, Valid: true}
				if u.Security != nil && *u.Security {
					security = 1
				}
			}
			if _, err := stmt.ExecContext(ctx, id, p.Name, p.Version, p.Arch,
				nullString(p.SourceName), nullString(p.SourceVersion), pending, security); err != nil {
				return fmt.Errorf("package %q: %w", p.Name, err)
			}
		}

		if err := saveSites(ctx, tx, id, snap.Sites); err != nil {
			return err
		}
		if err := saveV3(ctx, tx, id, snap); err != nil {
			return err
		}
		if err := verifyPlanItems(ctx, tx, n.Host.ID, id, received); err != nil {
			return err
		}
		return touch(id)
	})
	return saved, err
}

// saveSites stores a v2 snapshot's sites and their Composer packages.
func saveSites(ctx context.Context, tx *sql.Tx, snapshotID int64, sites []snapshot.Site) error {
	if len(sites) == 0 {
		return nil
	}
	siteStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO sites (snapshot_id, root, document_root, server_names, web_server, php_fpm_version,
			framework, framework_version, php_requirement, deployed_at, readable)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer siteStmt.Close()
	pkgStmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO app_packages (snapshot_id, manifest_path, ecosystem, name, version)
		VALUES (?, ?, 'Packagist', ?, ?)`)
	if err != nil {
		return err
	}
	defer pkgStmt.Close()
	for _, site := range sites {
		names := site.ServerNames
		if names == nil {
			names = []string{}
		}
		namesJSON, _ := json.Marshal(names)
		var deployed sql.NullString
		if site.DeployedAt != nil {
			deployed = sql.NullString{String: site.DeployedAt.UTC().Format(timeLayout), Valid: true}
		}
		if _, err := siteStmt.ExecContext(ctx, snapshotID, site.Root, site.DocumentRoot, string(namesJSON),
			site.WebServer, site.PHPFPMVersion, site.Framework, site.FrameworkVersion, site.PHPRequirement,
			deployed, boolInt(site.Readable)); err != nil {
			return fmt.Errorf("site %q: %w", site.Root, err)
		}
		manifest := strings.TrimSuffix(site.Root, "/") + "/composer.lock"
		for _, p := range site.ComposerPackages {
			if _, err := pkgStmt.ExecContext(ctx, snapshotID, manifest, p.Name, p.Version); err != nil {
				return fmt.Errorf("site %q package %q: %w", site.Root, p.Name, err)
			}
		}
	}
	return nil
}

// saveV3 stores containers and allowlisted lockfiles.
func saveV3(ctx context.Context, tx *sql.Tx, snapshotID int64, snap *snapshot.Snapshot) error {
	for _, c := range snap.Containers {
		if _, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO containers (snapshot_id, name, image, tag, digest, state) VALUES (?, ?, ?, ?, ?, ?)`,
			snapshotID, c.Name, c.Image, c.Tag, c.Digest, c.State); err != nil {
			return fmt.Errorf("container %q: %w", c.Name, err)
		}
	}
	for _, l := range snap.Lockfiles {
		for _, p := range l.Packages {
			if _, err := tx.ExecContext(ctx, `
				INSERT OR IGNORE INTO app_packages (snapshot_id, manifest_path, ecosystem, name, version) VALUES (?, ?, ?, ?, ?)`,
				snapshotID, l.Path, l.Ecosystem, p.Name, p.Version); err != nil {
				return fmt.Errorf("lockfile %q: %w", l.Path, err)
			}
		}
	}
	return nil
}

// RecordAnomaly stores an anomaly that isn't tied to a stored snapshot,
// such as a rejected replay.
func (s *Store) RecordAnomaly(ctx context.Context, hostID int64, at time.Time, a Anomaly) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		return addAnomaly(ctx, tx, hostID, 0, at.UTC().Format(timeLayout), a)
	})
}

func addAnomaly(ctx context.Context, tx *sql.Tx, hostID, snapshotID int64, at string, a Anomaly) error {
	detail := []byte("{}")
	if len(a.Detail) > 0 {
		var err error
		if detail, err = json.Marshal(a.Detail); err != nil {
			return err
		}
	}
	var snap sql.NullInt64
	if snapshotID != 0 {
		snap = sql.NullInt64{Int64: snapshotID, Valid: true}
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO anomalies (host_id, snapshot_id, rule, severity, summary, detail, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, hostID, snap, a.Rule, a.Severity, a.Summary, string(detail), at)
	return err
}

// AnomalyRow is a recorded anomaly.
type AnomalyRow struct {
	ID         int64
	Rule       string
	Severity   string
	Summary    string
	DetectedAt time.Time
	SnapshotID int64 // 0 if none
}

// Anomalies lists a host's open (unacknowledged) anomalies, newest first.
func (s *Store) Anomalies(ctx context.Context, hostID int64) ([]AnomalyRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, rule, severity, summary, detected_at, coalesce(snapshot_id, 0)
		FROM anomalies WHERE host_id = ? AND acknowledged_at IS NULL
		ORDER BY id DESC`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AnomalyRow
	for rows.Next() {
		var a AnomalyRow
		var at string
		if err := rows.Scan(&a.ID, &a.Rule, &a.Severity, &a.Summary, &at, &a.SnapshotID); err != nil {
			return nil, err
		}
		a.DetectedAt = parseTime(at)
		out = append(out, a)
	}
	return out, rows.Err()
}

// SnapshotSummary describes a host's latest snapshot.
type SnapshotSummary struct {
	ID               int64
	Source           string
	ReceivedAt       time.Time // the host's last report (unchanged reports don't store a new snapshot)
	CollectorVersion string
	OS               string
	Packages         int
	PendingUpdates   int
	PendingSecurity  int
	RebootRequired   *bool
}

// LatestSnapshot summarizes the host's most recent snapshot.
func (s *Store) LatestSnapshot(ctx context.Context, hostID int64) (SnapshotSummary, error) {
	var sum SnapshotSummary
	var received string
	var os sql.NullString
	var reboot sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.source, coalesce(h.last_seen_at, s.received_at), s.collector_version, coalesce(s.os_pretty, s.os_id), s.reboot_required,
		       (SELECT count(*) FROM packages p WHERE p.snapshot_id = s.id),
		       (SELECT count(*) FROM packages p WHERE p.snapshot_id = s.id AND p.pending_version IS NOT NULL),
		       (SELECT count(*) FROM packages p WHERE p.snapshot_id = s.id AND p.pending_security = 1)
		FROM hosts h JOIN snapshots s ON s.id = h.last_snapshot_id
		WHERE h.id = ?`, hostID).
		Scan(&sum.ID, &sum.Source, &received, &sum.CollectorVersion, &os, &reboot,
			&sum.Packages, &sum.PendingUpdates, &sum.PendingSecurity)
	if errors.Is(err, sql.ErrNoRows) {
		return SnapshotSummary{}, ErrNotFound
	}
	if err != nil {
		return SnapshotSummary{}, err
	}
	sum.ReceivedAt, sum.OS = parseTime(received), os.String
	if reboot.Valid {
		b := reboot.Int64 == 1
		sum.RebootRequired = &b
	}
	return sum, nil
}

// RotateToken revokes a host's live token and issues a new one.
func (s *Store) RotateToken(ctx context.Context, actor, orgSlug, name string) (string, error) {
	host, err := s.HostByName(ctx, orgSlug, name)
	if err != nil {
		return "", err
	}
	token, hash := newIngestToken()
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			UPDATE ingest_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
			WHERE host_id = ? AND revoked_at IS NULL`, host.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO ingest_tokens (host_id, token_hash) VALUES (?, ?)`, host.ID, hash[:]); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "token.rotate", OrgID: host.OrgID, Target: host.Name})
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
