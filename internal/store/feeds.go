// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

// ── Feed state ─────────────────────────────────────────────────────────────

type FeedState struct {
	Feed        string
	LastAttempt time.Time
	LastSuccess time.Time
	LastError   string
}

// RecordFeedRun notes a sync attempt; err == nil marks it successful.
func (s *Store) RecordFeedRun(ctx context.Context, feed string, at time.Time, runErr error) error {
	ts := at.UTC().Format(timeLayout)
	var success, msg sql.NullString
	if runErr == nil {
		success = sql.NullString{String: ts, Valid: true}
	} else {
		m := runErr.Error()
		if len(m) > 500 {
			m = m[:500]
		}
		msg = sql.NullString{String: m, Valid: true}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO feed_state (feed, last_attempt_at, last_success_at, last_error) VALUES (?, ?, ?, ?)
		ON CONFLICT (feed) DO UPDATE SET
			last_attempt_at = excluded.last_attempt_at,
			last_success_at = coalesce(excluded.last_success_at, feed_state.last_success_at),
			last_error = excluded.last_error`, feed, ts, success, msg)
	return err
}

func (s *Store) FeedStates(ctx context.Context) ([]FeedState, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT feed, last_attempt_at, last_success_at, coalesce(last_error, '') FROM feed_state ORDER BY feed`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FeedState
	for rows.Next() {
		var f FeedState
		var attempt, success sql.NullString
		if err := rows.Scan(&f.Feed, &attempt, &success, &f.LastError); err != nil {
			return nil, err
		}
		f.LastAttempt, f.LastSuccess = parseNullTime(attempt), parseNullTime(success)
		out = append(out, f)
	}
	return out, rows.Err()
}

// ── OSV ────────────────────────────────────────────────────────────────────

// OSVKey identifies one OSV query.
type OSVKey struct{ Ecosystem, Name, Version string }

// OSVCached returns cached advisory IDs for keys checked at or after since.
// Keys missing from the result need a fresh query.
func (s *Store) OSVCached(ctx context.Context, keys []OSVKey, since time.Time) (map[OSVKey][]string, error) {
	out := make(map[OSVKey][]string, len(keys))
	stmt, err := s.db.PrepareContext(ctx,
		`SELECT vuln_ids FROM osv_query_cache WHERE ecosystem = ? AND name = ? AND version = ? AND checked_at >= ?`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	cutoff := since.UTC().Format(timeLayout)
	for _, k := range keys {
		var raw string
		err := stmt.QueryRowContext(ctx, k.Ecosystem, k.Name, k.Version, cutoff).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var ids []string
		if err := json.Unmarshal([]byte(raw), &ids); err != nil {
			return nil, err
		}
		out[k] = ids
	}
	return out, nil
}

// PutOSVResults caches fresh query results.
func (s *Store) PutOSVResults(ctx context.Context, results map[OSVKey][]string, at time.Time) error {
	ts := at.UTC().Format(timeLayout)
	return s.tx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO osv_query_cache (ecosystem, name, version, vuln_ids, checked_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT DO UPDATE SET vuln_ids = excluded.vuln_ids, checked_at = excluded.checked_at`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for k, ids := range results {
			if ids == nil {
				ids = []string{}
			}
			b, _ := json.Marshal(ids)
			if _, err := stmt.ExecContext(ctx, k.Ecosystem, k.Name, k.Version, string(b), ts); err != nil {
				return err
			}
		}
		return nil
	})
}

// AdvisoryModified returns the stored modified time of each known advisory.
func (s *Store) AdvisoryModified(ctx context.Context, ids []string) (map[string]time.Time, error) {
	out := make(map[string]time.Time, len(ids))
	stmt, err := s.db.PrepareContext(ctx, `SELECT modified FROM advisories WHERE id = ?`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	for _, id := range ids {
		var m string
		err := stmt.QueryRowContext(ctx, id).Scan(&m)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		t, _ := time.Parse(time.RFC3339Nano, m)
		out[id] = t
	}
	return out, nil
}

type AffectedRange struct {
	Ecosystem, Package, Introduced, Fixed, LastAffected string
}

type Advisory struct {
	ID        string
	Modified  time.Time
	Published time.Time
	Withdrawn *time.Time
	Summary   string
	Severity  string // critical, high, medium, low, unknown
	CVSS      float64
	Raw       []byte
	Aliases   []string
	Ranges    []AffectedRange
}

// PutAdvisory inserts or replaces an advisory with its aliases and ranges.
func (s *Store) PutAdvisory(ctx context.Context, a Advisory) error {
	nullTime := func(t time.Time) sql.NullString {
		if t.IsZero() {
			return sql.NullString{}
		}
		return sql.NullString{String: t.UTC().Format(time.RFC3339Nano), Valid: true}
	}
	var withdrawn sql.NullString
	if a.Withdrawn != nil {
		withdrawn = nullTime(*a.Withdrawn)
	}
	var cvss sql.NullFloat64
	if a.CVSS > 0 {
		cvss = sql.NullFloat64{Float64: a.CVSS, Valid: true}
	}
	if a.Severity == "" {
		a.Severity = "unknown"
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		// ON DELETE CASCADE clears old aliases and ranges.
		if _, err := tx.ExecContext(ctx, `DELETE FROM advisories WHERE id = ?`, a.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO advisories (id, modified, published, withdrawn, summary, severity, cvss_score, raw)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			a.ID, a.Modified.UTC().Format(time.RFC3339Nano), nullTime(a.Published), withdrawn,
			a.Summary, a.Severity, cvss, string(a.Raw)); err != nil {
			return err
		}
		for _, alias := range a.Aliases {
			if _, err := tx.ExecContext(ctx,
				`INSERT OR IGNORE INTO advisory_aliases (advisory_id, alias) VALUES (?, ?)`, a.ID, alias); err != nil {
				return err
			}
		}
		for _, r := range a.Ranges {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO affected_ranges (advisory_id, ecosystem, package, introduced, fixed, last_affected)
				VALUES (?, ?, ?, ?, ?, ?)`, a.ID, r.Ecosystem, r.Package,
				nullString(r.Introduced), nullString(r.Fixed), nullString(r.LastAffected)); err != nil {
				return err
			}
		}
		return nil
	})
}

// FixedVersions lists the fixed versions an advisory records for a package
// in an ecosystem (matching "Ubuntu:22.04" to "Ubuntu:22.04:LTS" too).
func (s *Store) FixedVersions(ctx context.Context, advisoryID, ecosystem, pkg string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT fixed FROM affected_ranges
		WHERE advisory_id = ? AND package = ? AND fixed IS NOT NULL
		  AND (ecosystem = ? OR substr(ecosystem, 1, length(?) + 1) = ? || ':')
		ORDER BY id`, advisoryID, pkg, ecosystem, ecosystem, ecosystem)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ── EPSS ───────────────────────────────────────────────────────────────────

// OpenFindingCVEs lists the CVE IDs behind every open finding.
func (s *Store) OpenFindingCVEs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT alias FROM advisory_aliases
		WHERE alias LIKE 'CVE-%' AND advisory_id IN (SELECT advisory_id FROM findings WHERE resolved_at IS NULL)
		UNION
		SELECT DISTINCT advisory_id FROM findings WHERE resolved_at IS NULL AND advisory_id LIKE 'CVE-%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type EPSSScore struct {
	CVE               string
	Score, Percentile float64
	Date              time.Time
}

// PutEPSS upserts scores (CVEs not in the batch keep their last score).
func (s *Store) PutEPSS(ctx context.Context, scores []EPSSScore) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO epss_scores (cve_id, score, percentile, scored_on) VALUES (?, ?, ?, ?)
			ON CONFLICT (cve_id) DO UPDATE SET score = excluded.score, percentile = excluded.percentile,
				scored_on = excluded.scored_on`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, sc := range scores {
			if _, err := stmt.ExecContext(ctx, sc.CVE, sc.Score, sc.Percentile, sc.Date.Format(time.DateOnly)); err != nil {
				return err
			}
		}
		return nil
	})
}

// ── KEV & EOL ──────────────────────────────────────────────────────────────

type KEVEntry struct {
	CVE, Vendor, Product string
	DateAdded            time.Time
	DueDate              *time.Time
	KnownRansomware      bool
}

// ReplaceKEV swaps in a fresh catalog.
func (s *Store) ReplaceKEV(ctx context.Context, entries []KEVEntry) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM kev_entries`); err != nil {
			return err
		}
		stmt, err := tx.PrepareContext(ctx, `
			INSERT OR IGNORE INTO kev_entries (cve_id, vendor, product, date_added, due_date, known_ransomware)
			VALUES (?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, e := range entries {
			var due sql.NullString
			if e.DueDate != nil {
				due = sql.NullString{String: e.DueDate.Format(time.DateOnly), Valid: true}
			}
			if _, err := stmt.ExecContext(ctx, e.CVE, e.Vendor, e.Product,
				e.DateAdded.Format(time.DateOnly), due, boolInt(e.KnownRansomware)); err != nil {
				return err
			}
		}
		return nil
	})
}

type EOLCycle struct {
	Product, Cycle string
	ReleaseDate    *time.Time
	SupportUntil   *time.Time
	EOL            *time.Time
	EOLReached     bool
	Latest         string
}

// ReplaceEOL swaps in fresh cycles for one product.
func (s *Store) ReplaceEOL(ctx context.Context, product string, cycles []EOLCycle) error {
	date := func(t *time.Time) sql.NullString {
		if t == nil {
			return sql.NullString{}
		}
		return sql.NullString{String: t.Format(time.DateOnly), Valid: true}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM eol_cycles WHERE product = ?`, product); err != nil {
			return err
		}
		for _, c := range cycles {
			eol := date(c.EOL)
			if c.EOLReached && !eol.Valid {
				eol = sql.NullString{String: "reached", Valid: true}
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT OR IGNORE INTO eol_cycles (product, cycle, release_date, support_until, eol_date, latest)
				VALUES (?, ?, ?, ?, ?, ?)`, product, c.Cycle, date(c.ReleaseDate), date(c.SupportUntil), eol,
				nullString(c.Latest)); err != nil {
				return err
			}
		}
		return nil
	})
}

// EOLCycles returns stored cycles for a product.
func (s *Store) EOLCycles(ctx context.Context, product string) ([]EOLCycle, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT cycle, release_date, support_until, eol_date, coalesce(latest, '')
		FROM eol_cycles WHERE product = ?`, product)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	parse := func(s sql.NullString) *time.Time {
		if !s.Valid {
			return nil
		}
		t, err := time.Parse(time.DateOnly, s.String)
		if err != nil {
			return nil
		}
		return &t
	}
	var out []EOLCycle
	for rows.Next() {
		var c EOLCycle
		var rel, sup, eol sql.NullString
		if err := rows.Scan(&c.Cycle, &rel, &sup, &eol, &c.Latest); err != nil {
			return nil, err
		}
		c.Product = product
		c.ReleaseDate, c.SupportUntil, c.EOL = parse(rel), parse(sup), parse(eol)
		c.EOLReached = eol.String == "reached"
		out = append(out, c)
	}
	return out, rows.Err()
}

// ── Findings ───────────────────────────────────────────────────────────────

// HostInventory is what the findings engine needs about a host's latest snapshot.
type HostInventory struct {
	Host           IngestHost
	SnapshotID     int64
	OSID           string
	OSVersion      string
	OSIDLike       string
	OSPretty       string
	PackageManager string // "" for snapshots from before M2
	Packages       []InventoryPackage
	Sites          []InventorySite
	Containers     []InventoryContainer
	Lockfiles      []InventoryLockfile // npm / PyPI manifests outside sites
}

type InventoryContainer struct{ Name, Image, Tag, Digest, State string }

type InventoryLockfile struct {
	Path, Ecosystem string
	Packages        []AppPackage
}

// InventorySite is a web app found on the host (snapshot v2).
type InventorySite struct {
	Root, DocumentRoot string
	ServerNames        []string
	WebServer          string
	PHPFPMVersion      string // "8.3", or "" if unknown
	Readable           bool
	Framework          string // "laravel" or ""
	FrameworkVersion   string
	PHPRequirement     string // composer.json require.php
	DeployedAt         time.Time
	Packages           []AppPackage
}

type AppPackage struct{ Name, Version string }

type InventoryPackage struct {
	Name, Version, Arch, SourceName, SourceVersion string
	PendingVersion                                 string
	PendingSecurity                                bool
}

// HostsWithSnapshots lists every host that has reported at least once.
func (s *Store) HostsWithSnapshots(ctx context.Context) ([]IngestHost, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name FROM hosts h JOIN organizations o ON o.id = h.org_id
		WHERE h.last_snapshot_id IS NOT NULL ORDER BY o.slug, h.name`)
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

// Inventory loads a host's latest snapshot. ErrNotFound if it has none.
func (s *Store) Inventory(ctx context.Context, host IngestHost) (HostInventory, error) {
	inv := HostInventory{Host: host}
	var osID, osVer, idLike, pretty, pm sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.os_id, s.os_version, s.os_id_like, s.os_pretty, s.package_manager
		FROM hosts h JOIN snapshots s ON s.id = h.last_snapshot_id WHERE h.id = ?`, host.ID).
		Scan(&inv.SnapshotID, &osID, &osVer, &idLike, &pretty, &pm)
	if errors.Is(err, sql.ErrNoRows) {
		return inv, ErrNotFound
	}
	if err != nil {
		return inv, err
	}
	inv.OSID, inv.OSVersion, inv.OSIDLike, inv.OSPretty, inv.PackageManager =
		osID.String, osVer.String, idLike.String, pretty.String, pm.String

	rows, err := s.db.QueryContext(ctx, `
		SELECT name, version, arch, coalesce(source_name, ''), coalesce(source_version, ''),
		       coalesce(pending_version, ''), pending_security
		FROM packages WHERE snapshot_id = ? ORDER BY name`, inv.SnapshotID)
	if err != nil {
		return inv, err
	}
	defer rows.Close()
	for rows.Next() {
		var p InventoryPackage
		var sec int64
		if err := rows.Scan(&p.Name, &p.Version, &p.Arch, &p.SourceName, &p.SourceVersion,
			&p.PendingVersion, &sec); err != nil {
			return inv, err
		}
		p.PendingSecurity = sec == 1
		inv.Packages = append(inv.Packages, p)
	}
	if err := rows.Err(); err != nil {
		return inv, err
	}
	if inv.Sites, err = s.sites(ctx, inv.SnapshotID); err != nil {
		return inv, err
	}
	return inv, s.loadV3(ctx, &inv)
}

func (s *Store) loadV3(ctx context.Context, inv *HostInventory) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, image, tag, digest, state FROM containers WHERE snapshot_id = ? ORDER BY name`, inv.SnapshotID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var c InventoryContainer
		if err := rows.Scan(&c.Name, &c.Image, &c.Tag, &c.Digest, &c.State); err != nil {
			rows.Close()
			return err
		}
		inv.Containers = append(inv.Containers, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = s.db.QueryContext(ctx, `
		SELECT manifest_path, ecosystem, name, version FROM app_packages
		WHERE snapshot_id = ? AND ecosystem != 'Packagist' ORDER BY manifest_path, name`, inv.SnapshotID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var path, eco string
		var p AppPackage
		if err := rows.Scan(&path, &eco, &p.Name, &p.Version); err != nil {
			return err
		}
		if n := len(inv.Lockfiles); n == 0 || inv.Lockfiles[n-1].Path != path {
			inv.Lockfiles = append(inv.Lockfiles, InventoryLockfile{Path: path, Ecosystem: eco})
		}
		l := &inv.Lockfiles[len(inv.Lockfiles)-1]
		l.Packages = append(l.Packages, p)
	}
	return rows.Err()
}

func (s *Store) sites(ctx context.Context, snapshotID int64) ([]InventorySite, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT root, document_root, server_names, web_server, php_fpm_version, readable,
		       framework, framework_version, php_requirement, deployed_at
		FROM sites WHERE snapshot_id = ? ORDER BY root`, snapshotID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InventorySite
	byManifest := map[string]int{}
	for rows.Next() {
		var site InventorySite
		var names string
		var readable int64
		var deployed sql.NullString
		if err := rows.Scan(&site.Root, &site.DocumentRoot, &names, &site.WebServer, &site.PHPFPMVersion, &readable,
			&site.Framework, &site.FrameworkVersion, &site.PHPRequirement, &deployed); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(names), &site.ServerNames)
		site.Readable, site.DeployedAt = readable == 1, parseNullTime(deployed)
		byManifest[strings.TrimSuffix(site.Root, "/")+"/composer.lock"] = len(out)
		out = append(out, site)
	}
	if err := rows.Err(); err != nil || len(out) == 0 {
		return out, err
	}
	pkgs, err := s.db.QueryContext(ctx, `
		SELECT manifest_path, name, version FROM app_packages
		WHERE snapshot_id = ? AND ecosystem = 'Packagist' ORDER BY name`, snapshotID)
	if err != nil {
		return nil, err
	}
	defer pkgs.Close()
	for pkgs.Next() {
		var manifest string
		var p AppPackage
		if err := pkgs.Scan(&manifest, &p.Name, &p.Version); err != nil {
			return nil, err
		}
		if i, ok := byManifest[manifest]; ok {
			out[i].Packages = append(out[i].Packages, p)
		}
	}
	return out, pkgs.Err()
}

// Finding is one advisory affecting one source package on a host.
type Finding struct {
	AdvisoryID   string
	Ecosystem    string
	Package      string   // source package queried
	Version      string   // version queried
	Binaries     []string // installed binary packages built from it
	FixedVersion string   // "" if no fix published
	FixPending   bool     // a pending update reaches FixedVersion
	SiteRoot     string   // app root for Composer findings; "" for OS packages
}

// SetFindings makes the host's open findings exactly fs: new ones are
// added, existing ones refreshed (and reopened if they'd been resolved),
// and ones no longer present are marked resolved.
func (s *Store) SetFindings(ctx context.Context, hostID int64, fs []Finding, at time.Time) (added, resolved int, err error) {
	ts := at.UTC().Format(timeLayout)
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`CREATE TEMP TABLE IF NOT EXISTS current_findings_v2 (site_root TEXT, advisory_id TEXT, package_name TEXT)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM temp.current_findings_v2`); err != nil {
			return err
		}
		for _, f := range fs {
			bins, _ := json.Marshal(f.Binaries)
			var existed int
			if err := tx.QueryRowContext(ctx,
				`SELECT count(*) FROM findings WHERE host_id = ? AND site_root = ? AND advisory_id = ? AND package_name = ? AND resolved_at IS NULL`,
				hostID, f.SiteRoot, f.AdvisoryID, f.Package).Scan(&existed); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO findings (host_id, site_root, advisory_id, ecosystem, package_name, package_version, fixed_version,
					binaries, fix_pending, first_seen_at, last_seen_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (host_id, site_root, advisory_id, package_name) DO UPDATE SET
					ecosystem = excluded.ecosystem, package_version = excluded.package_version,
					fixed_version = excluded.fixed_version, binaries = excluded.binaries,
					fix_pending = excluded.fix_pending, last_seen_at = excluded.last_seen_at,
					resolved_at = NULL`,
				hostID, f.SiteRoot, f.AdvisoryID, f.Ecosystem, f.Package, f.Version, nullString(f.FixedVersion),
				string(bins), boolInt(f.FixPending), ts, ts); err != nil {
				return err
			}
			if existed == 0 {
				added++
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO temp.current_findings_v2 VALUES (?, ?, ?)`, f.SiteRoot, f.AdvisoryID, f.Package); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE findings SET resolved_at = ?
			WHERE host_id = ? AND resolved_at IS NULL
			  AND (site_root, advisory_id, package_name) NOT IN
			      (SELECT site_root, advisory_id, package_name FROM temp.current_findings_v2)`,
			ts, hostID)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		resolved = int(n)
		_, err = tx.ExecContext(ctx, `DELETE FROM temp.current_findings_v2`)
		return err
	})
	return added, resolved, err
}

// ReportFinding is an open finding joined with advisory, KEV and EPSS data.
type ReportFinding struct {
	AdvisoryID    string
	CVEs          []string
	Summary       string
	Severity      string
	CVSS          float64
	KEV           bool
	KEVRansomware bool
	Package       string
	Version       string
	Binaries      []string
	FixedVersion  string
	FixPending    bool
	FirstSeen     time.Time
	SiteRoot      string  // "" for OS packages
	EPSS          float64 // highest EPSS score among the advisory's CVEs (0 if none)
}

// OpenFindings lists a host's open findings in patch-priority order: known
// exploited first, then ones with a fix available, then by severity, EPSS
// and CVSS.
func (s *Store) OpenFindings(ctx context.Context, hostID int64) ([]ReportFinding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT f.advisory_id, a.summary, a.severity, coalesce(a.cvss_score, 0),
		       f.package_name, f.package_version, f.binaries, coalesce(f.fixed_version, ''), f.fix_pending,
		       f.first_seen_at, f.site_root,
		       coalesce((SELECT group_concat(alias, ' ') FROM advisory_aliases WHERE advisory_id = a.id AND alias LIKE 'CVE-%'), ''),
		       coalesce((SELECT max(k.known_ransomware) + 1 FROM kev_entries k
		                 WHERE k.cve_id = a.id OR k.cve_id IN (SELECT alias FROM advisory_aliases WHERE advisory_id = a.id)), 0),
		       coalesce((SELECT max(e.score) FROM epss_scores e
		                 WHERE e.cve_id = a.id OR e.cve_id IN (SELECT alias FROM advisory_aliases WHERE advisory_id = a.id)), 0)
		FROM findings f JOIN advisories a ON a.id = f.advisory_id
		WHERE f.host_id = ? AND f.resolved_at IS NULL AND a.withdrawn IS NULL`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportFinding
	for rows.Next() {
		var f ReportFinding
		var bins, first, cves string
		var pending, kev int64
		if err := rows.Scan(&f.AdvisoryID, &f.Summary, &f.Severity, &f.CVSS, &f.Package, &f.Version, &bins,
			&f.FixedVersion, &pending, &first, &f.SiteRoot, &cves, &kev, &f.EPSS); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(bins), &f.Binaries)
		f.FixPending, f.FirstSeen = pending == 1, parseTime(first)
		if cves != "" {
			f.CVEs = strings.Fields(cves)
		} else if strings.HasPrefix(f.AdvisoryID, "CVE-") {
			f.CVEs = []string{f.AdvisoryID}
		}
		f.KEV, f.KEVRansomware = kev > 0, kev == 2
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortFindings(out)
	return out, nil
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

func sortFindings(fs []ReportFinding) {
	less := func(a, b ReportFinding) int {
		if a.KEV != b.KEV {
			if a.KEV {
				return -1
			}
			return 1
		}
		if fa, fb := a.FixedVersion != "", b.FixedVersion != ""; fa != fb {
			if fa {
				return -1
			}
			return 1
		}
		if ra, rb := severityRank[a.Severity], severityRank[b.Severity]; ra != rb {
			return ra - rb
		}
		if a.EPSS != b.EPSS { // likelihood of exploitation in the next 30 days
			if a.EPSS > b.EPSS {
				return -1
			}
			return 1
		}
		if a.CVSS != b.CVSS {
			if a.CVSS > b.CVSS {
				return -1
			}
			return 1
		}
		return strings.Compare(a.AdvisoryID, b.AdvisoryID)
	}
	slices.SortFunc(fs, less)
}
