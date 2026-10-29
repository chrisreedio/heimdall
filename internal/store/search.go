// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"encoding/json"
	"strings"
)

// SearchHost identifies a host and its latest snapshot's OS for search.
type SearchHost struct {
	HostID         int64
	Org            string
	Host           string
	OSID           string
	OSVersion      string
	OSIDLike       string
	OSPretty       string
	PackageManager string
}

// Inventory returns the fields findings.HostEcosystem needs.
func (h SearchHost) Inventory() HostInventory {
	return HostInventory{
		Host: IngestHost{ID: h.HostID, OrgSlug: h.Org, Name: h.Host},
		OSID: h.OSID, OSVersion: h.OSVersion, OSIDLike: h.OSIDLike,
		OSPretty: h.OSPretty, PackageManager: h.PackageManager,
	}
}

// PackageHit is an installed package in a host's latest snapshot.
type PackageHit struct {
	SearchHost
	Name, Version, SourceName, SourceVersion, PendingVersion string
}

const searchHostCols = `h.id, o.slug, h.name, coalesce(s.os_id, ''), coalesce(s.os_version, ''),
	coalesce(s.os_id_like, ''), coalesce(s.os_pretty, ''), coalesce(s.package_manager, '')`

func scanSearchHost(sc interface{ Scan(...any) error }, h *SearchHost, extra ...any) error {
	return sc.Scan(append([]any{&h.HostID, &h.Org, &h.Host, &h.OSID, &h.OSVersion, &h.OSIDLike,
		&h.OSPretty, &h.PackageManager}, extra...)...)
}

// PackagesNamed finds packages whose binary or source name equals name
// (case-insensitive) in every host's latest snapshot, in one query.
func (s *Store) PackagesNamed(ctx context.Context, name string) ([]PackageHit, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT `+searchHostCols+`, p.name, p.version, coalesce(p.source_name, ''),
		       coalesce(p.source_version, ''), coalesce(p.pending_version, '')
		FROM hosts h
		JOIN organizations o ON o.id = h.org_id
		JOIN snapshots s ON s.id = h.last_snapshot_id
		JOIN packages p ON p.snapshot_id = s.id
		WHERE p.name = ?1 COLLATE NOCASE OR p.source_name = ?1 COLLATE NOCASE
		ORDER BY o.slug, h.name, p.name`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PackageHit
	for rows.Next() {
		var p PackageHit
		if err := scanSearchHost(rows, &p.SearchHost, &p.Name, &p.Version, &p.SourceName,
			&p.SourceVersion, &p.PendingVersion); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// FindingHit is an open finding matched by advisory ID or alias.
type FindingHit struct {
	SearchHost
	AdvisoryID, Package, Version, FixedVersion string
	SiteRoot                                   string // "" for OS packages
}

// OpenFindingsFor finds open findings whose advisory ID or any alias
// equals id (case-insensitive).
func (s *Store) OpenFindingsFor(ctx context.Context, id string) ([]FindingHit, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT `+searchHostCols+`, f.advisory_id, f.package_name, f.package_version, coalesce(f.fixed_version, ''),
		       f.site_root
		FROM findings f
		JOIN hosts h ON h.id = f.host_id
		JOIN organizations o ON o.id = h.org_id
		LEFT JOIN snapshots s ON s.id = h.last_snapshot_id
		JOIN advisories a ON a.id = f.advisory_id
		WHERE f.resolved_at IS NULL AND a.withdrawn IS NULL
		  AND (f.advisory_id = ?1 COLLATE NOCASE
		       OR f.advisory_id IN (SELECT advisory_id FROM advisory_aliases WHERE alias = ?1 COLLATE NOCASE))
		ORDER BY o.slug, h.name, f.site_root, f.package_name`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingHit
	for rows.Next() {
		var f FindingHit
		if err := scanSearchHost(rows, &f.SearchHost, &f.AdvisoryID, &f.Package, &f.Version, &f.FixedVersion,
			&f.SiteRoot); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// HostsMatching finds hosts whose name contains fragment (case-insensitive),
// including hosts that have never reported.
func (s *Store) HostsMatching(ctx context.Context, fragment string) ([]SearchHost, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT `+searchHostCols+`
		FROM hosts h
		JOIN organizations o ON o.id = h.org_id
		LEFT JOIN snapshots s ON s.id = h.last_snapshot_id
		WHERE instr(lower(h.name), ?) > 0
		ORDER BY o.slug, h.name`, strings.ToLower(fragment))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SearchHost
	for rows.Next() {
		var h SearchHost
		if err := scanSearchHost(rows, &h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SiteHit is a site in a host's latest snapshot.
type SiteHit struct {
	SearchHost
	Root, DocumentRoot string
	ServerNames        []string
	WebServer          string
	PHPFPMVersion      string
	Framework          string
	FrameworkVersion   string
}

// SitesAll lists every site in every host's latest snapshot, in one query.
// Search filters these in Go; a fleet has at most a few thousand sites.
func (s *Store) SitesAll(ctx context.Context) ([]SiteHit, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT `+searchHostCols+`, si.root, si.document_root, si.server_names, si.web_server,
		       si.php_fpm_version, si.framework, si.framework_version
		FROM hosts h
		JOIN organizations o ON o.id = h.org_id
		JOIN snapshots s ON s.id = h.last_snapshot_id
		JOIN sites si ON si.snapshot_id = s.id
		ORDER BY o.slug, h.name, si.root`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SiteHit
	for rows.Next() {
		var h SiteHit
		var names string
		if err := scanSearchHost(rows, &h.SearchHost, &h.Root, &h.DocumentRoot, &names, &h.WebServer,
			&h.PHPFPMVersion, &h.Framework, &h.FrameworkVersion); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(names), &h.ServerNames)
		out = append(out, h)
	}
	return out, rows.Err()
}

// ComposerHit is a Composer package in a site of a host's latest snapshot.
type ComposerHit struct {
	SearchHost
	SiteRoot, Name, Version string
}

// ComposerPackagesNamed finds a Composer package (case-insensitive) across
// every site in every host's latest snapshot.
func (s *Store) ComposerPackagesNamed(ctx context.Context, name string) ([]ComposerHit, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT `+searchHostCols+`, ap.manifest_path, ap.name, ap.version
		FROM hosts h
		JOIN organizations o ON o.id = h.org_id
		JOIN snapshots s ON s.id = h.last_snapshot_id
		JOIN app_packages ap ON ap.snapshot_id = s.id
		WHERE ap.ecosystem = 'Packagist' AND ap.name = ? COLLATE NOCASE
		ORDER BY o.slug, h.name, ap.manifest_path`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ComposerHit
	for rows.Next() {
		var c ComposerHit
		var manifest string
		if err := scanSearchHost(rows, &c.SearchHost, &manifest, &c.Name, &c.Version); err != nil {
			return nil, err
		}
		c.SiteRoot = strings.TrimSuffix(manifest, "/composer.lock")
		if c.SiteRoot == "" {
			c.SiteRoot = "/"
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
