// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// The attack-surface map's storage (internal/surface, docs/surface.md):
// zone settings and edge certificates, CNAME target checks and the change
// log. All of it is written by the Cloudflare sync.

// Surface settings states (zone settings and certificates alike).
const (
	SurfaceOK         = "ok"
	SurfacePermission = "permission"
	SurfaceError      = "error"
)

// SurfaceSettings is what a zone's settings and certificate packs said.
type SurfaceSettings struct {
	State, Note              string
	SSL, AlwaysHTTPS, MinTLS string
	At                       time.Time
	CertState, CertNote      string
	CertExpires              time.Time // zero: none found (or not read)
	CertAt                   time.Time
}

// SetSurfaceSettings stores a zone's settings read. Unless the state is
// ok, only the state and note change: the last good values stay.
func (s *Store) SetSurfaceSettings(ctx context.Context, zoneID, state, note, ssl, alwaysHTTPS, minTLS string, now time.Time) error {
	ts := now.UTC().Format(timeLayout)
	if state == SurfaceOK {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO surface_zone_settings (zone_id, state, note, ssl, always_https, min_tls, at)
			SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 WHERE EXISTS (SELECT 1 FROM cloudflare_zones WHERE id = ?1)
			ON CONFLICT (zone_id) DO UPDATE SET state = excluded.state, note = excluded.note, ssl = excluded.ssl,
				always_https = excluded.always_https, min_tls = excluded.min_tls, at = excluded.at`,
			zoneID, state, note, ssl, alwaysHTTPS, minTLS, ts)
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO surface_zone_settings (zone_id, state, note, at)
		SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM cloudflare_zones WHERE id = ?1)
		ON CONFLICT (zone_id) DO UPDATE SET state = excluded.state, note = excluded.note, at = excluded.at`,
		zoneID, state, note, ts)
	return err
}

// SetSurfaceCert stores a zone's certificate packs read, keeping the last
// good expiry unless the state is ok.
func (s *Store) SetSurfaceCert(ctx context.Context, zoneID, state, note string, expires, now time.Time) error {
	ts := now.UTC().Format(timeLayout)
	exp := ""
	if !expires.IsZero() {
		exp = expires.UTC().Format(timeLayout)
	}
	q := `
		INSERT INTO surface_zone_settings (zone_id, cert_state, cert_note, cert_expires, cert_at)
		SELECT ?1, ?2, ?3, ?4, ?5 WHERE EXISTS (SELECT 1 FROM cloudflare_zones WHERE id = ?1)
		ON CONFLICT (zone_id) DO UPDATE SET cert_state = excluded.cert_state, cert_note = excluded.cert_note,
			cert_at = excluded.cert_at`
	if state == SurfaceOK {
		q += `, cert_expires = excluded.cert_expires`
	}
	_, err := s.db.ExecContext(ctx, q, zoneID, state, note, exp, ts)
	return err
}

// SurfaceSettingsAll returns every zone's stored settings by zone ID.
func (s *Store) SurfaceSettingsAll(ctx context.Context) (map[string]SurfaceSettings, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT zone_id, state, note, ssl, always_https, min_tls, at, cert_state, cert_note, cert_expires, cert_at
		FROM surface_zone_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]SurfaceSettings{}
	for rows.Next() {
		var id, at, exp, certAt string
		var z SurfaceSettings
		if err := rows.Scan(&id, &z.State, &z.Note, &z.SSL, &z.AlwaysHTTPS, &z.MinTLS, &at, &z.CertState, &z.CertNote, &exp, &certAt); err != nil {
			return nil, err
		}
		z.At, z.CertExpires, z.CertAt = parseTime(at), parseTime(exp), parseTime(certAt)
		out[id] = z
	}
	return out, rows.Err()
}

// CNAME check statuses.
const (
	CNAMEOK       = "ok"
	CNAMENXDomain = "nxdomain" // the target doesn't exist: a takeover risk
	CNAMEError    = "error"    // the lookup failed (timeout, SERVFAIL)
)

// CNAMECheck is the last DNS answer for a CNAME target outside our zones.
type CNAMECheck struct {
	Target, Status, Note string
	CheckedAt            time.Time
}

// PutCNAMEChecks stores this sync's checks and forgets targets no record
// uses any more. A failed lookup doesn't replace an earlier answer.
func (s *Store) PutCNAMEChecks(ctx context.Context, checks []CNAMECheck, now time.Time) error {
	ts := now.UTC().Format(timeLayout)
	return s.tx(ctx, func(tx *sql.Tx) error {
		keep := make([]any, 0, len(checks))
		for _, c := range checks {
			keep = append(keep, c.Target)
			q := `INSERT INTO surface_cname_checks (target, status, note, checked_at) VALUES (?, ?, ?, ?)
				ON CONFLICT (target) DO UPDATE SET status = excluded.status, note = excluded.note, checked_at = excluded.checked_at`
			if c.Status == CNAMEError {
				q = `INSERT INTO surface_cname_checks (target, status, note, checked_at) VALUES (?, ?, ?, ?)
					ON CONFLICT (target) DO NOTHING`
			}
			if _, err := tx.ExecContext(ctx, q, c.Target, c.Status, c.Note, ts); err != nil {
				return err
			}
		}
		q := `DELETE FROM surface_cname_checks`
		if len(keep) > 0 {
			q += ` WHERE target NOT IN (?` + strings.Repeat(", ?", len(keep)-1) + `)`
		}
		_, err := tx.ExecContext(ctx, q, keep...)
		return err
	})
}

// CNAMEChecks returns the stored checks by target.
func (s *Store) CNAMEChecks(ctx context.Context) (map[string]CNAMECheck, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT target, status, note, checked_at FROM surface_cname_checks`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]CNAMECheck{}
	for rows.Next() {
		var c CNAMECheck
		var at string
		if err := rows.Scan(&c.Target, &c.Status, &c.Note, &at); err != nil {
			return nil, err
		}
		c.CheckedAt = parseTime(at)
		out[c.Target] = c
	}
	return out, rows.Err()
}

// Surface change kinds.
const (
	SurfaceAdded     = "added"
	SurfaceRemoved   = "removed"
	SurfaceProxied   = "proxied"   // grey → orange
	SurfaceUnproxied = "unproxied" // orange → grey: the origin is public now
	SurfaceTarget    = "target"    // the addresses or CNAME target changed
)

// SurfaceChangeKeepDays is how long the change log is kept.
const SurfaceChangeKeepDays = 90

// SurfaceChange is one change to a public name between two syncs.
type SurfaceChange struct {
	At           time.Time
	ZoneID, Zone string
	Name, Kind   string
	Old, New     string
	Orgs         []int64 // whose hosts or sites the name led to
}

// AddSurfaceChanges appends changes and drops those older than
// SurfaceChangeKeepDays.
func (s *Store) AddSurfaceChanges(ctx context.Context, cs []SurfaceChange, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, c := range cs {
			orgs, _ := json.Marshal(c.Orgs)
			if c.Orgs == nil {
				orgs = []byte("[]")
			}
			at := c.At
			if at.IsZero() {
				at = now
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO surface_changes (at, zone_id, zone, name, kind, old, new, orgs) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				at.UTC().Format(timeLayout), c.ZoneID, c.Zone, c.Name, c.Kind, c.Old, c.New, string(orgs)); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM surface_changes WHERE at < ?`,
			now.UTC().AddDate(0, 0, -SurfaceChangeKeepDays).Format(timeLayout))
		return err
	})
}

// SurfaceChanges returns the changes since t, newest first, at most limit.
func (s *Store) SurfaceChanges(ctx context.Context, since time.Time, limit int) ([]SurfaceChange, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT at, zone_id, zone, name, kind, old, new, orgs FROM surface_changes
		WHERE at >= ? ORDER BY at DESC, id DESC LIMIT ?`, since.UTC().Format(timeLayout), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SurfaceChange
	for rows.Next() {
		var c SurfaceChange
		var at, orgs string
		if err := rows.Scan(&at, &c.ZoneID, &c.Zone, &c.Name, &c.Kind, &c.Old, &c.New, &orgs); err != nil {
			return nil, err
		}
		c.At = parseTime(at)
		json.Unmarshal([]byte(orgs), &c.Orgs)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SurfaceHost is a reporting host as the surface map shows it.
type SurfaceHost struct {
	ID, OrgID int64
	Org, Name string
	OS        string // os-release PRETTY_NAME, or ID and version
}

// SurfaceHosts lists every host that has reported, with its OS.
func (s *Store) SurfaceHosts(ctx context.Context) ([]SurfaceHost, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name, coalesce(sn.os_pretty, ''), coalesce(sn.os_id, ''), coalesce(sn.os_version, '')
		FROM hosts h JOIN organizations o ON o.id = h.org_id JOIN snapshots sn ON sn.id = h.last_snapshot_id
		ORDER BY o.slug, h.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SurfaceHost
	for rows.Next() {
		var h SurfaceHost
		var id, ver string
		if err := rows.Scan(&h.ID, &h.OrgID, &h.Org, &h.Name, &h.OS, &id, &ver); err != nil {
			return nil, err
		}
		if h.OS == "" {
			h.OS = strings.TrimSpace(id + " " + ver)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SurfaceSite is a site in a host's latest snapshot: its stack.
type SurfaceSite struct {
	HostID                      int64
	Root                        string
	WebServer, PHP              string
	Framework, FrameworkVersion string
}

// SurfaceSites lists every site in every host's latest snapshot.
func (s *Store) SurfaceSites(ctx context.Context) ([]SurfaceSite, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.id, si.root, si.web_server, si.php_fpm_version, si.framework, si.framework_version
		FROM hosts h JOIN sites si ON si.snapshot_id = h.last_snapshot_id ORDER BY h.id, si.root`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SurfaceSite
	for rows.Next() {
		var x SurfaceSite
		if err := rows.Scan(&x.HostID, &x.Root, &x.WebServer, &x.PHP, &x.Framework, &x.FrameworkVersion); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
