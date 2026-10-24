// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"time"

	"github.com/chrisreedio/heimdall/internal/kernel"
)

// ── Fleet posture: per-host aggregates for the dashboard and host list ────

// FindingCounts tallies one host's open findings in one place: its OS
// (site root "") or one site. It counts exactly what OpenFindings returns,
// the way report.Counts does: findings on old kernels that aren't running
// (NotRunning) are left out of KEV, Fixable, FixPending, FixUrgent and
// NoFix.
type FindingCounts struct {
	Total, KEV, Critical, High, Medium, Low, Unknown int
	Fixable                                          int // a fixed version exists
	FixPending                                       int // ...and an update that installs it is already pending
	NoFix                                            int
	FixUrgent                                        int // fixable and critical or high
	InNews                                           int // named by a live threat-news incident
	NotRunning                                       int // on an old kernel that's installed but not running
	RebootPending                                    int // on the running kernel, a newer one installed
}

// OpenFindingCounts returns every host's open-finding tallies by site root
// from the finding_counts table: a few rows, where counting live would
// join tens of thousands of findings per host to the advisories table.
func (s *Store) OpenFindingCounts(ctx context.Context) (map[int64]map[string]FindingCounts, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT host_id, site_root, total, kev, critical, high, medium, low, unknown,
		       fixable, fix_pending, fix_urgent, in_news, not_running, reboot_pending
		FROM finding_counts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]map[string]FindingCounts{}
	for rows.Next() {
		var host int64
		var root string
		var c FindingCounts
		if err := rows.Scan(&host, &root, &c.Total, &c.KEV, &c.Critical, &c.High, &c.Medium, &c.Low, &c.Unknown,
			&c.Fixable, &c.FixPending, &c.FixUrgent, &c.InNews, &c.NotRunning, &c.RebootPending); err != nil {
			return nil, err
		}
		c.NoFix = c.Total - c.Fixable - c.NotRunning
		if out[host] == nil {
			out[host] = map[string]FindingCounts{}
		}
		out[host][root] = c
	}
	return out, rows.Err()
}

// countsSQL recounts open findings into finding_counts for host ?1 (0 = all
// hosts). It counts exactly what OpenFindings returns: KEV through the
// advisory's ID or any alias, news through a live incident naming the
// advisory or one of its CVE aliases. ?2 is each host's kernel package
// sets (kernelSets), so an OS finding is not_running when every binary is
// an old kernel's package, and reboot_pending when every binary is the
// running kernel's while a newer one is installed: kernel.State.Status.
const countsSQL = `
	WITH kev AS (
		SELECT k.cve_id AS id FROM kev_entries k
		UNION SELECT aa.advisory_id FROM advisory_aliases aa JOIN kev_entries k ON k.cve_id = aa.alias),
	news_cve AS (
		SELECT DISTINCT c.value AS cve FROM news_items n, json_each(n.cve_ids) c WHERE n.status = 'live'),
	news AS (
		SELECT cve AS id FROM news_cve
		UNION SELECT aa.advisory_id FROM advisory_aliases aa JOIN news_cve ON news_cve.cve = aa.alias),
	ks AS (
		SELECT CAST(key AS INTEGER) AS host_id, json_extract(value, '$.old') AS old, json_extract(value, '$.boot') AS boot
		FROM json_each(?2)),
	fs AS (
		SELECT f.host_id, f.site_root, a.severity AS sev,
		       coalesce(f.fixed_version, '') != '' AS fixable, f.fix_pending AS pending,
		       f.advisory_id IN (SELECT id FROM kev) AS kev, f.advisory_id IN (SELECT id FROM news) AS news,
		       coalesce(f.site_root = '' AND json_array_length(f.binaries) > 0 AND ks.old IS NOT NULL AND NOT EXISTS (
		           SELECT 1 FROM json_each(f.binaries) b WHERE b.value NOT IN (SELECT value FROM json_each(ks.old))), 0) AS nr,
		       coalesce(f.site_root = '' AND json_array_length(f.binaries) > 0 AND ks.boot IS NOT NULL AND NOT EXISTS (
		           SELECT 1 FROM json_each(f.binaries) b WHERE b.value NOT IN (SELECT value FROM json_each(ks.boot))), 0) AS rb
		FROM findings f JOIN advisories a INDEXED BY advisories_tally ON a.id = f.advisory_id
		LEFT JOIN ks ON ks.host_id = f.host_id
		WHERE f.resolved_at IS NULL AND a.withdrawn IS NULL AND f.host_id IN (SELECT id FROM hosts WHERE ?1 = 0 OR id = ?1))
	INSERT INTO finding_counts (host_id, site_root, total, kev, critical, high, medium, low, unknown,
	                            fixable, fix_pending, fix_urgent, in_news, not_running, reboot_pending)
	SELECT host_id, site_root, count(*),
	       sum(kev AND NOT nr),
	       sum(sev = 'critical'), sum(sev = 'high'), sum(sev = 'medium'),
	       sum(sev = 'low'), sum(sev NOT IN ('critical', 'high', 'medium', 'low')),
	       sum(fixable AND NOT nr), sum(pending AND NOT nr),
	       sum(fixable AND NOT nr AND sev IN ('critical', 'high')),
	       sum(news), sum(nr), sum(rb AND NOT nr)
	FROM fs
	GROUP BY host_id, site_root`

// refreshFindingCounts rewrites finding_counts for one host (0 = every
// host) inside tx. Callers: SetFindings (the host's findings changed, and
// with them any advisory updates fetched for it, or its kernels), ReplaceKEV,
// MatchNews and the 0014 migration.
func refreshFindingCounts(ctx context.Context, tx *sql.Tx, hostID int64) error {
	sets, err := kernelSets(ctx, tx, hostID)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM finding_counts WHERE ?1 = 0 OR host_id = ?1`, hostID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, countsSQL, hostID, sets)
	return err
}

// kernelSets is, as JSON, each Debian/Ubuntu host's old-kernel and
// reboot-pending package names ({"<host id>": {"old": [...], "boot": [...]}})
// from its latest snapshot, for host hostID (0 = every host). Hosts with
// neither are left out. It reads only the linux-* packages.
func kernelSets(ctx context.Context, tx *sql.Tx, hostID int64) (string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT h.id, coalesce(s.kernel, ''), p.name, p.version, p.arch
		FROM hosts h JOIN snapshots s ON s.id = h.last_snapshot_id
		JOIN packages p ON p.snapshot_id = s.id AND p.name >= 'linux-' AND p.name < 'linux.'
		WHERE (?1 = 0 OR h.id = ?1) AND s.package_manager = 'dpkg'
		ORDER BY h.id`, hostID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type sets struct {
		Old  []string `json:"old"`
		Boot []string `json:"boot"`
	}
	out := map[string]sets{}
	running := map[int64]string{}
	pkgs := map[int64][]kernel.Installed{}
	var order []int64
	for rows.Next() {
		var id int64
		var k string
		var p kernel.Installed
		if err := rows.Scan(&id, &k, &p.Name, &p.Version, &p.Arch); err != nil {
			return "", err
		}
		if _, ok := running[id]; !ok {
			order = append(order, id)
		}
		running[id] = k
		pkgs[id] = append(pkgs[id], p)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	for _, id := range order {
		st := kernel.HostState("dpkg", running[id], pkgs[id])
		if len(st.Old) > 0 || len(st.Boot) > 0 {
			out[strconv.FormatInt(id, 10)] = sets{Old: nonNilStrings(st.Old), Boot: nonNilStrings(st.Boot)}
		}
	}
	b, err := json.Marshal(out)
	return string(b), err
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// RecountFindings rewrites every host's finding_counts (after a migration
// that changes how they're counted).
func (s *Store) RecountFindings(ctx context.Context) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return refreshFindingCounts(ctx, tx, 0) })
}

// HostState is what a host's latest report says beyond its findings.
type HostState struct {
	ReceivedAt       time.Time
	CollectorVersion string
	RebootRequired   *bool // nil when the collector couldn't tell
	PendingUpdates   int
	PendingSecurity  int
	Triggers         string // the collector's raw trigger state ("" if it doesn't report one)
	News             int    // threat-news incidents confirmed on the host
}

// HostStates returns the latest-report state of every host that has
// reported, by host ID, in one query.
func (s *Store) HostStates(ctx context.Context) (map[int64]HostState, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.id, coalesce(h.last_seen_at, s.received_at), s.collector_version, s.reboot_required,
		       coalesce(h.triggers, ''),
		       (SELECT count(*) FROM packages p WHERE p.snapshot_id = s.id AND p.pending_version IS NOT NULL),
		       (SELECT count(*) FROM packages p WHERE p.snapshot_id = s.id AND p.pending_security = 1),
		       (SELECT count(*) FROM news_matches m WHERE m.host_id = h.id AND m.kind = 'confirmed')
		FROM hosts h JOIN snapshots s ON s.id = h.last_snapshot_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]HostState{}
	for rows.Next() {
		var id int64
		var st HostState
		var received string
		var reboot sql.NullInt64
		if err := rows.Scan(&id, &received, &st.CollectorVersion, &reboot, &st.Triggers,
			&st.PendingUpdates, &st.PendingSecurity, &st.News); err != nil {
			return nil, err
		}
		st.ReceivedAt = parseTime(received)
		if reboot.Valid {
			b := reboot.Int64 == 1
			st.RebootRequired = &b
		}
		out[id] = st
	}
	return out, rows.Err()
}
