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
// (NotRunning) and those only on kernel userland packages (KernelUserland)
// are left out of KEV, Fixable, FixPending, FixUrgent and NoFix.
type FindingCounts struct {
	Total, KEV, Critical, High, Medium, Low, Unknown int
	Fixable                                          int // a fixed version exists
	FixPending                                       int // ...and an update that installs it is already pending
	NoFix                                            int
	FixUrgent                                        int // fixable and critical or high
	InNews                                           int // named by a live threat-news incident
	NotRunning                                       int // on an old kernel that's installed but not running
	RebootPending                                    int // on the running kernel, a newer one installed
	KernelUserland                                   int // only on kernel userland packages (kernel.Userland)
	Watch                                            int // of NoFix, known-exploited, in the news or WatchEPSS likely
}

// WatchEPSS is the EPSS score (the chance of exploitation in the next 30
// days) from which a finding with no fix yet is still worth watching:
// counted in FindingCounts.Watch and shown on the host page's default view.
const WatchEPSS = 0.10

// OpenFindingCounts returns every host's open-finding tallies by site root
// from the finding_counts table: a few rows, where counting live would
// join tens of thousands of findings per host to the advisories table.
func (s *Store) OpenFindingCounts(ctx context.Context) (map[int64]map[string]FindingCounts, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT host_id, site_root, total, kev, critical, high, medium, low, unknown,
		       fixable, fix_pending, fix_urgent, in_news, not_running, reboot_pending, kernel_userland, watch
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
			&c.Fixable, &c.FixPending, &c.FixUrgent, &c.InNews, &c.NotRunning, &c.RebootPending, &c.KernelUserland, &c.Watch); err != nil {
			return nil, err
		}
		c.NoFix = c.Total - c.Fixable - c.NotRunning - c.KernelUserland
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
// running kernel's while a newer one is installed, and userland when every
// binary is a kernel userland package (?3, kernel.Userland's list):
// kernel.State.Status. ?4 is WatchEPSS: watch counts findings with no fix
// that are known-exploited, in the news, or scored at least that.
const countsSQL = `
	WITH kev AS (
		SELECT k.cve_id AS id FROM kev_entries k
		UNION SELECT aa.advisory_id FROM advisory_aliases aa JOIN kev_entries k ON k.cve_id = aa.alias),
	news_cve AS (
		SELECT DISTINCT c.value AS cve FROM news_items n, json_each(n.cve_ids) c WHERE n.status = 'live'),
	news AS (
		SELECT cve AS id FROM news_cve
		UNION SELECT aa.advisory_id FROM advisory_aliases aa JOIN news_cve ON news_cve.cve = aa.alias),
	hot AS (
		SELECT e.cve_id AS id FROM epss_scores e WHERE e.score >= ?4
		UNION SELECT aa.advisory_id FROM advisory_aliases aa JOIN epss_scores e ON e.cve_id = aa.alias WHERE e.score >= ?4),
	ks AS (
		SELECT CAST(key AS INTEGER) AS host_id, json_extract(value, '$.old') AS old, json_extract(value, '$.boot') AS boot
		FROM json_each(?2)),
	fs AS (
		SELECT f.host_id, f.site_root, a.severity AS sev,
		       coalesce(f.fixed_version, '') != '' AS fixable, f.fix_pending AS pending,
		       f.advisory_id IN (SELECT id FROM kev) AS kev, f.advisory_id IN (SELECT id FROM news) AS news,
		       f.advisory_id IN (SELECT id FROM hot) AS hot,
		       coalesce(f.site_root = '' AND json_array_length(f.binaries) > 0 AND h.dpkg AND NOT EXISTS (
		           SELECT 1 FROM json_each(f.binaries) b WHERE b.value NOT IN (SELECT value FROM json_each(?3))
		           AND b.value NOT LIKE 'linux-source-%'), 0) AS ku,
		       coalesce(f.site_root = '' AND json_array_length(f.binaries) > 0 AND ks.old IS NOT NULL AND NOT EXISTS (
		           SELECT 1 FROM json_each(f.binaries) b WHERE b.value NOT IN (SELECT value FROM json_each(ks.old))), 0) AS nr0,
		       coalesce(f.site_root = '' AND json_array_length(f.binaries) > 0 AND ks.boot IS NOT NULL AND NOT EXISTS (
		           SELECT 1 FROM json_each(f.binaries) b WHERE b.value NOT IN (SELECT value FROM json_each(ks.boot))), 0) AS rb
		FROM findings f JOIN advisories a INDEXED BY advisories_tally ON a.id = f.advisory_id
		LEFT JOIN ks ON ks.host_id = f.host_id
		JOIN (SELECT h.id, coalesce(s.package_manager = 'dpkg', 0) AS dpkg FROM hosts h
		      LEFT JOIN snapshots s ON s.id = h.last_snapshot_id WHERE ?1 = 0 OR h.id = ?1) h ON h.id = f.host_id
		WHERE f.resolved_at IS NULL AND a.withdrawn IS NULL),
	fk AS (SELECT *, nr0 AND NOT ku AS nr, ku OR nr0 AS off FROM fs)
	INSERT INTO finding_counts (host_id, site_root, total, kev, critical, high, medium, low, unknown,
	                            fixable, fix_pending, fix_urgent, in_news, not_running, reboot_pending, kernel_userland, watch)
	SELECT host_id, site_root, count(*),
	       sum(kev AND NOT off),
	       sum(sev = 'critical'), sum(sev = 'high'), sum(sev = 'medium'),
	       sum(sev = 'low'), sum(sev NOT IN ('critical', 'high', 'medium', 'low')),
	       sum(fixable AND NOT off), sum(pending AND NOT off),
	       sum(fixable AND NOT off AND sev IN ('critical', 'high')),
	       sum(news), sum(nr), sum(rb AND NOT off), sum(ku),
	       sum(NOT fixable AND NOT off AND (kev OR news OR hot))
	FROM fk
	GROUP BY host_id, site_root`

// refreshFindingCounts rewrites finding_counts for one host (0 = every
// host) inside tx. Callers: SetFindings (the host's findings changed, and
// with them any advisory updates fetched for it, or its kernels), ReplaceKEV,
// PutEPSS, MatchNews and the 0014 and 0016 migrations.
func refreshFindingCounts(ctx context.Context, tx *sql.Tx, hostID int64) error {
	sets, err := kernelSets(ctx, tx, hostID)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM finding_counts WHERE ?1 = 0 OR host_id = ?1`, hostID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, countsSQL, hostID, sets, userlandJSON, WatchEPSS)
	return err
}

// userlandJSON is kernel.Userland's exact names, for countsSQL.
var userlandJSON = func() string {
	b, _ := json.Marshal(kernel.UserlandNames())
	return string(b)
}()

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
	PackageManager   string
	// The privilege watch's last reported state and detail ("" if never).
	PrivilegeState, PrivilegeDetail string
}

// HostStates returns the latest-report state of every host that has
// reported, by host ID, in one query.
func (s *Store) HostStates(ctx context.Context) (map[int64]HostState, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.id, coalesce(h.last_seen_at, s.received_at), s.collector_version, s.reboot_required,
		       coalesce(h.triggers, ''),
		       (SELECT count(*) FROM packages p WHERE p.snapshot_id = s.id AND p.pending_version IS NOT NULL),
		       (SELECT count(*) FROM packages p WHERE p.snapshot_id = s.id AND p.pending_security = 1),
		       (SELECT count(*) FROM news_matches m WHERE m.host_id = h.id AND m.kind = 'confirmed'),
		       s.package_manager, coalesce(pw.state, ''), coalesce(pw.detail, '')
		FROM hosts h JOIN snapshots s ON s.id = h.last_snapshot_id
		LEFT JOIN privilege_watch pw ON pw.host_id = h.id`)
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
			&st.PendingUpdates, &st.PendingSecurity, &st.News, &st.PackageManager, &st.PrivilegeState, &st.PrivilegeDetail); err != nil {
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
