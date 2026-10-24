// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"time"
)

// ── Fleet posture: per-host aggregates for the dashboard and host list ────

// FindingCounts tallies one host's open findings in one place: its OS
// (site root "") or one site. It counts exactly what OpenFindings returns.
type FindingCounts struct {
	Total, KEV, Critical, High, Medium, Low, Unknown int
	Fixable                                          int // a fixed version exists
	FixPending                                       int // ...and an update that installs it is already pending
	NoFix                                            int
	FixUrgent                                        int // fixable and critical or high
	InNews                                           int // named by a live threat-news incident
}

// OpenFindingCounts returns every host's open-finding tallies by site root
// from the finding_counts table: a few rows, where counting live would
// join tens of thousands of findings per host to the advisories table.
func (s *Store) OpenFindingCounts(ctx context.Context) (map[int64]map[string]FindingCounts, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT host_id, site_root, total, kev, critical, high, medium, low, unknown,
		       fixable, fix_pending, fix_urgent, in_news
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
			&c.Fixable, &c.FixPending, &c.FixUrgent, &c.InNews); err != nil {
			return nil, err
		}
		c.NoFix = c.Total - c.Fixable
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
// advisory or one of its CVE aliases.
const countsSQL = `
	WITH kev AS (
		SELECT k.cve_id AS id FROM kev_entries k
		UNION SELECT aa.advisory_id FROM advisory_aliases aa JOIN kev_entries k ON k.cve_id = aa.alias),
	news_cve AS (
		SELECT DISTINCT c.value AS cve FROM news_items n, json_each(n.cve_ids) c WHERE n.status = 'live'),
	news AS (
		SELECT cve AS id FROM news_cve
		UNION SELECT aa.advisory_id FROM advisory_aliases aa JOIN news_cve ON news_cve.cve = aa.alias)
	INSERT INTO finding_counts
	SELECT f.host_id, f.site_root, count(*),
	       sum(f.advisory_id IN (SELECT id FROM kev)),
	       sum(a.severity = 'critical'), sum(a.severity = 'high'), sum(a.severity = 'medium'),
	       sum(a.severity = 'low'), sum(a.severity NOT IN ('critical', 'high', 'medium', 'low')),
	       sum(coalesce(f.fixed_version, '') != ''), sum(f.fix_pending),
	       sum(coalesce(f.fixed_version, '') != '' AND a.severity IN ('critical', 'high')),
	       sum(f.advisory_id IN (SELECT id FROM news))
	FROM findings f JOIN advisories a INDEXED BY advisories_tally ON a.id = f.advisory_id
	WHERE f.resolved_at IS NULL AND a.withdrawn IS NULL AND f.host_id IN (SELECT id FROM hosts WHERE ?1 = 0 OR id = ?1)
	GROUP BY f.host_id, f.site_root`

// refreshFindingCounts rewrites finding_counts for one host (0 = every
// host) inside tx. Callers: SetFindings (the host's findings changed, and
// with them any advisory updates fetched for it), ReplaceKEV and MatchNews.
func refreshFindingCounts(ctx context.Context, tx *sql.Tx, hostID int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM finding_counts WHERE ?1 = 0 OR host_id = ?1`, hostID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, countsSQL, hostID)
	return err
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
