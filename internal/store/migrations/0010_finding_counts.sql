-- Per-host tallies of open findings, so the dashboard and host list read a
-- few rows instead of joining tens of thousands of findings to the (large)
-- advisories table on every request. Kept current by the store whenever
-- findings, the KEV catalog or threat-news matches change (see
-- refreshFindingCounts); this fills it once for existing data.
CREATE TABLE finding_counts (
    host_id     INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    site_root   TEXT    NOT NULL, -- '' for OS packages
    total       INTEGER NOT NULL,
    kev         INTEGER NOT NULL,
    critical    INTEGER NOT NULL,
    high        INTEGER NOT NULL,
    medium      INTEGER NOT NULL,
    low         INTEGER NOT NULL,
    unknown     INTEGER NOT NULL,
    fixable     INTEGER NOT NULL,
    fix_pending INTEGER NOT NULL,
    fix_urgent  INTEGER NOT NULL, -- fixable, and critical or high
    in_news     INTEGER NOT NULL,
    PRIMARY KEY (host_id, site_root)
) STRICT, WITHOUT ROWID;

-- Recounting reads each finding's advisory severity and withdrawn date. The
-- advisories table holds the raw OSV JSON (most of a hub's database), so
-- reading those from a small covering index keeps the recount off it.
CREATE INDEX advisories_tally ON advisories (id, severity, withdrawn);

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
WHERE f.resolved_at IS NULL AND a.withdrawn IS NULL
GROUP BY f.host_id, f.site_root;
