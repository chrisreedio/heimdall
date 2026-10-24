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

// ── Threat news ────────────────────────────────────────────────────────────

// NewsItem is one incident from a news feed. Its text is untrusted: it was
// validated by internal/feeds/news and must only be rendered escaped.
type NewsItem struct {
	ID          int64
	Source      string // feed URL
	Slug        string
	Category    string // patch, breach, supply-chain
	Title       string
	URL         string // https, links back to the source
	Severity    string
	PatchStatus string
	Status      string // live or closed
	Product     string
	Stacks      []string
	Tags        []string
	CVEs        []string
	Affected    []string
	Fixed       []string
	Summary     string
	StartedAt   time.Time
	UpdatedAt   time.Time
	ClosedAt    *time.Time
	FetchedAt   time.Time
}

// NewsHost is a host an incident affects.
type NewsHost struct {
	HostID  int64
	OrgID   int64
	OrgSlug string
	Name    string
	Reason  string // the CVE IDs that matched
}

// NewsEntry is an incident with the hosts it affects (only those the
// caller's scope may see).
type NewsEntry struct {
	NewsItem
	Hosts []NewsHost
}

// NewsRetention is how long closed incidents are kept.
const NewsRetention = 90 * 24 * time.Hour

var newsCategories = []string{"patch", "breach", "supply-chain"}

func checkNewsItem(it NewsItem) error {
	switch {
	case it.Slug == "":
		return &ValidationError{"slug", "is required"}
	case it.Title == "":
		return &ValidationError{"title", "is required"}
	case !strings.HasPrefix(it.URL, "https://"):
		return &ValidationError{"url", "must be https"}
	case !slices.Contains(newsCategories, it.Category):
		return &ValidationError{"category", "must be patch, breach or supply-chain"}
	case it.StartedAt.IsZero() || it.UpdatedAt.IsZero():
		return &ValidationError{"dates", "startedAt and updatedAt are required"}
	}
	return nil
}

// NewsValidators returns the ETag and Last-Modified stored for a source.
func (s *Store) NewsValidators(ctx context.Context, source string) (etag, lastModified string, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT etag, last_modified FROM news_sources WHERE source = ?`, source).
		Scan(&etag, &lastModified)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	return etag, lastModified, err
}

// TouchNewsSource records an unchanged (304) check of a source.
func (s *Store) TouchNewsSource(ctx context.Context, source string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE news_sources SET checked_at = ? WHERE source = ?`,
		at.UTC().Format(timeLayout), source)
	return err
}

// ReplaceNews makes a source's stored incidents exactly items, keeping the
// IDs (and so the matches) of incidents it already had, and remembers the
// response's validators. Callers pass only a successfully parsed, non-empty
// feed: a failed fetch never reaches here, so the last good copy stays.
func (s *Store) ReplaceNews(ctx context.Context, source string, items []NewsItem, etag, lastModified string, at time.Time) (removed int, err error) {
	for _, it := range items {
		if err := checkNewsItem(it); err != nil {
			return 0, err
		}
	}
	ts := at.UTC().Format(timeLayout)
	jsonList := func(l []string) string {
		if l == nil {
			l = []string{}
		}
		b, _ := json.Marshal(l)
		return string(b)
	}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE IF NOT EXISTS current_news (slug TEXT PRIMARY KEY)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM temp.current_news`); err != nil {
			return err
		}
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO news_items (source, slug, category, title, url, severity, patch_status, status, product,
				stacks, tags, cve_ids, affected, fixed, summary, started_at, updated_at, closed_at, fetched_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (source, slug) DO UPDATE SET
				category = excluded.category, title = excluded.title, url = excluded.url,
				severity = excluded.severity, patch_status = excluded.patch_status, status = excluded.status,
				product = excluded.product, stacks = excluded.stacks, tags = excluded.tags,
				cve_ids = excluded.cve_ids, affected = excluded.affected, fixed = excluded.fixed,
				summary = excluded.summary, started_at = excluded.started_at, updated_at = excluded.updated_at,
				closed_at = excluded.closed_at, fetched_at = excluded.fetched_at`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, it := range items {
			var closed sql.NullString
			if it.ClosedAt != nil {
				closed = sql.NullString{String: it.ClosedAt.UTC().Format(timeLayout), Valid: true}
			}
			if _, err := stmt.ExecContext(ctx, source, it.Slug, it.Category, it.Title, it.URL, it.Severity,
				it.PatchStatus, it.Status, it.Product, jsonList(it.Stacks), jsonList(it.Tags), jsonList(it.CVEs),
				jsonList(it.Affected), jsonList(it.Fixed), it.Summary, it.StartedAt.UTC().Format(timeLayout),
				it.UpdatedAt.UTC().Format(timeLayout), closed, ts); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO temp.current_news VALUES (?)`, it.Slug); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx,
			`DELETE FROM news_items WHERE source = ? AND slug NOT IN (SELECT slug FROM temp.current_news)`, source)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		removed = int(n)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO news_sources (source, etag, last_modified, checked_at) VALUES (?, ?, ?, ?)
			ON CONFLICT (source) DO UPDATE SET etag = excluded.etag, last_modified = excluded.last_modified,
				checked_at = excluded.checked_at`, source, etag, lastModified, ts); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM temp.current_news`)
		return err
	})
	return removed, err
}

// DeleteNewsExcept removes incidents (and validators) from sources that are
// no longer configured.
func (s *Store) DeleteNewsExcept(ctx context.Context, sources []string) (int, error) {
	b, _ := json.Marshal(append([]string{}, sources...))
	var n int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM news_items WHERE source NOT IN (SELECT value FROM json_each(?))`, string(b))
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		_, err = tx.ExecContext(ctx, `DELETE FROM news_sources WHERE source NOT IN (SELECT value FROM json_each(?))`, string(b))
		return err
	})
	return int(n), err
}

// PruneNews deletes closed incidents that closed before cutoff (or, with no
// close date, were last updated before it).
func (s *Store) PruneNews(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM news_items WHERE status = 'closed' AND coalesce(closed_at, updated_at) < ?`,
		cutoff.UTC().Format(timeLayout))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// MatchNews recomputes confirmed matches: an incident affects a host when
// one of its CVEs is an open finding there (the advisory's own ID or one of
// its aliases). hostID 0 recomputes every host. Matches that still hold
// keep their first matched_at; resolved findings drop theirs.
func (s *Store) MatchNews(ctx context.Context, hostID int64, at time.Time) error {
	ts := at.UTC().Format(timeLayout)
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`CREATE TEMP TABLE IF NOT EXISTS current_news_matches (item_id INTEGER, host_id INTEGER, reason TEXT)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM temp.current_news_matches`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO temp.current_news_matches (item_id, host_id, reason)
			SELECT m.item_id, m.host_id, group_concat(DISTINCT m.cve)
			FROM (
				SELECT n.id AS item_id, f.host_id AS host_id, c.value AS cve
				FROM news_items n, json_each(n.cve_ids) c
				JOIN findings f ON f.advisory_id = c.value
				JOIN advisories a ON a.id = f.advisory_id
				WHERE f.resolved_at IS NULL AND a.withdrawn IS NULL AND (?1 = 0 OR f.host_id = ?1)
				UNION
				SELECT n.id, f.host_id, c.value
				FROM news_items n, json_each(n.cve_ids) c
				JOIN advisory_aliases aa ON aa.alias = c.value
				JOIN findings f ON f.advisory_id = aa.advisory_id
				JOIN advisories a ON a.id = f.advisory_id
				WHERE f.resolved_at IS NULL AND a.withdrawn IS NULL AND (?1 = 0 OR f.host_id = ?1)
			) m
			GROUP BY m.item_id, m.host_id`, hostID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM news_matches WHERE kind = 'confirmed' AND (?1 = 0 OR host_id = ?1)
			  AND (item_id, host_id) NOT IN (SELECT item_id, host_id FROM temp.current_news_matches)`, hostID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO news_matches (item_id, host_id, kind, reason, matched_at)
			SELECT item_id, host_id, 'confirmed', reason, ? FROM temp.current_news_matches WHERE true
			ON CONFLICT (item_id, host_id, kind) DO UPDATE SET reason = excluded.reason`, ts); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM temp.current_news_matches`); err != nil {
			return err
		}
		// Incidents going live or closing change which findings are "in the news".
		return refreshFindingCounts(ctx, tx, hostID)
	})
}

// LiveNewsCVEs returns the CVE IDs named by live incidents.
func (s *Store) LiveNewsCVEs(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT c.value FROM news_items n, json_each(n.cve_ids) c WHERE n.status = 'live'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out[c] = true
	}
	return out, rows.Err()
}

const newsColumns = `n.id, n.source, n.slug, n.category, n.title, n.url, n.severity, n.patch_status, n.status,
	n.product, n.stacks, n.tags, n.cve_ids, n.affected, n.fixed, n.summary, n.started_at, n.updated_at,
	n.closed_at, n.fetched_at`

func scanNewsItem(rows *sql.Rows) (NewsItem, error) {
	var it NewsItem
	var stacks, tags, cves, affected, fixed, started, updated, fetched string
	var closed sql.NullString
	if err := rows.Scan(&it.ID, &it.Source, &it.Slug, &it.Category, &it.Title, &it.URL, &it.Severity,
		&it.PatchStatus, &it.Status, &it.Product, &stacks, &tags, &cves, &affected, &fixed, &it.Summary,
		&started, &updated, &closed, &fetched); err != nil {
		return it, err
	}
	for _, l := range []struct {
		raw string
		dst *[]string
	}{{stacks, &it.Stacks}, {tags, &it.Tags}, {cves, &it.CVEs}, {affected, &it.Affected}, {fixed, &it.Fixed}} {
		json.Unmarshal([]byte(l.raw), l.dst)
	}
	it.StartedAt, it.UpdatedAt, it.FetchedAt = parseTime(started), parseTime(updated), parseTime(fetched)
	if closed.Valid {
		t := parseTime(closed.String)
		it.ClosedAt = &t
	}
	return it, nil
}

// News lists stored incidents newest first, each with the hosts it affects
// that scope may see.
func (s *Store) News(ctx context.Context, scope Scope) ([]NewsEntry, error) {
	return s.news(ctx, scope, 0)
}

// HostNews lists the incidents that affect one host. The caller checks the
// viewer may see the host.
func (s *Store) HostNews(ctx context.Context, hostID int64) ([]NewsEntry, error) {
	all, err := s.news(ctx, AllScope, hostID)
	if err != nil {
		return nil, err
	}
	var out []NewsEntry
	for _, e := range all {
		if len(e.Hosts) > 0 {
			out = append(out, e)
		}
	}
	return out, nil
}

func (s *Store) news(ctx context.Context, scope Scope, onlyHost int64) ([]NewsEntry, error) {
	q := `SELECT ` + newsColumns + ` FROM news_items n`
	var args []any
	if onlyHost != 0 {
		q += ` WHERE n.id IN (SELECT item_id FROM news_matches WHERE host_id = ?)`
		args = append(args, onlyHost)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY n.started_at DESC, n.updated_at DESC, n.id DESC`, args...)
	if err != nil {
		return nil, err
	}
	var out []NewsEntry
	byID := map[int64]int{}
	for rows.Next() {
		it, err := scanNewsItem(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		byID[it.ID] = len(out)
		out = append(out, NewsEntry{NewsItem: it})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	q = `SELECT m.item_id, h.id, h.org_id, o.slug, h.name, m.reason
		FROM news_matches m JOIN hosts h ON h.id = m.host_id JOIN organizations o ON o.id = h.org_id
		WHERE m.kind = 'confirmed'`
	args = nil
	if onlyHost != 0 {
		q += ` AND m.host_id = ?`
		args = append(args, onlyHost)
	}
	mrows, err := s.db.QueryContext(ctx, q+` ORDER BY o.slug, h.name`, args...)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var item int64
		var h NewsHost
		if err := mrows.Scan(&item, &h.HostID, &h.OrgID, &h.OrgSlug, &h.Name, &h.Reason); err != nil {
			return nil, err
		}
		h.Reason = strings.ReplaceAll(h.Reason, ",", ", ")
		i, ok := byID[item]
		if !ok || !scope.CanView(h.OrgID) {
			continue
		}
		out[i].Hosts = append(out[i].Hosts, h)
	}
	return out, mrows.Err()
}
