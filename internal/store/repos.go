// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/realmwatch/heimdall/internal/handoff"
)

// SiteRepo is a site's repository: as detected by the collector, and as
// set by an operator (which wins).
type SiteRepo struct {
	Detected, Manual string
}

// Repo is the repository to use: the manual one if set, else the detected one.
func (r SiteRepo) Repo() string {
	if r.Manual != "" {
		return r.Manual
	}
	return r.Detected
}

// MaxDetectedRepos caps how many detected repositories one push can set.
const MaxDetectedRepos = 200

// SiteRepos returns a host's site repositories, keyed by root.
func (s *Store) SiteRepos(ctx context.Context, hostID int64) (map[string]SiteRepo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT root, detected, manual FROM site_repos WHERE host_id = ?`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]SiteRepo{}
	for rows.Next() {
		var root string
		var r SiteRepo
		if err := rows.Scan(&root, &r.Detected, &r.Manual); err != nil {
			return nil, err
		}
		out[root] = r
	}
	return out, rows.Err()
}

// SiteReposByOrg returns the repositories of an org's sites, keyed by
// SiteLabelKey (org, host, root).
func (s *Store) SiteReposByOrg(ctx context.Context, orgID int64) (map[string]SiteRepo, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT o.slug, h.name, r.root, r.detected, r.manual
		FROM site_repos r
		JOIN hosts h ON h.id = r.host_id
		JOIN organizations o ON o.id = h.org_id
		WHERE h.org_id = ?`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]SiteRepo{}
	for rows.Next() {
		var org, host, root string
		var r SiteRepo
		if err := rows.Scan(&org, &host, &root, &r.Detected, &r.Manual); err != nil {
			return nil, err
		}
		out[SiteLabelKey(org, host, root)] = r
	}
	return out, rows.Err()
}

func validRepoRoot(root string) bool { return root != "" && len(root) <= 512 && root[0] == '/' }

// SetDetectedSiteRepos replaces the collector-detected repositories of a
// host's sites with repos (root → URL). Every URL is normalized here, with
// credentials stripped, and one that isn't valid is dropped. Sites not in
// repos lose their detected repository; manual ones are kept.
func (s *Store) SetDetectedSiteRepos(ctx context.Context, hostID int64, repos map[string]string) error {
	clean := map[string]string{}
	for _, root := range slices.Sorted(maps.Keys(repos)) {
		if len(clean) == MaxDetectedRepos {
			break
		}
		if !validRepoRoot(root) {
			continue
		}
		if u, err := handoff.NormalizeRepo(repos[root]); err == nil {
			clean[root] = u
		}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		cur := map[string]string{}
		rows, err := tx.QueryContext(ctx, `SELECT root, detected FROM site_repos WHERE host_id = ? AND detected != ''`, hostID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var root, d string
			if err := rows.Scan(&root, &d); err != nil {
				rows.Close()
				return err
			}
			cur[root] = d
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if maps.Equal(cur, clean) {
			return nil // the usual hourly push: nothing changed
		}
		for root := range cur {
			if _, ok := clean[root]; !ok {
				if _, err := tx.ExecContext(ctx, `UPDATE site_repos SET detected = '', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
					WHERE host_id = ? AND root = ?`, hostID, root); err != nil {
					return err
				}
			}
		}
		for root, u := range clean {
			if cur[root] == u {
				continue
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO site_repos (host_id, root, detected) VALUES (?, ?, ?)
				ON CONFLICT (host_id, root) DO UPDATE SET detected = excluded.detected,
					updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`, hostID, root, u); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM site_repos WHERE host_id = ? AND detected = '' AND manual = ''`, hostID)
		return err
	})
}

// SetSiteRepo sets (or, with "", clears) the repository an operator gave a
// site. Credentials in the URL are stripped and never stored.
func (s *Store) SetSiteRepo(ctx context.Context, actor string, hostID int64, root, repo string) error {
	if !validRepoRoot(root) {
		return &ValidationError{"site", "a site root is required"}
	}
	if repo != "" {
		u, err := handoff.NormalizeRepo(repo)
		if err != nil {
			return &ValidationError{"repo", err.Error()}
		}
		repo = u
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var orgID int64
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT org_id, name FROM hosts WHERE id = ?`, hostID).Scan(&orgID, &name); errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("host %d: %w", hostID, ErrNotFound)
		} else if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO site_repos (host_id, root, manual) VALUES (?, ?, ?)
			ON CONFLICT (host_id, root) DO UPDATE SET manual = excluded.manual,
				updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`, hostID, root, repo); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM site_repos WHERE host_id = ? AND root = ? AND detected = '' AND manual = ''`, hostID, root); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "site.repo", OrgID: orgID, Target: name,
			Detail: map[string]any{"root": root, "repo": repo}})
	})
}
