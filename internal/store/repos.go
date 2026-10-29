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

// SiteRepo is a site's repository and checked-out branch: as detected by
// the collector, and as set by an operator (which wins).
type SiteRepo struct {
	Detected, Manual string
	// DetectedBranch is the branch the collector found checked out, or ""
	// (unknown, or a detached HEAD: then DetectedCommit is its commit).
	DetectedBranch, DetectedCommit string
	ManualBranch                   string
}

// Branch is the branch to use: the manual one if set, else the detected
// one, or "" when unknown.
func (r SiteRepo) Branch() string {
	if r.ManualBranch != "" {
		return r.ManualBranch
	}
	return r.DetectedBranch
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
	rows, err := s.db.QueryContext(ctx, `SELECT root, `+siteRepoCols+` FROM site_repos WHERE host_id = ?`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]SiteRepo{}
	for rows.Next() {
		var root string
		var r SiteRepo
		if err := rows.Scan(append([]any{&root}, r.dest()...)...); err != nil {
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
		SELECT o.slug, h.name, r.root, r.detected, r.manual, r.detected_branch, r.detected_commit, r.manual_branch
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
		if err := rows.Scan(append([]any{&org, &host, &root}, r.dest()...)...); err != nil {
			return nil, err
		}
		out[SiteLabelKey(org, host, root)] = r
	}
	return out, rows.Err()
}

const siteRepoCols = `detected, manual, detected_branch, detected_commit, manual_branch`

func (r *SiteRepo) dest() []any {
	return []any{&r.Detected, &r.Manual, &r.DetectedBranch, &r.DetectedCommit, &r.ManualBranch}
}

// RepoSite is a site with a known repository, anywhere on the hub.
type RepoSite struct {
	OrgID     int64
	Org, Host string
	HostID    int64
	Root      string
	Repo      SiteRepo
}

// RepoSites returns every site whose repository (manual or detected) is
// known, in every org: the hand-off finds a repository's other sites with
// it, and keeps only those in orgs the viewer may operate in.
func (s *Store) RepoSites(ctx context.Context) ([]RepoSite, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.org_id, o.slug, h.name, h.id, r.root, r.detected, r.manual, r.detected_branch, r.detected_commit, r.manual_branch
		FROM site_repos r
		JOIN hosts h ON h.id = r.host_id
		JOIN organizations o ON o.id = h.org_id
		WHERE r.detected != '' OR r.manual != ''
		ORDER BY o.slug, h.name, r.root`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RepoSite
	for rows.Next() {
		var rs RepoSite
		if err := rows.Scan(append([]any{&rs.OrgID, &rs.Org, &rs.Host, &rs.HostID, &rs.Root}, rs.Repo.dest()...)...); err != nil {
			return nil, err
		}
		out = append(out, rs)
	}
	return out, rows.Err()
}

// emptyRow matches a site_repos row with nothing left in it.
const emptyRow = `detected = '' AND manual = '' AND detected_branch = '' AND detected_commit = '' AND manual_branch = ''`

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
		_, err = tx.ExecContext(ctx, `DELETE FROM site_repos WHERE host_id = ? AND `+emptyRow, hostID)
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
		if _, err := tx.ExecContext(ctx, `DELETE FROM site_repos WHERE host_id = ? AND root = ? AND `+emptyRow, hostID, root); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "site.repo", OrgID: orgID, Target: name,
			Detail: map[string]any{"root": root, "repo": repo}})
	})
}

// DetectedRef is a site's checked-out branch as the collector reports it:
// a branch, or the commit of a detached HEAD.
type DetectedRef struct {
	Branch, Commit string
}

// SetDetectedSiteBranches replaces the collector-detected branches of a
// host's sites with refs (root → branch or commit). A branch or commit
// that isn't valid is dropped. Sites not in refs lose their detected
// branch (unknown is normal: a zero-downtime release often has no .git);
// manual ones are kept.
func (s *Store) SetDetectedSiteBranches(ctx context.Context, hostID int64, refs map[string]DetectedRef) error {
	clean := map[string]DetectedRef{}
	for _, root := range slices.Sorted(maps.Keys(refs)) {
		if len(clean) == MaxDetectedRepos {
			break
		}
		ref := refs[root]
		switch {
		case !validRepoRoot(root):
		case ref.Branch != "" && ref.Commit == "" && handoff.ValidBranch(ref.Branch):
			clean[root] = ref
		case ref.Branch == "" && handoff.ValidCommit(ref.Commit):
			clean[root] = ref
		}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		cur := map[string]DetectedRef{}
		rows, err := tx.QueryContext(ctx, `SELECT root, detected_branch, detected_commit FROM site_repos
			WHERE host_id = ? AND (detected_branch != '' OR detected_commit != '')`, hostID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var root string
			var ref DetectedRef
			if err := rows.Scan(&root, &ref.Branch, &ref.Commit); err != nil {
				rows.Close()
				return err
			}
			cur[root] = ref
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
				if _, err := tx.ExecContext(ctx, `UPDATE site_repos SET detected_branch = '', detected_commit = '',
					updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE host_id = ? AND root = ?`, hostID, root); err != nil {
					return err
				}
			}
		}
		for root, ref := range clean {
			if cur[root] == ref {
				continue
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO site_repos (host_id, root, detected_branch, detected_commit) VALUES (?, ?, ?, ?)
				ON CONFLICT (host_id, root) DO UPDATE SET detected_branch = excluded.detected_branch,
					detected_commit = excluded.detected_commit,
					updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`, hostID, root, ref.Branch, ref.Commit); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM site_repos WHERE host_id = ? AND `+emptyRow, hostID)
		return err
	})
}

// SetSiteBranch sets (or, with "", clears) the branch an operator gave a
// site, for when the collector can't see it (a release with no .git).
func (s *Store) SetSiteBranch(ctx context.Context, actor string, hostID int64, root, branch string) error {
	if !validRepoRoot(root) {
		return &ValidationError{"site", "a site root is required"}
	}
	if branch != "" && !handoff.ValidBranch(branch) {
		return &ValidationError{"branch", "a branch name is letters, digits, \".\", \"_\", \"-\" and \"/\""}
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
			INSERT INTO site_repos (host_id, root, manual_branch) VALUES (?, ?, ?)
			ON CONFLICT (host_id, root) DO UPDATE SET manual_branch = excluded.manual_branch,
				updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`, hostID, root, branch); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM site_repos WHERE host_id = ? AND root = ? AND `+emptyRow, hostID, root); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "site.branch", OrgID: orgID, Target: name,
			Detail: map[string]any{"root": root, "branch": branch}})
	})
}
