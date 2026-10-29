// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"strings"
	"testing"
)

func TestSiteRepos(t *testing.T) {
	s, ctx := newStore(t), t.Context()
	s.CreateOrg(ctx, "test", "acme", "")
	s.CreateEnv(ctx, "test", "acme", "prod", "")
	h, _, _ := s.AddHost(ctx, "test", "acme", "prod", "web-01", nil)

	if err := s.SetDetectedSiteRepos(ctx, h.ID, map[string]string{
		"/var/www/app": "https://deploy:ghp_SECRET@github.com/acme/app.git", "/var/www/bad": "file:///x", "relative": "https://github.com/a/b",
	}); err != nil {
		t.Fatal(err)
	}
	repos, _ := s.SiteRepos(ctx, h.ID)
	if len(repos) != 1 || repos["/var/www/app"] != (SiteRepo{Detected: "https://github.com/acme/app"}) {
		t.Fatalf("repos = %+v", repos)
	}
	// The manual repository wins; credentials are stripped; it's audited.
	if err := s.SetSiteRepo(ctx, "user:1", h.ID, "/var/www/app", "https://x:SECRET@gitlab.com/acme/app"); err != nil {
		t.Fatal(err)
	}
	repos, _ = s.SiteRepos(ctx, h.ID)
	r := repos["/var/www/app"]
	if r.Repo() != "https://gitlab.com/acme/app" || r.Detected != "https://github.com/acme/app" {
		t.Errorf("repo = %+v", r)
	}
	s.CreateOrg(ctx, "test", "beta", "")
	s.CreateEnv(ctx, "test", "beta", "prod", "")
	other, _, _ := s.AddHost(ctx, "test", "beta", "prod", "web-09", nil)
	s.SetSiteRepo(ctx, "user:1", other.ID, "/var/www/app", "https://github.com/beta/app")
	ih, _ := s.HostByName(ctx, "acme", "web-01")
	if byOrg, _ := s.SiteReposByOrg(ctx, ih.OrgID); len(byOrg) != 1 || byOrg[SiteLabelKey("acme", "web-01", "/var/www/app")] != r {
		t.Errorf("by org = %+v", byOrg)
	}
	if at, _ := s.LastAuditAt(ctx, "site.repo"); at.IsZero() {
		t.Error("site.repo not audited")
	}
	var ve *ValidationError
	if err := s.SetSiteRepo(ctx, "user:1", h.ID, "/var/www/app", "ftp://SECRET@x/y"); !errors.As(err, &ve) || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("invalid repo: %v", err)
	}
	if err := s.SetSiteRepo(ctx, "user:1", 999, "/var/www/app", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing host: %v", err)
	}
	// Clearing both removes the row.
	s.SetSiteRepo(ctx, "user:1", h.ID, "/var/www/app", "")
	s.SetDetectedSiteRepos(ctx, h.ID, nil)
	if repos, _ := s.SiteRepos(ctx, h.ID); len(repos) != 0 {
		t.Errorf("repos = %+v", repos)
	}
}

func TestSiteBranches(t *testing.T) {
	s, ctx := newStore(t), t.Context()
	s.CreateOrg(ctx, "test", "acme", "")
	s.CreateEnv(ctx, "test", "acme", "prod", "")
	h, _, _ := s.AddHost(ctx, "test", "acme", "prod", "web-01", nil)
	sha := strings.Repeat("ab", 20)

	s.SetDetectedSiteRepos(ctx, h.ID, map[string]string{"/var/www/app": "https://github.com/acme/app"})
	if err := s.SetDetectedSiteBranches(ctx, h.ID, map[string]DetectedRef{
		"/var/www/app": {Branch: "dev"}, "/var/www/zdt/current": {Commit: sha},
		"/var/www/bad": {Branch: "a..b"}, "/var/www/both": {Branch: "x", Commit: sha}, "/var/www/hash": {Commit: "abc"},
		"relative": {Branch: "main"},
	}); err != nil {
		t.Fatal(err)
	}
	repos, _ := s.SiteRepos(ctx, h.ID)
	if len(repos) != 2 || repos["/var/www/app"] != (SiteRepo{Detected: "https://github.com/acme/app", DetectedBranch: "dev"}) ||
		repos["/var/www/zdt/current"] != (SiteRepo{DetectedCommit: sha}) {
		t.Fatalf("repos = %+v", repos)
	}
	// A push without the repository keeps the branch-only row.
	s.SetDetectedSiteRepos(ctx, h.ID, map[string]string{"/var/www/app": "https://github.com/acme/app"})
	if repos, _ := s.SiteRepos(ctx, h.ID); repos["/var/www/zdt/current"].DetectedCommit != sha {
		t.Errorf("repository push dropped a branch: %+v", repos)
	}
	// The manual branch wins and is audited; an invalid one is refused.
	if err := s.SetSiteBranch(ctx, "user:1", h.ID, "/var/www/zdt/current", "env/beta"); err != nil {
		t.Fatal(err)
	}
	if repos, _ := s.SiteRepos(ctx, h.ID); repos["/var/www/zdt/current"].Branch() != "env/beta" || repos["/var/www/app"].Branch() != "dev" {
		t.Errorf("branch = %+v", repos)
	}
	if at, _ := s.LastAuditAt(ctx, "site.branch"); at.IsZero() {
		t.Error("site.branch not audited")
	}
	var ve *ValidationError
	if err := s.SetSiteBranch(ctx, "user:1", h.ID, "/var/www/app", "x; reboot"); !errors.As(err, &ve) || ve.Field != "branch" {
		t.Errorf("invalid branch: %v", err)
	}
	// The site is everywhere it should be: RepoSites lists repository rows only.
	all, _ := s.RepoSites(ctx)
	if len(all) != 1 || all[0].Root != "/var/www/app" || all[0].Repo.Branch() != "dev" || all[0].Org != "acme" || all[0].Host != "web-01" {
		t.Errorf("RepoSites = %+v", all)
	}
	// Zero input: every detected branch goes, the manual one stays, and an
	// emptied row is removed.
	s.SetDetectedSiteBranches(ctx, h.ID, nil)
	repos, _ = s.SiteRepos(ctx, h.ID)
	if repos["/var/www/app"].DetectedBranch != "" || repos["/var/www/zdt/current"] != (SiteRepo{ManualBranch: "env/beta"}) {
		t.Errorf("after an empty push: %+v", repos)
	}
	s.SetSiteBranch(ctx, "user:1", h.ID, "/var/www/zdt/current", "")
	if repos, _ := s.SiteRepos(ctx, h.ID); len(repos) != 1 {
		t.Errorf("cleared row kept: %+v", repos)
	}
}
