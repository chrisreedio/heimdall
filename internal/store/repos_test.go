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
