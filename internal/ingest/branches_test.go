// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"bytes"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/store"
)

func TestParseSiteBranches(t *testing.T) {
	sha := strings.Repeat("0a", 20)
	cases := map[string]map[string]store.DetectedRef{
		"v1": {},
		"v1 /home/forge/a.com/current branch:main,/var/www/b commit:" + sha + ",/srv/with space branch:env/beta": {
			"/home/forge/a.com/current": {Branch: "main"}, "/var/www/b": {Commit: sha}, "/srv/with space": {Branch: "env/beta"}},
		"v1 /a branch:x, ,noRef,/b tag:v1,/c branch:,/a branch:y": {"/a": {Branch: "x"}}, // the store validates each name
	}
	for in, want := range cases {
		got, ok := parseSiteBranches(in)
		if !ok || !maps.Equal(got, want) {
			t.Errorf("parseSiteBranches(%q) = %v, %v; want %v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "v2 /a branch:b", "v1x", "/a branch:b", "v1 " + strings.Repeat("a", maxSiteReposHeader)} {
		if _, ok := parseSiteBranches(bad); ok {
			t.Errorf("parseSiteBranches(%q) accepted", bad)
		}
	}
}

func (e *env) pushBranches(header string, set bool) {
	e.t.Helper()
	hr := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(e.body))
	hr.Header.Set("Authorization", "Bearer "+e.token)
	hr.Header.Set("Content-Type", "application/json")
	if set {
		hr.Header.Set(SiteBranchesHeader, header)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, hr)
	if w.Code >= 300 {
		e.t.Fatalf("push status %d: %s", w.Code, w.Body.String())
	}
}

func TestSiteBranchesHeader(t *testing.T) {
	e := newEnv(t, nil)
	ctx := t.Context()
	e.pushBranches("v1 /home/forge/a.com branch:dev,/var/www/b branch:x;reboot", true)
	repos, _ := e.st.SiteRepos(ctx, e.host.ID)
	if len(repos) != 1 || repos["/home/forge/a.com"].DetectedBranch != "dev" {
		t.Fatalf("repos = %+v", repos)
	}
	// An older collector (no header) and a malformed one change nothing.
	e.pushBranches("", false)
	e.pushBranches("garbage", true)
	if repos, _ := e.st.SiteRepos(ctx, e.host.ID); repos["/home/forge/a.com"].DetectedBranch != "dev" {
		t.Fatalf("repos = %+v", repos)
	}
	// "v1" alone: none found (a zero-downtime release with no .git), so
	// the detected branch goes and the push still succeeds.
	e.pushBranches("v1", true)
	if repos, _ := e.st.SiteRepos(ctx, e.host.ID); len(repos) != 0 {
		t.Fatalf("repos = %+v", repos)
	}
}
