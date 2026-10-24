// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/chrisreedio/heimdall/internal/snapshot"
)

func TestParseSiteRepos(t *testing.T) {
	cases := map[string]map[string]string{
		"v1": {},
		"v1 /home/forge/a.com https://github.com/acme/a,/var/www/b git@github.com:acme/b": {
			"/home/forge/a.com": "https://github.com/acme/a", "/var/www/b": "git@github.com:acme/b"},
		"v1 /a x, ,noURL,/a y": {"/a": "x"}, // the store normalizes or drops each URL
	}
	for in, want := range cases {
		got, ok := parseSiteRepos(in)
		if !ok || !maps.Equal(got, want) {
			t.Errorf("parseSiteRepos(%q) = %v, %v; want %v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "v2 /a b", "v1x", "/a https://github.com/a/b", "v1 " + strings.Repeat("a", maxSiteReposHeader)} {
		if _, ok := parseSiteRepos(bad); ok {
			t.Errorf("parseSiteRepos(%q) accepted", bad)
		}
	}
}

func (e *env) pushRepos(header string, set bool) {
	e.t.Helper()
	hr := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(e.body))
	hr.Header.Set("Authorization", "Bearer "+e.token)
	hr.Header.Set("Content-Type", "application/json")
	if set {
		hr.Header.Set(SiteReposHeader, header)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, hr)
	if w.Code >= 300 {
		e.t.Fatalf("push status %d: %s", w.Code, w.Body.String())
	}
}

func TestSiteReposHeader(t *testing.T) {
	e := newEnv(t, nil)
	ctx := t.Context()
	e.pushRepos("v1 /home/forge/a.com https://forge:ghp_SECRET@github.com/acme/a.git,/var/www/b file:///srv/b.git", true)
	repos, _ := e.st.SiteRepos(ctx, e.host.ID)
	if len(repos) != 1 || repos["/home/forge/a.com"].Detected != "https://github.com/acme/a" {
		t.Fatalf("repos = %+v", repos)
	}
	// An operator's repository wins and survives the collector's changes.
	if err := e.st.SetSiteRepo(ctx, "user:1", e.host.ID, "/var/www/b", "git@github.com:acme/b.git"); err != nil {
		t.Fatal(err)
	}
	// An older collector (no header) and a malformed one change nothing.
	e.pushRepos("", false)
	e.pushRepos("garbage", true)
	if repos, _ := e.st.SiteRepos(ctx, e.host.ID); repos["/home/forge/a.com"].Detected == "" || repos["/var/www/b"].Repo() != "git@github.com:acme/b" {
		t.Fatalf("repos = %+v", repos)
	}
	// "v1" alone: the collector found none, so detected ones go.
	e.pushRepos("v1", true)
	repos, _ = e.st.SiteRepos(ctx, e.host.ID)
	if _, ok := repos["/home/forge/a.com"]; ok || len(repos) != 1 || repos["/var/www/b"].Manual != "git@github.com:acme/b" {
		t.Fatalf("repos = %+v", repos)
	}
	// Nothing that looked like a credential was stored.
	for _, r := range repos {
		if strings.Contains(r.Detected+r.Manual, "SECRET") {
			t.Fatalf("credential stored: %+v", r)
		}
	}
}

// Old hubs and new collectors: repositories travel in a header, so the
// snapshot body a new collector sends is the same document every hub
// already accepts. Simulated here with the strict decoder, which an old
// hub would run unchanged: the v3 body decodes, while a "repo" field in a
// site (the alternative design) would make it reject the whole push.
func TestSiteReposCompatibleWithOlderHubs(t *testing.T) {
	raw, err := os.ReadFile("../snapshot/testdata/debian12-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.DecodeBytes(raw); err != nil {
		t.Fatalf("the body a collector sends: %v", err)
	}
	var doc map[string]any
	json.Unmarshal(raw, &doc)
	doc["sites"].([]any)[0].(map[string]any)["repo"] = "https://github.com/acme/app"
	withField, _ := json.Marshal(doc)
	if _, err := snapshot.DecodeBytes(withField); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("a site field would have been accepted by older hubs (%v); the header design would be unnecessary", err)
	}
	// And a hub that doesn't know the header (any older release) accepts
	// the push untouched: the handler ignores unknown headers, which is
	// what this release does for any header it doesn't read.
	e := newEnv(t, nil)
	hr := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(e.body))
	hr.Header.Set("Authorization", "Bearer "+e.token)
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("X-Heimdall-Some-Future-Header", "v9 anything at all")
	hr.Header.Set(SiteReposHeader, "v1 /home/forge/a.com https://github.com/acme/a")
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, hr)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if repos, _ := e.st.SiteRepos(t.Context(), e.host.ID); repos["/home/forge/a.com"].Detected != "https://github.com/acme/a" {
		t.Errorf("repos = %+v", repos)
	}
}
