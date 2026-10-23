// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/report"
	"github.com/chrisreedio/heimdall/internal/store"
)

func TestAddHost(t *testing.T) {
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.IngestURL, c.Version = "https://ingest.example.com", "v0.4.0"
	})
	e.seed()
	if w := e.get("/hosts/new", signedIn(e)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Register host") {
		t.Fatalf("form: %d", w.Code)
	}
	f := url.Values{"csrf": {auth.CSRFToken(goodToken)}, "org": {"acme"}, "env": {"prod"}, "name": {"db-07"}, "tags": {"db, role:primary"}}
	w := e.post("/hosts/new", f, signedIn(e), origin(e.baseURL))
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "hmd_ingest_") {
		t.Fatalf("add: %d", w.Code)
	}
	want := "curl -fsSLO https://github.com/chrisreedio/heimdall/releases/download/v0.4.0/install.sh &amp;&amp; sudo sh install.sh --hub https://ingest.example.com"
	if !strings.Contains(body, want) {
		t.Errorf("linux command missing:\n%s", body)
	}
	if strings.Contains(body, "127.0.0.1:8080/install") {
		t.Error("install command must never point at the hub")
	}
	if h, err := e.st.HostByName(t.Context(), "acme", "db-07"); err != nil || h.Name != "db-07" {
		t.Errorf("host not created: %v", err)
	}
	// Only org admins may add hosts; others don't learn the page exists.
	orgs, _ := e.st.ListOrgs(t.Context())
	e.auth.viewer = &auth.Viewer{UserID: 1, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{orgs[0].ID: store.RoleOperator}}}
	if w := e.get("/hosts/new", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("operator: %d", w.Code)
	}
	if w := e.post("/hosts/new", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("operator post: %d", w.Code)
	}
}

func TestAddHostFormDetails(t *testing.T) {
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.IngestURL, c.Version = "https://ingest.example.com", "v0.4.0"
	})
	e.seed()
	// One org: the environment picker isn't grouped by org.
	if body := e.get("/hosts/new", signedIn(e)).Body.String(); strings.Contains(body, "<optgroup") || !strings.Contains(body, `value="acme/prod"`) {
		t.Errorf("environment options:\n%s", body)
	}
	// The picker's "org/env" value is accepted.
	f := url.Values{"csrf": {auth.CSRFToken(goodToken)}, "env": {"acme/prod"}, "name": {"web-09"}}
	if w := e.post("/hosts/new", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "web-09 is registered") {
		t.Fatalf("add with org/env: %d", w.Code)
	}
	// A rejected submit keeps what was typed.
	f = url.Values{"csrf": {auth.CSRFToken(goodToken)}, "env": {"acme/prod"}, "name": {"Bad Name!"}, "tags": {"web, role:lb"}}
	w := e.post("/hosts/new", f, signedIn(e), origin(e.baseURL))
	if body := w.Body.String(); w.Code != http.StatusBadRequest || !strings.Contains(body, `value="Bad Name!"`) || !strings.Contains(body, `value="web, role:lb"`) || !strings.Contains(body, `value="acme/prod" selected`) {
		t.Errorf("rejected submit should keep its values: %d", w.Code)
	}
}

func TestTaggingRoutes(t *testing.T) {
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, nil)
	e.seed()
	ctx := t.Context()
	a, _, _ := e.st.AddHost(ctx, "test", "acme", "prod", "tag-a", nil)
	b, _, _ := e.st.AddHost(ctx, "test", "acme", "prod", "tag-b", nil)
	csrf := auth.CSRFToken(goodToken)
	f := url.Values{"csrf": {csrf}, "tag": {"frontend"}, "host": {strconv.FormatInt(a.ID, 10), strconv.FormatInt(b.ID, 10)}}
	if w := e.post("/drift/tag", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "tagged=2") {
		t.Fatalf("drift tag: %d %s", w.Code, w.Header().Get("Location"))
	}
	if body := e.get("/drift", signedIn(e)).Body.String(); !strings.Contains(body, `<option value="frontend"`) {
		t.Error("newly shared tag isn't offered for comparison")
	}
	f = url.Values{"csrf": {csrf}, "tags": {"db, Primary"}}
	if w := e.post("/hosts/acme/tag-a/tags", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("host tags: %d", w.Code)
	}
	if tags, _ := e.st.HostTags(ctx, a.ID); strings.Join(tags, ",") != "db,primary" {
		t.Errorf("tags = %v", tags)
	}
	// An unknown host ID is refused, and so is anyone below org admin.
	f = url.Values{"csrf": {csrf}, "tag": {"x"}, "host": {"999999"}}
	if w := e.post("/drift/tag", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("unknown host: %d", w.Code)
	}
	orgs, _ := e.st.ListOrgs(ctx)
	e.auth.viewer = &auth.Viewer{UserID: 1, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{orgs[0].ID: store.RoleOperator}}}
	f = url.Values{"csrf": {csrf}, "tag": {"x"}, "host": {strconv.FormatInt(a.ID, 10)}}
	if w := e.post("/drift/tag", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("operator tagging: %d", w.Code)
	}
	if w := e.post("/hosts/acme/tag-a/tags", url.Values{"csrf": {csrf}, "tags": {"x"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("operator editing tags: %d", w.Code)
	}
	if w := e.post("/hosts/acme/tag-a/rename", url.Values{"csrf": {csrf}, "name": {"x"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("operator renaming: %d", w.Code)
	}
}

func TestSuggestSiteLabel(t *testing.T) {
	for names, want := range map[string]string{
		"example.com": "production", "www.example.com": "production", "staging.example.com": "staging",
		"stg-api.example.com": "staging", "uat.example.com": "staging", "dev.example.com": "development",
		"api-dev.example.com": "development", "test.example.com": "development", "_": "", "": "",
	} {
		var ns []string
		if names != "" {
			ns = []string{names}
		}
		if got := suggestSiteLabel(ns); got != want {
			t.Errorf("%q: got %q, want %q", names, got, want)
		}
	}
}

func TestEnvironmentsAndSiteLabels(t *testing.T) {
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.IngestURL, c.Version = "https://ingest.example.com", "v0.4.0"
	})
	e.seed()
	ctx := t.Context()
	csrf := auth.CSRFToken(goodToken)
	// Add a host into a brand-new environment.
	f := url.Values{"csrf": {csrf}, "env": {"acme/__new__"}, "new_env": {"Shared-Hosting"}, "name": {"box-1"}}
	if w := e.post("/hosts/new", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusOK {
		t.Fatalf("add into new env: %d %s", w.Code, w.Body.String())
	}
	h, _ := e.st.HostByName(ctx, "acme", "box-1")
	if h.EnvSlug != "shared-hosting" {
		t.Errorf("env = %q", h.EnvSlug)
	}
	if w := e.post("/hosts/new", url.Values{"csrf": {csrf}, "env": {"acme/__new__"}, "name": {"box-2"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusBadRequest {
		t.Errorf("new env without a name: %d", w.Code)
	}
	// Move it back to prod from the host page; the Hosts page filters by env.
	if w := e.post("/hosts/acme/box-1/env", url.Values{"csrf": {csrf}, "env": {"prod"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("move: %d", w.Code)
	}
	if h, _ = e.st.HostByName(ctx, "acme", "box-1"); h.EnvSlug != "prod" {
		t.Errorf("after move env = %q", h.EnvSlug)
	}
	e.st.AddHost(ctx, "test", "acme", "shared-hosting", "box-3", nil)
	body := e.get("/hosts?env=shared-hosting", signedIn(e)).Body.String()
	if !strings.Contains(body, "box-3") || strings.Contains(body, ">box-1<") {
		t.Errorf("env filter didn't filter")
	}
	// Site labels: admins set one, and only admins.
	f = url.Values{"csrf": {csrf}, "org": {"acme"}, "host": {"box-1"}, "root": {"/var/www/app"}, "label": {"staging"}}
	if w := e.post("/sites/label", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("label: %d", w.Code)
	}
	if labels, _ := e.st.SiteLabelsByName(ctx); labels[store.SiteLabelKey("acme", "box-1", "/var/www/app")] != "staging" {
		t.Errorf("labels = %v", labels)
	}
	orgs, _ := e.st.ListOrgs(ctx)
	e.auth.viewer = &auth.Viewer{UserID: 1, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{orgs[0].ID: store.RoleOperator}}}
	f.Set("label", "production")
	if w := e.post("/sites/label", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("operator labelling: %d", w.Code)
	}
	if w := e.post("/hosts/acme/box-1/env", url.Values{"csrf": {csrf}, "env": {"shared-hosting"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("operator moving a host: %d", w.Code)
	}
}

func TestHostPageHelpers(t *testing.T) {
	pathBreak := funcs["pathBreak"].(func(string) template.HTML)
	if got := pathBreak(`/home/<b>evil</b>/x`); string(got) != `/<wbr>home/<wbr>&lt;b&gt;evil&lt;/<wbr>b&gt;/<wbr>x` {
		t.Errorf("pathBreak = %q", got)
	}
	relPath := funcs["relPath"].(func(string, string) string)
	if got := relPath("/home/forge/site/current", "/home/forge/site/current/public"); got != "public" {
		t.Errorf("relPath inside = %q", got)
	}
	if got := relPath("/var/www/a", "/srv/b"); got != "/srv/b" {
		t.Errorf("relPath outside = %q", got)
	}
	head := funcs["head"].(func([]report.Finding, int, bool) []report.Finding)
	list := make([]report.Finding, 250)
	if len(head(list, 200, false)) != 200 || len(head(list, 200, true)) != 250 || len(head(list[:5], 200, false)) != 5 {
		t.Error("head doesn't cap as expected")
	}
}

func TestSitePageNotFound(t *testing.T) {
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, nil)
	e.seed()
	e.st.AddHost(t.Context(), "test", "acme", "prod", "site-host", nil)
	for _, path := range []string{
		"/hosts/acme/site-host/site?root=%2Fvar%2Fwww%2Fnope", // no such site
		"/hosts/acme/nope/site?root=%2Fvar%2Fwww",             // no such host
		"/hosts/other/site-host/site?root=%2F",                // no such org
	} {
		if w := e.get(path, signedIn(e)); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
}
