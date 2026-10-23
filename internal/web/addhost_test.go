// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/chrisreedio/heimdall/internal/auth"
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
