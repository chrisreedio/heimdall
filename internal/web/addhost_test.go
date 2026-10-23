// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"net/url"
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
