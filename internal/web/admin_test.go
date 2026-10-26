// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/ingest"
	"github.com/realmwatch/heimdall/internal/search"
	"github.com/realmwatch/heimdall/internal/store"
)

const testTenant = "11111111-1111-1111-1111-111111111111"

// adminEnv has the signed-in admin (user 1) and bob as real users, and
// orgs acme and globex.
func adminEnv(t *testing.T) *env {
	t.Helper()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.EntraTenants = []string{testTenant} })
	ctx := t.Context()
	secret := []byte("0123456789abcdefghij")
	if id, err := e.st.CreateLocalUser(ctx, "test", "admin@example.com", "Admin", true, "$argon2id$x", secret); err != nil || id != 1 {
		t.Fatalf("admin user: %d %v", id, err)
	}
	if _, err := e.st.CreateLocalUser(ctx, "test", "bob@example.com", "Bob", false, "$argon2id$x", secret); err != nil {
		t.Fatal(err)
	}
	e.st.CreateOrg(ctx, "test", "acme", "Acme")
	e.st.CreateOrg(ctx, "test", "globex", "Globex")
	return e
}

func (e *env) adminPost(action string, form url.Values) *httptest.ResponseRecorder {
	e.t.Helper()
	form.Set("csrf", auth.CSRFToken(goodToken))
	return e.post("/admin/users/"+action, form, signedIn(e), origin("http://127.0.0.1:8080"))
}

func TestAdminPageAccess(t *testing.T) {
	e := adminEnv(t)
	w := e.get("/admin/users", signedIn(e))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "bob@example.com") ||
		!strings.Contains(w.Body.String(), `href="/admin/users"`) {
		t.Fatalf("admin page: %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "\"secret\"") {
		t.Error("page leaks secrets")
	}

	// A non-admin gets the same answer as for a page that doesn't exist,
	// and no Users link.
	e.auth.viewer = &auth.Viewer{UserID: 2, Email: "bob@example.com", Scope: store.Scope{Orgs: map[int64]store.Role{1: store.RoleAdmin}}, SessionToken: goodToken}
	if w := e.get("/admin/users", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("non-admin GET: %d", w.Code)
	}
	if w := e.adminPost("grant", url.Values{"email": {"bob@example.com"}, "org": {"globex"}, "role": {"admin"}}); w.Code != http.StatusNotFound {
		t.Errorf("non-admin POST: %d", w.Code)
	}
	if strings.Contains(e.get("/", signedIn(e)).Body.String(), `href="/admin/users"`) {
		t.Error("Users nav shown to a non-admin")
	}
}

func TestAdminActionsNeedCSRF(t *testing.T) {
	e := adminEnv(t)
	form := url.Values{"email": {"bob@example.com"}, "org": {"acme"}, "role": {"viewer"}}
	if w := e.post("/admin/users/grant", form, signedIn(e), origin("http://127.0.0.1:8080")); w.Code != http.StatusForbidden {
		t.Errorf("no CSRF: %d", w.Code)
	}
	form.Set("csrf", auth.CSRFToken(goodToken))
	if w := e.post("/admin/users/grant", form, signedIn(e), origin("https://evil.example.com")); w.Code != http.StatusForbidden {
		t.Errorf("wrong origin: %d", w.Code)
	}
	if sc, _ := e.st.ScopeFor(t.Context(), 2); !sc.Empty() {
		t.Error("refused requests changed roles")
	}
}

func TestAdminGrantRevokeDisable(t *testing.T) {
	e := adminEnv(t)
	ctx := t.Context()
	w := e.adminPost("grant", url.Values{"email": {"bob@example.com"}, "org": {"acme"}, "role": {"operator"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/users?ok=granted" {
		t.Fatalf("grant: %d %s", w.Code, w.Body.String())
	}
	if sc, _ := e.st.ScopeFor(ctx, 2); sc.Role(1) != store.RoleOperator {
		t.Errorf("scope after grant: %+v", sc)
	}
	if body := e.get("/admin/users?ok=granted", signedIn(e)).Body.String(); !strings.Contains(body, "Role granted.") ||
		!strings.Contains(body, "acme: operator") {
		t.Error("grant not shown")
	}
	// Notices come from a fixed set; arbitrary text isn't reflected.
	if body := e.get("/admin/users?ok=<b>pwned</b>", signedIn(e)).Body.String(); strings.Contains(body, "pwned") {
		t.Error("notice reflected from the query string")
	}

	if w := e.adminPost("grant", url.Values{"email": {"bob@example.com"}, "org": {"acme"}, "role": {"root"}}); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "must be viewer, operator or admin") {
		t.Errorf("bad role: %d", w.Code)
	}
	if w := e.adminPost("grant", url.Values{"email": {"nobody@example.com"}, "org": {"acme"}, "role": {"viewer"}}); w.Code != http.StatusBadRequest {
		t.Errorf("unknown user: %d", w.Code)
	}

	if w := e.adminPost("revoke", url.Values{"email": {"bob@example.com"}, "org": {"acme"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d", w.Code)
	}
	if sc, _ := e.st.ScopeFor(ctx, 2); !sc.Empty() {
		t.Errorf("scope after revoke: %+v", sc)
	}

	if w := e.adminPost("disable", url.Values{"email": {"bob@example.com"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("disable: %d", w.Code)
	}
	if u, _ := e.st.UserByID(ctx, 2); !u.Disabled {
		t.Error("bob not disabled")
	}
	if w := e.adminPost("enable", url.Values{"email": {"bob@example.com"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("enable: %d", w.Code)
	}
	if u, _ := e.st.UserByID(ctx, 2); u.Disabled {
		t.Error("bob still disabled")
	}

	for _, self := range []string{"Admin@Example.com", "#1"} {
		w = e.adminPost("disable", url.Values{"email": {self}})
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "can&#39;t disable the account you&#39;re signed in with") {
			t.Errorf("self-disable %s: %d", self, w.Code)
		}
	}
	if u, _ := e.st.UserByID(ctx, 1); u.Disabled {
		t.Error("admin disabled themselves")
	}
	if w := e.adminPost("delete-everything", url.Values{}); w.Code != http.StatusNotFound {
		t.Errorf("unknown action: %d", w.Code)
	}
}

func TestAdminAddEntraUser(t *testing.T) {
	e := adminEnv(t)
	w := e.adminPost("entra", url.Values{"tenant": {testTenant}, "email": {"Carol@Example.com"}, "name": {"Carol"}, "admin": {"on"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("add: %d %s", w.Code, w.Body.String())
	}
	users, _ := e.st.ListUsers(t.Context())
	found := false
	for _, u := range users {
		if u.Kind == "entra" && u.Email == "carol@example.com" && u.IsAdmin && u.DisplayName == "Carol" {
			found = true
		}
	}
	if !found {
		t.Errorf("entra user not created: %+v", users)
	}
	if w := e.adminPost("entra", url.Values{"tenant": {"22222222-2222-2222-2222-222222222222"}, "email": {"dave@example.com"}}); w.Code != http.StatusBadRequest {
		t.Errorf("unconfigured tenant: %d", w.Code)
	}
	if w := e.adminPost("entra", url.Values{"tenant": {testTenant}, "email": {"Carol@Example.com"}}); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "already exists") {
		t.Errorf("duplicate: %d", w.Code)
	}
}

// seedOrg adds an org with one reporting host.
func (e *env) seedOrg(org, host string) {
	e.t.Helper()
	ctx := e.t.Context()
	e.st.CreateOrg(ctx, "test", org, "")
	e.st.CreateEnv(ctx, "test", org, "prod", "")
	if _, _, err := e.st.AddHost(ctx, "test", org, "prod", host, nil); err != nil {
		e.t.Fatal(err)
	}
	h, _ := e.st.HostByName(ctx, org, host)
	raw, _ := os.ReadFile("../snapshot/testdata/debian12-v2.json")
	var snap map[string]any
	json.Unmarshal(raw, &snap)
	snap["collected_at"] = testNow.Format(time.RFC3339)
	raw, _ = json.Marshal(snap)
	acc := ingest.Accepter{Store: e.st, Now: func() time.Time { return testNow }}
	if res, err := acc.Accept(ctx, h, "push", raw); err != nil || res.Status != http.StatusCreated {
		e.t.Fatalf("snapshot: %+v %v", res, err)
	}
}

func TestScopeLimitsWhatViewersSee(t *testing.T) {
	var gotScope store.Scope
	sf := func(_ context.Context, q string, sc store.Scope) (*search.Result, error) {
		gotScope = sc
		return &search.Result{}, nil
	}
	e := newEnv(t, "http://127.0.0.1:8080", sf)
	e.seedOrg("acme", "acme-web")
	e.seedOrg("globex", "globex-web")
	acme, _ := e.st.HostByName(t.Context(), "acme", "acme-web")
	scope := store.Scope{Orgs: map[int64]store.Role{acme.OrgID: store.RoleViewer}}
	e.auth.viewer = &auth.Viewer{UserID: 2, Email: "bob@example.com", Scope: scope, SessionToken: goodToken}

	for _, p := range []string{"/", "/hosts", "/sites"} {
		body := e.get(p, signedIn(e)).Body.String()
		if !strings.Contains(body, "acme-web") || strings.Contains(body, "globex-web") || strings.Contains(body, "Globex") {
			t.Errorf("%s: scope not applied", p)
		}
	}
	if w := e.get("/hosts/globex/globex-web", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("other org's host page: %d", w.Code)
	}
	if w := e.get("/hosts/acme/acme-web", signedIn(e)); w.Code != http.StatusOK {
		t.Errorf("own host page: %d", w.Code)
	}
	if w := e.get("/?org=globex", signedIn(e)); strings.Contains(w.Body.String(), "globex-web") {
		t.Error("org filter bypassed scope")
	}
	e.get("/search?q=openssl", signedIn(e))
	if gotScope.Admin || gotScope.Role(acme.OrgID) != store.RoleViewer || len(gotScope.Orgs) != 1 {
		t.Errorf("search got scope %+v", gotScope)
	}
}

func TestEmptyScopeMessage(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seedOrg("acme", "acme-web")
	e.auth.viewer = &auth.Viewer{UserID: 2, Email: "new@example.com", SessionToken: goodToken}
	for _, p := range []string{"/", "/hosts", "/sites", "/search?q=openssl"} {
		body := e.get(p, signedIn(e)).Body.String()
		if !strings.Contains(body, "access to any organization yet") || strings.Contains(body, "acme-web") {
			t.Errorf("%s: no empty-scope message", p)
		}
	}
}
