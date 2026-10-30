// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

func TestPlansFlow(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seed()
	// The fake viewer is user 1; plans record who created and ticked them.
	if _, err := e.st.CreateLocalUser(t.Context(), "test", "admin@example.com", "", true, "$argon2id$x", []byte("secretsecretsecret12")); err != nil {
		t.Fatal(err)
	}
	form := func(kv ...string) url.Values {
		v := url.Values{"csrf": {auth.CSRFToken(goodToken)}}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	w := e.post("/plans", form("name", "October", "org", "acme"), signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/plans/1" {
		t.Fatalf("create: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := e.post("/plans/1/add", form("hostref", "acme/web-01", "batch", "2"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("add: %d %s", w.Code, w.Body.String())
	}
	if w := e.post("/plans/1/done", form("org", "acme", "host", "web-01"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("done: %d", w.Code)
	}
	body := e.get("/plans/1", signedIn(e)).Body.String()
	if !strings.Contains(body, "web-01") || !strings.Contains(body, "waiting for a clean check-in") {
		t.Errorf("plan page:\n%s", body)
	}
	if !strings.Contains(e.get("/plans", signedIn(e)).Body.String(), "October") {
		t.Error("plans list missing the plan")
	}
	// CSRF is required like every other POST.
	if w := e.post("/plans/1/undo", url.Values{"org": {"acme"}, "host": {"web-01"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusForbidden {
		t.Errorf("no csrf: %d", w.Code)
	}
}

func TestPlansRespectScope(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seed()
	// The fake viewer is user 1; plans record who created and ticked them.
	if _, err := e.st.CreateLocalUser(t.Context(), "test", "admin@example.com", "", true, "$argon2id$x", []byte("secretsecretsecret12")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CreatePlan(t.Context(), "test", 0, "acme", "acme plan"); err != nil {
		t.Fatal(err)
	}
	orgs, _ := e.st.ListOrgs(t.Context())
	// A viewer can see the plan but not change it.
	e.auth.viewer = &auth.Viewer{UserID: 1, Email: "v@example.com", SessionToken: goodToken,
		Scope: store.Scope{Orgs: map[int64]store.Role{orgs[0].ID: store.RoleViewer}}}
	if w := e.get("/plans/1", signedIn(e)); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "mark done") {
		t.Errorf("viewer page: %d", w.Code)
	}
	f := url.Values{"csrf": {auth.CSRFToken(goodToken)}, "hostref": {"acme/web-01"}}
	if w := e.post("/plans/1/add", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusForbidden {
		t.Errorf("viewer add: %d", w.Code)
	}
	// Someone without access to acme doesn't learn the plan exists.
	e.auth.viewer.Scope = store.Scope{Orgs: map[int64]store.Role{}}
	if w := e.get("/plans/1", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("no access: %d", w.Code)
	}
}
