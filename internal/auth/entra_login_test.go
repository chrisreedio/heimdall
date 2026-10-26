// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"testing"

	"github.com/realmwatch/heimdall/internal/store"
)

const (
	testTenant = "11111111-1111-1111-1111-111111111111"
	testOID    = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
)

func TestLoginIdentity(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.st.CreateOrg(ctx, "test", "acme", "")
	id := store.EntraIdentity{TenantID: testTenant, ObjectID: testOID, Email: "alice@example.com", Name: "Alice"}

	if _, err := e.svc.LoginIdentity(ctx, id, nil, "203.0.113.5", "ua"); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("unprovisioned: %v", err)
	}
	if _, err := e.st.CreateEntraUser(ctx, "test", testTenant, "", "alice@example.com", "", false); err != nil {
		t.Fatal(err)
	}
	e.svc.SyncAppRoles = true
	tok, err := e.svc.LoginIdentity(ctx, id, []string{"Heimdall.Viewer"}, "203.0.113.5", "ua")
	if err != nil {
		t.Fatal(err)
	}
	v, err := e.svc.Session(ctx, tok)
	if err != nil || v.Kind != "entra" || v.Email != "alice@example.com" || v.DisplayName != "Alice" {
		t.Fatalf("session: %+v %v", v, err)
	}
	if v.Scope.Admin || len(v.Scope.Orgs) != 1 {
		t.Errorf("app role should grant viewer on acme only: %+v", v.Scope)
	}
}

// With local login disabled, passwords stop working and local sessions end,
// while Entra sessions keep working.
func TestDisableLocal(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	local, err := e.login(email, password, e.code())
	if err != nil {
		t.Fatal(err)
	}
	e.st.CreateEntraUser(ctx, "test", testTenant, testOID, "alice@example.com", "", false)
	sso, err := e.svc.LoginIdentity(ctx, store.EntraIdentity{TenantID: testTenant, ObjectID: testOID}, nil, "ip", "ua")
	if err != nil {
		t.Fatal(err)
	}

	e.svc.DisableLocal = true
	if _, err := e.svc.Session(ctx, local); !errors.Is(err, ErrNoSession) {
		t.Errorf("local session should end: %v", err)
	}
	e.now = e.now.Add(31e9) // next TOTP step
	if _, err := e.login(email, password, e.code()); !errors.Is(err, ErrInvalidLogin) {
		t.Errorf("password login should be refused: %v", err)
	}
	if _, err := e.svc.Session(ctx, sso); err != nil {
		t.Errorf("entra session should survive: %v", err)
	}
}
