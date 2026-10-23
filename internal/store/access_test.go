// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"testing"
	"time"
)

const (
	tenantA  = "11111111-1111-1111-1111-111111111111"
	tenantB  = "22222222-2222-2222-2222-222222222222"
	oidAlice = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
)

func TestScopesAndGrants(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	s.CreateOrg(ctx, "test", "acme", "")
	s.CreateOrg(ctx, "test", "globex", "")
	uid, err := s.CreateLocalUser(ctx, "test", "bob@example.com", "", false, "$argon2id$x", []byte("secretsecretsecret12"))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := s.ScopeFor(ctx, uid)
	if err != nil || !sc.Empty() {
		t.Fatalf("new user should have no access: %+v %v", sc, err)
	}

	if err := s.Grant(ctx, "test", "bob@example.com", "acme", RoleOperator); err != nil {
		t.Fatal(err)
	}
	acme, _ := orgIDBySlug(ctx, s.db, "acme")
	globex, _ := orgIDBySlug(ctx, s.db, "globex")
	sc, _ = s.ScopeFor(ctx, uid)
	if !sc.CanView(acme) || !sc.CanOperate(acme) || sc.CanAdmin(acme) {
		t.Errorf("acme operator: %+v", sc)
	}
	if sc.CanView(globex) {
		t.Error("must not see globex")
	}

	if err := s.Revoke(ctx, "test", "bob@example.com", "acme"); err != nil {
		t.Fatal(err)
	}
	if sc, _ = s.ScopeFor(ctx, uid); !sc.Empty() {
		t.Error("revoke left access")
	}
	if err := s.Revoke(ctx, "test", "bob@example.com", "acme"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second revoke: %v", err)
	}
	if _, err := ParseRole("root"); err == nil {
		t.Error("bad role accepted")
	}
	if !AllScope.CanAdmin(12345) {
		t.Error("AllScope must allow everything")
	}
}

func TestEntraProvisioningAndBinding(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	// Provisioned by email: the first login binds the oid.
	if _, err := s.CreateEntraUser(ctx, "test", tenantA, "", "Alice@Example.com", "", false); err != nil {
		t.Fatal(err)
	}
	u, err := s.ResolveEntraUser(ctx, EntraIdentity{TenantID: tenantA, ObjectID: oidAlice, Email: "alice@example.com", Name: "Alice"})
	if err != nil || u.Kind != "entra" || u.DisplayName != "Alice" {
		t.Fatalf("first login: %+v %v", u, err)
	}
	// From then on the oid identifies her, even if her email changes.
	u2, err := s.ResolveEntraUser(ctx, EntraIdentity{TenantID: tenantA, ObjectID: oidAlice, Email: "alice.new@example.com"})
	if err != nil || u2.ID != u.ID {
		t.Fatalf("oid lookup: %+v %v", u2, err)
	}
	// Someone else claiming her old email in the same tenant isn't her.
	if _, err := s.ResolveEntraUser(ctx, EntraIdentity{TenantID: tenantA, ObjectID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Email: "alice@example.com"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("email reuse after binding: %v", err)
	}
	// Same email in another tenant isn't her either.
	if _, err := s.ResolveEntraUser(ctx, EntraIdentity{TenantID: tenantB, ObjectID: oidAlice, Email: "alice@example.com"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("other tenant: %v", err)
	}
	// Not provisioned at all.
	if _, err := s.ResolveEntraUser(ctx, EntraIdentity{TenantID: tenantA, ObjectID: "cccccccc-cccc-cccc-cccc-cccccccccccc", Email: "eve@example.com"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unprovisioned: %v", err)
	}
	if _, err := s.CreateEntraUser(ctx, "test", "not-a-guid", "", "x@example.com", "", false); err == nil {
		t.Error("bad tenant accepted")
	}
}

func TestSyncAppRoles(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	s.CreateOrg(ctx, "test", "acme", "")
	s.CreateOrg(ctx, "test", "globex", "")
	acme, _ := orgIDBySlug(ctx, s.db, "acme")
	globex, _ := orgIDBySlug(ctx, s.db, "globex")
	uid, _ := s.CreateEntraUser(ctx, "test", tenantA, oidAlice, "alice@example.com", "", false)

	if err := s.SyncAppRoles(ctx, uid, []string{"Heimdall.Viewer", "Heimdall.Org.acme.Operator", "Something.Else"}); err != nil {
		t.Fatal(err)
	}
	sc, _ := s.ScopeFor(ctx, uid)
	if sc.Role(acme) != RoleOperator || sc.Role(globex) != RoleViewer || sc.Admin {
		t.Errorf("after sync: %+v", sc)
	}

	// A manual grant survives syncs; app-role grants follow the token.
	if err := s.Grant(ctx, "test", "alice@example.com", "globex", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncAppRoles(ctx, uid, []string{"Heimdall.Admin"}); err != nil {
		t.Fatal(err)
	}
	sc, _ = s.ScopeFor(ctx, uid)
	if !sc.Admin || sc.Orgs[acme] != "" || sc.Orgs[globex] != RoleAdmin {
		t.Errorf("after second sync: %+v", sc)
	}
	if err := s.SyncAppRoles(ctx, uid, nil); err != nil {
		t.Fatal(err)
	}
	if sc, _ = s.ScopeFor(ctx, uid); sc.Admin {
		t.Error("admin must follow the roles claim")
	}
}

func TestAuthRequestsAreSingleUse(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	var state [32]byte
	state[0] = 1
	if err := s.PutAuthRequest(ctx, state, AuthRequest{Nonce: "n", Verifier: "v", ReturnTo: "/hosts", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	r, err := s.TakeAuthRequest(ctx, state, now.Add(time.Minute), 10*time.Minute)
	if err != nil || r.Nonce != "n" || r.Verifier != "v" || r.ReturnTo != "/hosts" {
		t.Fatalf("take: %+v %v", r, err)
	}
	if _, err := s.TakeAuthRequest(ctx, state, now.Add(time.Minute), 10*time.Minute); !errors.Is(err, ErrNotFound) {
		t.Errorf("second take: %v", err)
	}
	state[0] = 2
	s.PutAuthRequest(ctx, state, AuthRequest{Nonce: "n", Verifier: "v", CreatedAt: now})
	if _, err := s.TakeAuthRequest(ctx, state, now.Add(11*time.Minute), 10*time.Minute); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired take: %v", err)
	}
}
