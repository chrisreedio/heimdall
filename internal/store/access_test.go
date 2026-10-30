// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	tenantA  = "11111111-1111-1111-1111-111111111111"
	tenantB  = "22222222-2222-2222-2222-222222222222"
	oidAlice = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
)

func TestScopesAndGrants(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestUserRefDisambiguates(t *testing.T) {
	t.Parallel()
	s, ctx := newStore(t), t.Context()
	if _, err := s.CreateOrg(ctx, "test", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	local, err := s.CreateLocalUser(ctx, "test", "chris@example.com", "", true, "x-hash", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	entra, err := s.CreateEntraUser(ctx, "test", tenantA, "", "chris@example.com", "Chris", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Grant(ctx, "test", "chris@example.com", "acme", RoleViewer); err == nil || !strings.Contains(err.Error(), "#") {
		t.Fatalf("ambiguous email should ask for an ID: %v", err)
	}
	if err := s.Grant(ctx, "test", UserRef(entra), "acme", RoleOperator); err != nil {
		t.Fatal(err)
	}
	if ms, _ := s.Memberships(ctx, entra); len(ms) != 1 || ms[0].Role != RoleOperator {
		t.Errorf("entra memberships = %+v", ms)
	}
	if ms, _ := s.Memberships(ctx, local); len(ms) != 0 {
		t.Errorf("local account got the role: %+v", ms)
	}
	if err := s.SetUserDisabled(ctx, "test", UserRef(local), true); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, "test", "#999", "acme"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id: %v", err)
	}
}

func TestEntraDuplicatesRefused(t *testing.T) {
	t.Parallel()
	s, ctx := newStore(t), t.Context()
	bound, err := s.CreateEntraUser(ctx, "test", tenantA, oidAlice, "alice@example.com", "", false)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := s.CreateEntraUser(ctx, "test", tenantA, "", "bob@example.com", "", false)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		oid, email, want string
	}{
		"email of a bound user":   {"", "Alice@Example.com", UserRef(bound) + ", active"},
		"email of a pending user": {"", "bob@example.com", UserRef(pending) + ", pending first sign-in"},
		"same object ID":          {oidAlice, "alice.new@example.com", "that object ID already exists (" + UserRef(bound)},
		"pending email, new oid":  {"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "bob@example.com", UserRef(pending)},
	} {
		_, err := s.CreateEntraUser(ctx, "test", tenantA, c.oid, c.email, "", false)
		if !errors.Is(err, ErrExists) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Another tenant, or a local account, may share the email.
	if _, err := s.CreateEntraUser(ctx, "test", tenantB, "", "alice@example.com", "", false); err != nil {
		t.Errorf("other tenant: %v", err)
	}
	if _, err := s.CreateLocalUser(ctx, "test", "alice@example.com", "", false, "h", []byte("s")); err != nil {
		t.Errorf("local account: %v", err)
	}
	if users, _ := s.ListUsers(ctx); len(users) != 4 {
		t.Errorf("refused creates added rows: %d users", len(users))
	}
}

// The incident this guards against: a pending duplicate of a bound user
// could never bind (sign-in matches the bound row's oid first), so when
// the bound row was disabled the person was locked out.
func TestDisabledBoundUserNotShadowedByDuplicate(t *testing.T) {
	t.Parallel()
	s, ctx := newStore(t), t.Context()
	old, err := s.CreateEntraUser(ctx, "test", tenantA, "", "alice@example.com", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveEntraUser(ctx, EntraIdentity{TenantID: tenantA, ObjectID: oidAlice, Email: "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserDisabled(ctx, "test", UserRef(old), true); err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateEntraUser(ctx, "test", tenantA, "", "alice@example.com", "", true)
	if !errors.Is(err, ErrExists) || err.Error() != "an Entra user with that email already exists ("+UserRef(old)+", disabled): enable it or delete it first" {
		t.Fatalf("duplicate of a disabled bound user: %v", err)
	}
	// The fix the message points to works: enabling the old row lets her in.
	if err := s.SetUserDisabled(ctx, "test", UserRef(old), false); err != nil {
		t.Fatal(err)
	}
	if u, err := s.ResolveEntraUser(ctx, EntraIdentity{TenantID: tenantA, ObjectID: oidAlice, Email: "alice@example.com"}); err != nil || u.ID != old || u.Disabled {
		t.Errorf("after enabling: %+v %v", u, err)
	}
}

func TestDeleteUser(t *testing.T) {
	t.Parallel()
	s, ctx := newStore(t), t.Context()
	if _, err := s.CreateOrg(ctx, "test", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	both := SignInMethods{Local: true, Entra: true}
	admin, _ := s.CreateLocalUser(ctx, "test", "admin@example.com", "", true, "h", []byte("s"))
	bob, err := s.CreateEntraUser(ctx, "test", tenantA, oidAlice, "bob@example.com", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Grant(ctx, "test", "bob@example.com", "acme", RoleOperator); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.CreateSession(ctx, [32]byte{1}, bob, now, now.Add(time.Hour), "203.0.113.5", "ua"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateMCPToken(ctx, "test", bob, "laptop"); err != nil {
		t.Fatal(err)
	}
	plan, err := s.CreatePlan(ctx, "test", bob, "acme", "October patches")
	if err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteUser(ctx, "user:1", bob, both); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserByID(ctx, bob); !errors.Is(err, ErrNotFound) {
		t.Errorf("bob still there: %v", err)
	}
	// Foreign keys are on, so what hung off bob went with him.
	for _, table := range []string{"memberships", "sessions", "mcp_tokens"} {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE user_id = ?`, bob).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s: %d rows left (%v)", table, n, err)
		}
	}
	var createdBy *int64
	if err := s.db.QueryRowContext(ctx, `SELECT created_by FROM patch_plans WHERE id = ?`, plan.ID).Scan(&createdBy); err != nil || createdBy != nil {
		t.Errorf("plan kept, author cleared: %v %v", createdBy, err)
	}
	var actor, target, detail string
	if err := s.db.QueryRowContext(ctx, `SELECT actor, target, detail FROM audit_log WHERE action = 'user.delete'`).Scan(&actor, &target, &detail); err != nil ||
		actor != "user:1" || target != "bob@example.com" || !strings.Contains(detail, `"kind":"entra"`) || !strings.Contains(detail, `"admin":false`) ||
		!strings.Contains(detail, `"email":"bob@example.com"`) {
		t.Errorf("audit: %s %s %s %v", actor, target, detail, err)
	}
	var older int
	if s.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE target = 'bob@example.com' AND action != 'user.delete'`).Scan(&older); older == 0 {
		t.Error("bob's earlier audit entries went with him")
	}
	if err := s.DeleteUser(ctx, "test", bob, both); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
	// Bob had the highest ID; the next user doesn't inherit it (and with it
	// his audit entries and sign-in history).
	if next, err := s.CreateEntraUser(ctx, "test", tenantA, "", "dave@example.com", "", false); err != nil || next <= bob {
		t.Errorf("next user ID %d after deleting %d: %v", next, bob, err)
	}

	// Nobody deletes themselves.
	if err := s.DeleteUser(ctx, "user:1", admin, both); err == nil || !strings.Contains(err.Error(), "signed in with") {
		t.Errorf("self-delete: %v", err)
	}
	// Nor the last active admin, even from the CLI.
	if err := s.DeleteUser(ctx, "cli:root", admin, both); err == nil || !strings.Contains(err.Error(), "last active admin") {
		t.Errorf("last admin: %v", err)
	}
	// A disabled admin doesn't count as a way in.
	other, _ := s.CreateLocalUser(ctx, "test", "other@example.com", "", true, "h", []byte("s"))
	s.SetUserDisabled(ctx, "test", UserRef(other), true)
	if err := s.DeleteUser(ctx, "cli:root", admin, both); err == nil {
		t.Error("deleted the last active admin while the other is disabled")
	}
	if err := s.DeleteUser(ctx, "cli:root", other, both); err != nil {
		t.Errorf("disabled admin: %v", err)
	}

	// With local sign-in off, a local admin isn't a way in, so the Entra
	// admin is the last one, and the local admin can go.
	entraAdmin, err := s.CreateEntraUser(ctx, "test", tenantA, "", "carol@example.com", "", true)
	if err != nil {
		t.Fatal(err)
	}
	ssoOnly := SignInMethods{Entra: true}
	if err := s.DeleteUser(ctx, "cli:root", entraAdmin, ssoOnly); err == nil || !strings.Contains(err.Error(), "last active admin") {
		t.Errorf("last admin who can sign in: %v", err)
	}
	if err := s.DeleteUser(ctx, "cli:root", admin, ssoOnly); err != nil {
		t.Errorf("local admin with local sign-in off: %v", err)
	}
	if err := s.DeleteUser(ctx, "cli:root", entraAdmin, both); err == nil {
		t.Error("deleted the last admin of all")
	}
}
