// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"
)

func TestSignIns(t *testing.T) {
	t.Parallel()
	s, ctx := newStore(t), t.Context()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	acme, _ := s.CreateOrg(ctx, "test", "acme", "")
	beta, _ := s.CreateOrg(ctx, "test", "beta", "")
	alice, err := s.CreateLocalUser(ctx, "test", "alice@example.com", "Alice", false, "x", []byte("0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	bob, _ := s.CreateLocalUser(ctx, "test", "bob@example.com", "", false, "x", []byte("0123456789"))
	if err := s.Grant(ctx, "test", "alice@example.com", "acme", RoleViewer); err != nil {
		t.Fatal(err)
	}
	const ip = "203.0.113.7"
	// Alice: an open session from 2h to 1h ago, audited when it began.
	if err := s.CreateSession(ctx, sha256.Sum256([]byte("a")), alice, now.Add(-2*time.Hour), now.Add(time.Hour), ip, "ua"); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchSession(ctx, sha256.Sum256([]byte("a")), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	signIn := func(user int64, at time.Time, action, ip string) {
		t.Helper()
		if _, err := s.db.ExecContext(ctx, `INSERT INTO audit_log (at, actor, action, target, ip) VALUES (?, ?, ?, '', ?)`,
			at.Format(timeLayout), fmt.Sprintf("user:%d", user), action, ip); err != nil {
			t.Fatal(err)
		}
	}
	signIn(alice, now.Add(-2*time.Hour+time.Second), "login.success", ip) // the session's own audit entry
	signIn(bob, now.Add(-30*24*time.Hour), "login.success", ip)           // long ago, from the audit log only
	signIn(bob, now, "login.failure", ip)                                 // not a sign-in
	signIn(bob, now, "login.success", "198.51.100.1")                     // elsewhere

	all, err := s.SignInsFrom(ctx, ip, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].UserID != alice || !all[0].Open || all[0].Who() != "Alice" ||
		all[1].Who() != "bob@example.com" || all[1].Open {
		t.Fatalf("sign-ins = %+v", all)
	}
	near, err := s.SignInsNear(ctx, ip, now.Add(-30*time.Minute), 12*time.Hour, 0)
	if err != nil || len(near) != 1 || near[0].UserID != alice {
		t.Fatalf("near = %+v, %v", near, err)
	}
	if near, _ = s.SignInsNear(ctx, ip, now.Add(-30*time.Minute), 12*time.Hour, acme.ID); len(near) != 1 {
		t.Errorf("alice can see acme: %+v", near)
	}
	if near, _ = s.SignInsNear(ctx, ip, now.Add(-30*time.Minute), 12*time.Hour, beta.ID); len(near) != 0 {
		t.Errorf("alice can't see beta, so isn't matched there: %+v", near)
	}
	if near, _ = s.SignInsNear(ctx, ip, now.Add(-20*24*time.Hour), 12*time.Hour, 0); len(near) != 0 {
		t.Errorf("nothing near then: %+v", near)
	}
	if near, _ = s.SignInsNear(ctx, ip, now.Add(-30*24*time.Hour+6*time.Hour), 12*time.Hour, 0); len(near) != 1 || near[0].UserID != bob {
		t.Errorf("bob's old sign-in: %+v", near)
	}
	if err := s.SetSessionTailscale(ctx, sha256.Sum256([]byte("a")), "alice@example.com", ""); err != nil {
		t.Fatal(err)
	}
	if all, _ = s.SignInsFrom(ctx, ip, 1); len(all) != 1 || all[0].TailscaleUser != "alice@example.com" {
		t.Errorf("tailnet user = %+v", all)
	}
}

func TestIPPolicyAndWhereAddressesAppear(t *testing.T) {
	t.Parallel()
	s, ctx := newStore(t), t.Context()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	acme, _ := s.CreateOrg(ctx, "test", "acme", "")
	beta, _ := s.CreateOrg(ctx, "test", "beta", "")
	p, err := s.IPPolicy(ctx, acme.ID)
	if err != nil || p.TailnetOnly || !p.AllowServices || p.CountServices {
		t.Fatalf("default policy = %+v, %v", p, err)
	}
	if err := s.SetIPPolicy(ctx, "cli:test", IPPolicy{OrgID: acme.ID, TailnetOnly: true, CountServices: true}, now); err != nil {
		t.Fatal(err)
	}
	if p, _ = s.IPPolicy(ctx, acme.ID); !p.TailnetOnly || p.AllowServices || !p.CountServices || p.UpdatedBy != "cli:test" || !p.UpdatedAt.Equal(now) {
		t.Errorf("policy = %+v", p)
	}
	if p, _ = s.IPPolicy(ctx, beta.ID); p.TailnetOnly {
		t.Error("one org's policy leaked into another")
	}
	if at, _ := s.LastAuditAt(ctx, "ip_policy.set"); at.IsZero() {
		t.Error("policy change not audited")
	}

	for _, o := range []string{"acme", "beta"} {
		s.CreateEnv(ctx, "test", o, "prod", "")
		if _, _, err := s.AddHost(ctx, "test", o, "prod", "web-01", nil); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := s.HostByName(ctx, "acme", "web-01")
	b, _ := s.HostByName(ctx, "beta", "web-01")
	at := now.Add(-time.Hour).Truncate(time.Second)
	for _, h := range []IngestHost{a, b} {
		if _, _, err := s.RecordPrivilege(ctx, h.ID, []PrivilegeEvent{{At: at, Kind: "sudo", User: "chris", Source: "203.0.113.7"},
			{At: at.Add(time.Second), Kind: "root-ssh", User: "root", Source: "203.0.113.7"},
			{At: at, Kind: "su", User: "chris", Source: "?"}, {At: at.Add(-48 * time.Hour), Kind: "sudo", User: "old", Source: "203.0.113.7"}}, "on", "", now); err != nil {
			t.Fatal(err)
		}
	}
	acmeOnly := Scope{Orgs: map[int64]Role{acme.ID: RoleViewer}}
	evs, err := s.PrivilegeFrom(ctx, acmeOnly, "203.0.113.7", 10)
	if err != nil || len(evs) != 3 || evs[0].Host.OrgSlug != "acme" || evs[0].Kind != "root-ssh" {
		t.Fatalf("events = %+v, %v", evs, err)
	}
	srcs, err := s.PrivilegeSourcesSince(ctx, AllScope, 0, now.Add(-24*time.Hour))
	if err != nil || len(srcs) != 2 || srcs[0].Count != 2 || srcs[0].Kinds["root-ssh"] != 1 || len(srcs[0].Users) != 2 ||
		!srcs[0].Last.Equal(at.Add(time.Second)) {
		t.Fatalf("sources = %+v, %v", srcs, err)
	}
	if srcs, _ = s.PrivilegeSourcesSince(ctx, acmeOnly, b.ID, now.Add(-24*time.Hour)); len(srcs) != 0 {
		t.Errorf("another org's host: %+v", srcs)
	}

	for _, e := range []AuditEntry{{Actor: "user:1", Action: "host.rename", OrgID: acme.ID, IP: "203.0.113.7"},
		{Actor: "user:1", Action: "host.rename", OrgID: beta.ID, IP: "203.0.113.7"}, {Actor: "user:1", Action: "login.success", IP: "203.0.113.7"}} {
		if err := s.Audit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if rows, _ := s.AuditFrom(ctx, "203.0.113.7", true, nil, 10); len(rows) != 3 {
		t.Errorf("all audit rows = %+v", rows)
	}
	if rows, _ := s.AuditFrom(ctx, "203.0.113.7", false, []int64{acme.ID}, 10); len(rows) != 1 || rows[0].OrgID != acme.ID {
		t.Errorf("acme audit rows = %+v", rows)
	}
	labels, err := s.AllIPLabels(ctx)
	if err != nil || len(labels) != 0 {
		t.Errorf("labels = %v, %v", labels, err)
	}
}
