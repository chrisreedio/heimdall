// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/secret"
)

func TestEnrollApprovalAndDedup(t *testing.T) {
	t.Parallel()
	s, ctx := newStore(t), t.Context()
	s.CreateOrg(ctx, "test", "acme", "")
	s.CreateEnv(ctx, "test", "acme", "prod", "")
	s.CreateOrg(ctx, "test", "other", "")
	s.CreateEnv(ctx, "test", "other", "prod", "")
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

	k, key, err := s.CreateEnrollKey(ctx, "test", "acme", "prod",
		NewEnrollKey{Label: "rollout", Tags: []string{"web"}, MaxUses: 3, TTL: time.Hour, Approval: true}, now)
	if err != nil || !k.Approval || !strings.HasPrefix(key, secret.EnrollPrefix) {
		t.Fatalf("create = %+v %q, %v", k, key, err)
	}
	hash := secret.Hash(key)
	m1, m2 := strings.Repeat("a1", 32), strings.Repeat("b2", 32)

	got, err := s.EnrollHost(ctx, hash, "WEB-01", m1, "192.0.2.10", now)
	if err != nil || !got.Awaiting || got.Host.Name != "web-01" || got.Host.AutoName {
		t.Fatalf("enroll = %+v, %v", got, err)
	}
	// A taken name gets a suffix; the same machine is refused.
	if g, err := s.EnrollHost(ctx, hash, "web-01", m2, "192.0.2.11", now); err != nil || g.Host.Name != "web-01-2" {
		t.Fatalf("second = %+v, %v", g, err)
	}
	var dup *AlreadyEnrolledError
	if _, err := s.EnrollHost(ctx, hash, "web-01", m1, "", now); !errors.As(err, &dup) || dup.Host != "web-01" {
		t.Fatalf("same machine: %v", err)
	}
	// Machine IDs are per org: another org's key enrolls the same server.
	_, key2, _ := s.CreateEnrollKey(ctx, "test", "other", "prod", NewEnrollKey{TTL: time.Hour}, now)
	if g, err := s.EnrollHost(ctx, secret.Hash(key2), "", m1, "", now); err != nil || g.Awaiting || !g.Host.AutoName {
		t.Fatalf("other org = %+v, %v", g, err)
	}

	waiting, err := s.AwaitingHosts(ctx, "acme")
	if err != nil || len(waiting) != 2 {
		t.Fatalf("awaiting = %+v, %v", waiting, err)
	}
	if w := waiting[0]; w.Name != "web-01" || w.KeyLabel != "rollout" || w.IP != "192.0.2.10" || len(w.Tags) != 1 || w.Tags[0] != "web" {
		t.Errorf("awaiting[0] = %+v", w)
	}
	if all, _ := s.AwaitingHosts(ctx, ""); len(all) != 2 {
		t.Errorf("all orgs: %d waiting", len(all))
	}

	if err := s.ApproveHost(ctx, "admin", "acme", "web-01"); err != nil {
		t.Fatal(err)
	}
	if err := s.RejectHost(ctx, "admin", "acme", "web-01"); !errors.Is(err, ErrNotFound) {
		t.Errorf("reject an approved host: %v", err)
	}
	if err := s.RejectHost(ctx, "admin", "acme", "web-01-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HostByName(ctx, "acme", "web-01-2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("rejected host still there: %v", err)
	}
	if w, _ := s.AwaitingHosts(ctx, "acme"); len(w) != 0 {
		t.Errorf("still waiting: %+v", w)
	}
	var approvals int
	s.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE action IN ('host.approve', 'host.reject')`).Scan(&approvals)
	if approvals != 2 {
		t.Errorf("%d approve/reject audit entries", approvals)
	}

	// Rejecting freed the machine, and a use was spent on each enrollment.
	if _, err := s.EnrollHost(ctx, hash, "web-02", m2, "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnrollHost(ctx, hash, "web-03", "", "", now); !errors.Is(err, ErrEnrollUsedUp) {
		t.Errorf("fourth use: %v", err)
	}
	if _, err := s.EnrollHost(ctx, secret.Hash(key2), "", "", "", now.Add(2*time.Hour)); !errors.Is(err, ErrEnrollExpired) {
		t.Errorf("expired: %v", err)
	}
	keys, _ := s.ListEnrollKeys(ctx, "acme")
	if len(keys) != 1 || keys[0].Uses != 3 || keys[0].Status(now) != "used up" || strings.Join(keys[0].Hosts, ",") != "web-01,web-02" {
		t.Errorf("keys = %+v", keys)
	}
}
