// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/snapshot"
)

// saveTestSnapshot stores a minimal snapshot with one package, optionally
// with a pending security update.
func saveTestSnapshot(t *testing.T, s *Store, host IngestHost, at time.Time, pendingSecurity bool) {
	t.Helper()
	yes := true
	snap := &snapshot.Snapshot{
		Format: snapshot.FormatV1, CollectedAt: at, PackageManager: "dpkg",
		Collector: snapshot.Collector{Version: "0.2.0"},
		OS:        snapshot.OS{ID: "debian", VersionID: "12"},
		Kernel:    snapshot.Kernel{Release: "6.1.0", Arch: "x86_64"},
		Packages:  []snapshot.Package{{Name: "openssl", Version: "3.0.11-1", Arch: "amd64"}},
	}
	if pendingSecurity {
		snap.Updates = []snapshot.Update{{Name: "openssl", Arch: "amd64", Version: "3.0.13-1", Security: &yes}}
	}
	if _, err := s.SaveSnapshot(t.Context(), NewSnapshot{
		Host: host, Source: "push", ReceivedAt: at, Snapshot: snap,
		PayloadSHA256: sha256.Sum256([]byte(fmt.Sprint(at.UnixNano(), pendingSecurity))),
	}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPlanLifecycle(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	setupHost(t, s) // acme/prod/web-01.example.com
	s.CreateOrg(ctx, "test", "other", "")
	s.CreateEnv(ctx, "test", "other", "prod", "")
	s.AddHost(ctx, "test", "other", "prod", "db-9", nil)
	host, _ := s.HostByName(ctx, "acme", "web-01.example.com")
	foreign, _ := s.HostByName(ctx, "other", "db-9")
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

	p, err := s.CreatePlan(ctx, "test", 0, "acme", "October patching")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddToPlan(ctx, "test", p.ID, host, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.AddToPlan(ctx, "test", p.ID, foreign, 1); err == nil {
		t.Error("an acme plan must not accept another org's host")
	}

	// Ticked, but the next snapshot still has a pending security update.
	if err := s.SetPlanItemDone(ctx, "test", 0, p.ID, host, true, now); err != nil {
		t.Fatal(err)
	}
	saveTestSnapshot(t, s, host, now.Add(time.Hour), true)
	items, _ := s.PlanItems(ctx, p.ID)
	if len(items) != 1 || items[0].DoneAt.IsZero() || !items[0].VerifiedAt.IsZero() || items[0].PendingSecurity != 1 {
		t.Fatalf("after unclean snapshot: %+v", items)
	}

	// A clean snapshot verifies it.
	saveTestSnapshot(t, s, host, now.Add(2*time.Hour), false)
	items, _ = s.PlanItems(ctx, p.ID)
	if items[0].VerifiedAt.IsZero() {
		t.Fatalf("clean snapshot should verify: %+v", items[0])
	}
	if p, _ = s.PlanByID(ctx, p.ID); p.Hosts != 1 || p.Done != 1 || p.Verified != 1 {
		t.Errorf("summary: %+v", p)
	}

	// Unticking clears verification; closing blocks further edits.
	s.SetPlanItemDone(ctx, "test", 0, p.ID, host, false, now)
	if items, _ = s.PlanItems(ctx, p.ID); !items[0].VerifiedAt.IsZero() || !items[0].DoneAt.IsZero() {
		t.Errorf("untick: %+v", items[0])
	}
	// Ticked after the fix landed: the next report verifies it even though
	// it's unchanged (stored as a heartbeat).
	s.SetPlanItemDone(ctx, "test", 0, p.ID, host, true, now.Add(3*time.Hour))
	saveTestSnapshot(t, s, host, now.Add(4*time.Hour), false)
	if n, _ := s.CountRows(ctx, "heartbeats"); n != 1 {
		t.Fatalf("heartbeats = %d, want 1", n)
	}
	if items, _ = s.PlanItems(ctx, p.ID); items[0].VerifiedAt.IsZero() {
		t.Errorf("unchanged clean report should verify: %+v", items[0])
	}
	if err := s.ClosePlan(ctx, "test", p.ID, true, now); err != nil {
		t.Fatal(err)
	}
	if err := s.AddToPlan(ctx, "test", p.ID, host, 2); err == nil {
		t.Error("closed plan accepted a host")
	}
}

func TestPlanVisibility(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	s.CreateOrg(ctx, "test", "acme", "")
	s.CreateOrg(ctx, "test", "globex", "")
	acme, _ := orgIDBySlug(ctx, s.db, "acme")
	s.CreatePlan(ctx, "test", 0, "acme", "acme plan")
	s.CreatePlan(ctx, "test", 0, "globex", "globex plan")
	s.CreatePlan(ctx, "test", 0, "", "fleet-wide plan")

	viewer := Scope{Orgs: map[int64]Role{acme: RoleViewer}}
	plans, err := s.ListPlans(ctx, viewer)
	if err != nil || len(plans) != 1 || plans[0].Name != "acme plan" {
		t.Fatalf("viewer sees %+v %v", plans, err)
	}
	if viewer.CanOperatePlan(plans[0]) {
		t.Error("viewer must not operate")
	}
	if all, _ := s.ListPlans(ctx, AllScope); len(all) != 3 {
		t.Errorf("admin sees %d plans", len(all))
	}
}

func TestPruneSnapshots(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	setupHost(t, s)
	host, _ := s.HostByName(ctx, "acme", "web-01.example.com")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 6 {
		saveTestSnapshot(t, s, host, base.Add(time.Duration(i)*24*time.Hour), i%2 == 0)
	}
	// Keep 2 per host; everything older than day 5 may go.
	n, err := s.PruneSnapshots(ctx, base.Add(5*24*time.Hour), 2)
	if err != nil || n != 4 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	snaps, _ := s.Snapshots(ctx, host.ID, 10)
	if len(snaps) != 2 || !snaps[0].ReceivedAt.Equal(base.Add(5*24*time.Hour)) {
		t.Errorf("left %+v", snaps)
	}
	if _, err := s.LatestSnapshot(ctx, host.ID); err != nil {
		t.Errorf("latest snapshot must survive: %v", err)
	}
}

func TestPruneKeepsRecentlyReportedSnapshots(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	setupHost(t, s)
	host, _ := s.HostByName(ctx, "acme", "web-01.example.com")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	day := func(n int) time.Time { return base.Add(time.Duration(n) * 24 * time.Hour) }
	for i := range 10 { // one snapshot, then nine unchanged reports
		saveTestSnapshot(t, s, host, day(i), false)
	}
	saveTestSnapshot(t, s, host, day(10), true) // a real change
	if n, _ := s.CountRows(ctx, "snapshots"); n != 2 {
		t.Fatalf("snapshots = %d, want 2", n)
	}
	// The first snapshot is old, but was still reported on days 8 and 9.
	n, err := s.PruneSnapshots(ctx, day(8), 1)
	if err != nil || n != 0 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	if hb, _ := s.CountRows(ctx, "heartbeats"); hb != 2 {
		t.Errorf("heartbeats left = %d, want 2", hb)
	}
	if n, _ := s.PruneSnapshots(ctx, day(11), 1); n != 1 {
		t.Errorf("then pruned %d, want 1", n)
	}
	if hb, _ := s.CountRows(ctx, "heartbeats"); hb != 0 {
		t.Errorf("heartbeats left = %d, want 0", hb)
	}
}
