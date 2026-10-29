// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"testing"
	"time"
)

func TestAckAnomalies(t *testing.T) {
	s := newStore(t)
	h, _ := setupHost(t, s)
	ctx := t.Context()
	at := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	for _, k := range []string{"a", "b", "c"} {
		if _, err := s.AddAnomaly(ctx, h.ID, 0, Anomaly{Rule: "package_change", Severity: "medium", Summary: k,
			Detail: map[string]any{"key": k}}, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AckAnomaly(ctx, "test", 0, 1, "seen", at); err != nil {
		t.Fatal(err)
	}
	ts, err := s.AnomalyTargets(ctx, []int64{3, 1, 99})
	if err != nil || len(ts) != 2 || ts[0].ID != 1 || ts[0].Open || !ts[1].Open || ts[1].Rule != "package_change" || ts[1].Host.Name != "web-01.example.com" {
		t.Fatalf("targets = %+v, %v", ts, err)
	}
	if _, err := s.AckAnomalies(ctx, "test", 0, []int64{2, 3}, " ", at); err == nil {
		t.Error("empty note accepted")
	}
	n, err := s.AckAnomalies(ctx, "test", 0, []int64{1, 2, 3, 99}, "deploy", at)
	if err != nil || n != 2 {
		t.Fatalf("acked %d, %v; want 2", n, err)
	}
	var audits int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE action = 'anomaly.ack'`).Scan(&audits); err != nil || audits != 3 {
		t.Errorf("audit entries = %d, %v; want 3 (one each)", audits, err)
	}
	if open, _ := s.OpenAnomalies(ctx, AllScope); len(open) != 0 {
		t.Errorf("still open: %+v", open)
	}
}
