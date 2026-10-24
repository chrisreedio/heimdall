// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"fmt"
	"testing"
	"time"
)

// Every rule in AnomalyRules is accepted by the anomalies CHECK, and the
// rebuilt table keeps its index.
func TestAnomalyRulesMatchSchema(t *testing.T) {
	s := newStore(t)
	h, _ := setupHost(t, s)
	for _, rule := range AnomalyRules {
		if err := s.RecordAnomaly(t.Context(), h.ID, time.Now(), Anomaly{Rule: rule, Severity: "low", Summary: "x"}); err != nil {
			t.Errorf("rule %s: %v", rule, err)
		}
	}
	var n int
	if err := s.db.QueryRowContext(t.Context(),
		`SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'anomalies_open' AND tbl_name = 'anomalies'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("anomalies_open index: %d %v", n, err)
	}
}

func TestInventoryMatch(t *testing.T) {
	s := newStore(t)
	h, _ := setupHost(t, s)
	ctx := t.Context()
	// inv inserts a snapshot with an inventory hash byte (0: NULL, as before 0007).
	seq := 0
	inv := func(b byte) int64 {
		t.Helper()
		seq++
		var hash any
		if b != 0 {
			hash = fmt.Appendf(nil, "%032d", b)[:32]
		}
		var id int64
		if err := s.db.QueryRowContext(ctx, `
			INSERT INTO snapshots (host_id, source, received_at, collected_at, collector_version, payload_sha256, inventory_sha256)
			VALUES (?, 'push', ?, ?, '0.4.13', ?, ?) RETURNING id`, h.ID,
			fmt.Sprintf("2026-10-%02dT12:00:00.000Z", seq), fmt.Sprintf("2026-10-%02dT12:00:00.000Z", seq),
			fmt.Appendf(nil, "%032d", seq)[:32], hash).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	old0, a1 := inv(0), inv(1)
	b := inv(2)
	a2 := inv(1)
	null := inv(0)

	if id, at, ok, err := s.InventoryMatch(ctx, h.ID, a2, b); err != nil || !ok || id != a1 || at.Day() != 2 {
		t.Errorf("revert: %d %v %v %v", id, at, ok, err)
	}
	if _, _, ok, _ := s.InventoryMatch(ctx, h.ID, a2, b, a1); ok {
		t.Error("excluded snapshot matched")
	}
	if _, _, ok, _ := s.InventoryMatch(ctx, h.ID, b, a1); ok {
		t.Error("new inventory matched")
	}
	if _, _, ok, _ := s.InventoryMatch(ctx, h.ID, null, a2); ok {
		t.Errorf("snapshot without an inventory hash matched %d", old0)
	}
}
