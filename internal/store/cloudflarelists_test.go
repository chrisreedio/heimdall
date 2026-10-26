// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

// 0033 rebuilds ip_labels for the office kind: labels from before stay,
// with their IDs, and office is accepted after.
func TestMigrateOfficeKind(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "h.db")
	if err := Create(path); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL,
		applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))) STRICT`); err != nil {
		t.Fatal(err)
	}
	for _, m := range ms[:32] {
		if _, err := s.db.ExecContext(ctx, m.sql); err != nil {
			t.Fatalf("%s: %v", m.name, err)
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO schema_migrations (version, name) VALUES (?, ?)`, m.version, m.name); err != nil {
			t.Fatal(err)
		}
	}
	id, err := s.AddIPLabel(ctx, "test", IPLabel{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Kind: IPKindStaff, Name: "Office", Person: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO ip_labels (prefix, kind, name, source) VALUES ('198.51.100.0/24', 'office', 'x', 'manual')`); err == nil {
		t.Fatal("office accepted before 0033")
	}
	if applied, err := s.Migrate(ctx); err != nil || len(applied) != len(ms)-32 {
		t.Fatalf("migrate: %v %v", applied, err)
	}
	ls, err := s.IPLabels(ctx, 0)
	if err != nil || len(ls) != 1 || ls[0].ID != id || ls[0].Person != "alice" || ls[0].Kind != IPKindStaff {
		t.Fatalf("labels after 0033: %+v %v", ls, err)
	}
	if _, err := s.AddIPLabel(ctx, "test", IPLabel{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Kind: IPKindOffice, Name: "VPN exit"}); err != nil {
		t.Fatalf("office after 0033: %v", err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'ip_labels_org' AND tbl_name = 'ip_labels'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("ip_labels_org index: %d %v", n, err)
	}
}

func TestCloudflareIPLists(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	const acct, other = "a1", "a2"
	found := []CloudflareIPList{
		{ID: "l-offices", AccountID: acct, Name: "offices", Items: 2},
		{ID: "l-bans", AccountID: acct, Name: "heimdall_ban", Items: 40},
		{ID: "l-elsewhere", AccountID: other, Name: "partners", Items: 1},
	}
	got, err := s.ReplaceCloudflareIPLists(ctx, []string{acct, other}, found, now)
	if err != nil || len(got) != 3 || got[0].Name != "heimdall_ban" || got[1].Kind != CFListIgnore || !got[1].SeenAt.Equal(now) {
		t.Fatalf("first sync: %+v %v", got, err)
	}

	// Mapping: only known kinds, only known lists; audited.
	if err := s.SetCloudflareIPListKind(ctx, "user:1", "l-offices", "tailnet", now); err == nil {
		t.Error("tailnet accepted as a list kind")
	}
	if err := s.SetCloudflareIPListKind(ctx, "user:1", "l-nope", IPKindOffice, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown list: %v", err)
	}
	if err := s.SetCloudflareIPListKind(ctx, "user:1", "l-offices", IPKindOffice, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCloudflareIPListKind(ctx, "user:1", "l-elsewhere", IPKindStaff, now); err != nil {
		t.Fatal(err)
	}
	var audits int
	s.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE action = 'cloudflare.ip_list.map'`).Scan(&audits)
	if audits != 2 {
		t.Errorf("audit entries: %d", audits)
	}

	// A sync stores the list's labels; a manual label beside them is never touched.
	office := netip.MustParsePrefix("203.0.113.4/32")
	if err := s.ReplaceIPLabels(ctx, 0, IPListSource("l-offices"), []IPLabel{{Prefix: office, Kind: IPKindOffice, Name: "offices", Person: "Alice Example"}}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceIPLabels(ctx, 0, IPListSource("l-elsewhere"), []IPLabel{{Prefix: netip.MustParsePrefix("192.0.2.9/32"), Kind: IPKindStaff, Name: "partners"}}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIPSourceRun(ctx, IPListSource("l-elsewhere"), now, 1, nil); err != nil {
		t.Fatal(err)
	}
	manual, err := s.AddIPLabel(ctx, "test", IPLabel{Prefix: office, Kind: IPKindStaff, Name: "Alice home"})
	if err != nil {
		t.Fatal(err)
	}

	// Re-mapping changes the kind of the labels at once.
	if err := s.SetCloudflareIPListKind(ctx, "user:1", "l-offices", IPKindStaff, now); err != nil {
		t.Fatal(err)
	}
	if ls := labelsFrom(t, s, IPListSource("l-offices")); len(ls) != 1 || ls[0].Kind != IPKindStaff {
		t.Errorf("re-mapped labels: %+v", ls)
	}

	// Ignoring a list removes its labels, not the manual one.
	if err := s.SetCloudflareIPListKind(ctx, "user:1", "l-offices", CFListIgnore, now); err != nil {
		t.Fatal(err)
	}
	if ls := labelsFrom(t, s, IPListSource("l-offices")); len(ls) != 0 {
		t.Errorf("ignored list kept labels: %+v", ls)
	}
	if ls := labelsFrom(t, s, IPSourceManual); len(ls) != 1 || ls[0].ID != manual {
		t.Errorf("manual label: %+v", ls)
	}
	// And removing the manual label leaves the lists alone.
	if err := s.SetCloudflareIPListKind(ctx, "user:1", "l-offices", IPKindOffice, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceIPLabels(ctx, 0, IPListSource("l-offices"), []IPLabel{{Prefix: office, Kind: IPKindOffice, Name: "offices"}}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveIPLabel(ctx, "test", 0, manual); err != nil {
		t.Fatal(err)
	}
	if ls := labelsFrom(t, s, IPListSource("l-offices")); len(ls) != 1 {
		t.Errorf("list labels after removing the manual one: %+v", ls)
	}

	// A list gone from an account that was read is dropped with its
	// labels and state; one in an account that wasn't read stays.
	later := now.Add(time.Hour)
	got, err = s.ReplaceCloudflareIPLists(ctx, []string{acct}, found[:1], later)
	if err != nil || len(got) != 2 || got[0].ID != "l-offices" || got[0].Kind != IPKindOffice || got[1].ID != "l-elsewhere" {
		t.Fatalf("second sync: %+v %v", got, err)
	}
	if !got[0].SeenAt.Equal(later) || got[0].UpdatedBy != "user:1" || got[0].UpdatedAt.IsZero() {
		t.Errorf("kept list: %+v", got[0])
	}
	if ls := labelsFrom(t, s, IPListSource("l-elsewhere")); len(ls) != 1 {
		t.Errorf("unread account's labels: %+v", ls)
	}
	got, err = s.ReplaceCloudflareIPLists(ctx, []string{acct, other}, found[:1], later)
	if err != nil || len(got) != 1 {
		t.Fatalf("third sync: %+v %v", got, err)
	}
	if ls := labelsFrom(t, s, IPListSource("l-elsewhere")); len(ls) != 0 {
		t.Errorf("deleted list's labels: %+v", ls)
	}
	states, _ := s.IPSourceStates(ctx)
	for _, st := range states {
		if st.Source == IPListSource("l-elsewhere") {
			t.Errorf("deleted list's state kept: %+v", st)
		}
	}
}

func labelsFrom(t *testing.T, s *Store, source string) []IPLabel {
	t.Helper()
	ls, err := s.IPLabels(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []IPLabel
	for _, l := range ls {
		if l.Source == source {
			out = append(out, l)
		}
	}
	return out
}
