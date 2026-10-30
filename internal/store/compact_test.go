// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAdvisoryRecordRoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	rec := []byte(`{"id":"UBUNTU-CVE-2099-0001","affected":[` + strings.Repeat(`{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"linux"}},`, 500) + `{}]}`)
	if err := s.PutAdvisory(ctx, Advisory{ID: "UBUNTU-CVE-2099-0001", Modified: newsNow, Raw: rec}); err != nil {
		t.Fatal(err)
	}
	got, err := s.AdvisoryRecord(ctx, "UBUNTU-CVE-2099-0001")
	if err != nil || !bytes.Equal(got, rec) {
		t.Fatalf("record round trip: %v\n%.80s", err, got)
	}
	var raw string
	var stored int
	s.db.QueryRowContext(ctx, `SELECT raw, length(record) FROM advisories`).Scan(&raw, &stored)
	if raw != "" || stored == 0 || stored*10 > len(rec) {
		t.Errorf("stored raw %q, record %d bytes for %d", raw, stored, len(rec))
	}
	if _, err := s.AdvisoryRecord(ctx, "NOPE-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing advisory: %v", err)
	}
	// No record at all is fine too.
	if err := s.PutAdvisory(ctx, Advisory{ID: "EMPTY-1", Modified: newsNow}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.AdvisoryRecord(ctx, "EMPTY-1"); err != nil || got != nil {
		t.Errorf("empty record: %q %v", got, err)
	}
}

// Refreshing an advisory used to delete and reinsert it, which cascaded to
// every host's findings for it.
func TestPutAdvisoryKeepsFindings(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	h := addFindingHost(t, s, "acme", "web-01", "DEBIAN-CVE-2099-0001", "CVE-2099-0001")
	later := newsNow.Add(time.Hour)
	if err := s.PutAdvisory(ctx, Advisory{ID: "DEBIAN-CVE-2099-0001", Modified: later, Severity: "critical",
		Raw: []byte(`{}`), Aliases: []string{"CVE-2099-0009"},
		Ranges: []AffectedRange{{Ecosystem: "Debian:12", Package: "openssl", Fixed: "2"}}}); err != nil {
		t.Fatal(err)
	}
	fs, err := s.OpenFindings(ctx, h.ID)
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings after refresh: %+v %v", fs, err)
	}
	if !fs[0].FirstSeen.Equal(newsNow) || fs[0].Severity != "critical" {
		t.Errorf("finding = %+v", fs[0])
	}
	if strings.Join(fs[0].CVEs, ",") != "CVE-2099-0009" {
		t.Errorf("aliases not replaced: %v", fs[0].CVEs)
	}
	fixed, err := s.FixedVersions(ctx, "DEBIAN-CVE-2099-0001", "Debian:12", "openssl")
	if err != nil || len(fixed) != 1 || fixed[0] != "2" {
		t.Errorf("ranges: %v %v", fixed, err)
	}
}

// putLegacy stores an advisory the way Heimdall did before migration 0012.
func putLegacy(t *testing.T, s *Store, id, raw string) {
	t.Helper()
	if _, err := s.db.ExecContext(t.Context(),
		`INSERT INTO advisories (id, modified, raw) VALUES (?, '2026-01-01T00:00:00Z', ?)`, id, raw); err != nil {
		t.Fatal(err)
	}
}

func TestSlimAdvisoriesConvertsLegacyRows(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	big := strings.Repeat("x", 3<<20) // three of these exceed one batch
	for i := range 7 {
		putLegacy(t, s, fmt.Sprintf("OLD-%d", i), fmt.Sprintf(`{"id":"OLD-%d","pad":"%s"}`, i, big))
	}
	putLegacy(t, s, "BAD-1", `{"id":"BAD-1","unparseable":true}`)
	if err := s.PutAdvisory(ctx, Advisory{ID: "NEW-1", Modified: newsNow, Raw: []byte(`{"id":"NEW-1"}`)}); err != nil {
		t.Fatal(err)
	}
	slim := func(raw []byte) ([]byte, error) {
		if bytes.Contains(raw, []byte("unparseable")) {
			return nil, errors.New("bad record")
		}
		return raw[:bytes.IndexByte(raw, ',')+1], nil // `{"id":"OLD-n",`
	}
	var reports int
	p, err := s.SlimAdvisories(ctx, slim, func(SlimProgress) { reports++ })
	if err != nil {
		t.Fatal(err)
	}
	if p.Rows != 9 || p.Converted != 8 || reports < 2 {
		t.Errorf("progress %+v after %d reports", p, reports)
	}
	for i := range 7 {
		id := fmt.Sprintf("OLD-%d", i)
		if got, err := s.AdvisoryRecord(ctx, id); err != nil || string(got) != `{"id":"`+id+`",` {
			t.Errorf("%s: %.40q %v", id, got, err)
		}
	}
	// What slim can't parse is kept whole.
	if got, _ := s.AdvisoryRecord(ctx, "BAD-1"); string(got) != `{"id":"BAD-1","unparseable":true}` {
		t.Errorf("BAD-1 = %q", got)
	}
	if got, _ := s.AdvisoryRecord(ctx, "NEW-1"); string(got) != `{"id":"NEW-1"}` {
		t.Errorf("NEW-1 = %q", got)
	}
	var left int
	s.db.QueryRowContext(ctx, `SELECT count(*) FROM advisories WHERE raw != ''`).Scan(&left)
	if left != 0 {
		t.Errorf("%d rows still hold raw JSON", left)
	}
	// Rerunning finds nothing to do.
	if p, err := s.SlimAdvisories(ctx, slim, nil); err != nil || p.Converted != 0 || p.Rows != 9 {
		t.Errorf("second run: %+v %v", p, err)
	}

	// The space comes back with Compact.
	st, err := s.SpaceStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.FreePages*2 < st.Pages || st.CompactNeeds() <= 2*st.UsedBytes() {
		t.Errorf("stats %+v", st)
	}
	if err := s.Compact(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := s.SpaceStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.FreePages != 0 || after.Bytes()*4 > st.Bytes() || after.WorthCompacting() {
		t.Errorf("after compacting: %+v (before %+v)", after, st)
	}
	if got, _ := s.AdvisoryRecord(ctx, "OLD-3"); string(got) != `{"id":"OLD-3",` {
		t.Errorf("after compacting: %q", got)
	}
}

func TestWorthCompacting(t *testing.T) {
	t.Parallel()
	const mib = 1 << 20 / 4096 // pages
	for _, tt := range []struct {
		pages, free int64
		want        bool
	}{
		{1000 * mib, 950 * mib, true}, // after slimming: nearly all free
		{1000 * mib, 300 * mib, true},
		{1000 * mib, 200 * mib, false}, // under a quarter
		{100 * mib, 60 * mib, false},   // under 64 MiB
		{0, 0, false},
	} {
		st := SpaceStats{PageSize: 4096, Pages: tt.pages, FreePages: tt.free}
		if got := st.WorthCompacting(); got != tt.want {
			t.Errorf("%+v: WorthCompacting = %v", st, got)
		}
	}
}

func TestPruneAdvisories(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	addFindingHost(t, s, "acme", "web-01", "FINDING-1")
	for _, id := range []string{"FRESH-1", "OLD-1", "ORPHAN-1", "SHARED-1"} {
		if err := s.PutAdvisory(ctx, Advisory{ID: id, Modified: newsNow, Raw: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	old := newsNow.Add(-40 * 24 * time.Hour)
	if err := s.PutOSVResults(ctx, map[OSVKey][]string{
		{Ecosystem: "Debian:12", Name: "a", Version: "1"}: {"FRESH-1", "SHARED-1"},
	}, newsNow); err != nil {
		t.Fatal(err)
	}
	if err := s.PutOSVResults(ctx, map[OSVKey][]string{
		{Ecosystem: "Debian:12", Name: "a", Version: "0"}: {"OLD-1", "SHARED-1", "FINDING-1"},
	}, old); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneAdvisories(ctx, newsNow.Add(-30*24*time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	known, err := s.AdvisoryModified(ctx, []string{"FINDING-1", "FRESH-1", "OLD-1", "ORPHAN-1", "SHARED-1"})
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"FINDING-1": true, "FRESH-1": true, "SHARED-1": true, "OLD-1": false, "ORPHAN-1": false} {
		if _, ok := known[id]; ok != want {
			t.Errorf("%s kept = %v, want %v", id, ok, want)
		}
	}
	cached, err := s.OSVCached(ctx, []OSVKey{{Ecosystem: "Debian:12", Name: "a", Version: "0"}}, time.Time{})
	if err != nil || len(cached) != 0 {
		t.Errorf("old query result kept: %v %v", cached, err)
	}
}
