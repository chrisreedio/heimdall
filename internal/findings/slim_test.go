// SPDX-License-Identifier: AGPL-3.0-or-later

package findings

import (
	"io"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/feeds/osv"
)

// Golden check over every OSV fixture: what Heimdall derives from a record
// (summary, aliases, CVSS, severity, ranges per ecosystem) is the same from
// the stored slim record as from the original.
func TestSlimRecordDerivesSameAdvisory(t *testing.T) {
	dir := "../feeds/osv/testdata/"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.Name() == "querybatch.json" {
			continue
		}
		raw, err := os.ReadFile(dir + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		full, err := osv.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		slim, err := osv.Slim(raw)
		if err != nil {
			t.Fatal(err)
		}
		v, err := osv.Parse(slim)
		if err != nil {
			t.Fatal(err)
		}
		want, got := toAdvisory(full, nil), toAdvisory(v, nil)
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%s:\nfull %+v\nslim %+v", e.Name(), want, got)
		}
		if len(want.Ranges) == 0 || want.Severity == "" {
			t.Errorf("%s: fixture derives nothing to compare: %+v", e.Name(), want)
		}
		n++
	}
	if n < 6 {
		t.Errorf("only %d fixtures", n)
	}
}

// A changed advisory is refetched and stored slim, without disturbing the
// findings that refer to it.
func TestRefreshedAdvisoryKeepsFindings(t *testing.T) {
	e := newEnv(t)
	e.report("3.0.11-1~deb12u2", "")
	if _, err := e.eng.EvaluateHost(t.Context(), e.host); err != nil {
		t.Fatal(err)
	}
	first := e.open()
	if len(first) != 1 {
		t.Fatalf("findings = %+v", first)
	}

	e.now = e.now.Add(7 * time.Hour) // past MaxAge: query OSV again
	e.osv.modified.Store("2099-01-01T00:00:00Z")
	fetches := e.osv.vulnFetches.Load()
	if _, err := e.eng.EvaluateHost(t.Context(), e.host); err != nil {
		t.Fatal(err)
	}
	if e.osv.vulnFetches.Load() == fetches {
		t.Fatal("changed advisory not refetched")
	}
	now := e.open()
	if len(now) != 1 || !now[0].FirstSeen.Equal(first[0].FirstSeen) || now[0].FixedVersion != first[0].FixedVersion {
		t.Errorf("after refetch: %+v, before %+v", now, first)
	}

	rec, err := e.st.AdvisoryRecord(t.Context(), advisoryID)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := osv.Parse(rec); err != nil || v.ID != advisoryID || strings.Contains(string(rec), `"versions"`) {
		t.Errorf("stored record: %v %.200s", err, rec)
	}
}

// Once nothing refers to an advisory any more (the host is gone) and its
// query result has aged out, a sync prunes it.
func TestSyncPrunesUnreferencedAdvisories(t *testing.T) {
	e := newEnv(t)
	e.report("3.0.11-1~deb12u2", "")
	s := &Syncer{Store: e.st, Engine: e.eng, Feeds: config.Feeds{OSV: true},
		Now: func() time.Time { return e.now }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := t.Context()
	if err := s.syncOSV(ctx); err != nil {
		t.Fatal(err)
	}
	has := func() bool {
		known, err := e.st.AdvisoryModified(ctx, []string{advisoryID})
		if err != nil {
			t.Fatal(err)
		}
		return len(known) == 1
	}
	if !has() {
		t.Fatal("advisory not stored")
	}

	// The host upgrades: its resolved finding still refers to the advisory.
	e.now = e.now.Add(40 * 24 * time.Hour)
	e.report("3.0.13-1~deb12u1", "")
	if err := s.syncOSV(ctx); err != nil {
		t.Fatal(err)
	}
	if !has() {
		t.Fatal("advisory behind a resolved finding was pruned")
	}

	if err := e.st.RemoveHost(ctx, "test", "acme", e.host.Name); err != nil {
		t.Fatal(err)
	}
	if err := s.syncOSV(ctx); err != nil {
		t.Fatal(err)
	}
	if has() {
		t.Error("unreferenced advisory kept")
	}
}
