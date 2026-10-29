// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/ingest"
	"github.com/realmwatch/heimdall/internal/store"
)

// bind9's client tools without named: a no-fix finding with a high EPSS
// score isn't worth watching there, a known-exploited one still is, and
// the same score on another package still counts. The page's counts and
// the store's (the host list's) agree.
func TestClientOnlyWatch(t *testing.T) {
	st := newStore(t)
	ctx := t.Context()
	if _, _, err := st.AddHost(ctx, "test", "acme", "prod", "web-01", nil); err != nil {
		t.Fatal(err)
	}
	host, _ := st.HostByName(ctx, "acme", "web-01")
	raw, err := os.ReadFile("../snapshot/testdata/debian12-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	json.Unmarshal(raw, &snap)
	snap["collected_at"] = now.Format(time.RFC3339)
	snap["packages"] = append(snap["packages"].([]any),
		map[string]any{"name": "bind9-host", "version": "1:9.18.1-1", "arch": "amd64", "source_name": "bind9", "source_version": "1:9.18.1-1"},
		map[string]any{"name": "bind9-libs", "version": "1:9.18.1-1", "arch": "amd64", "source_name": "bind9", "source_version": "1:9.18.1-1"})
	raw, _ = json.Marshal(snap)
	acc := ingest.Accepter{Store: st, Now: func() time.Time { return now }}
	if res, err := acc.Accept(ctx, host, "push", raw); err != nil || res.Status != http.StatusCreated {
		t.Fatalf("push: %+v %v", res, err)
	}

	for _, id := range []string{"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"} {
		if err := st.PutAdvisory(ctx, store.Advisory{ID: id, Modified: now, Severity: "high", Raw: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.ReplaceKEV(ctx, []store.KEVEntry{{CVE: "CVE-2099-0002", DateAdded: now}}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutEPSS(ctx, []store.EPSSScore{{CVE: "CVE-2099-0001", Score: 0.5, Date: now}, {CVE: "CVE-2099-0003", Score: 0.5, Date: now}}); err != nil {
		t.Fatal(err)
	}
	bind := []string{"bind9-host", "bind9-libs"}
	if _, _, err := st.SetFindings(ctx, host.ID, []store.Finding{
		{AdvisoryID: "CVE-2099-0001", Ecosystem: "Debian:12", Package: "bind9", Version: "1:9.18.1-1", Binaries: bind}, // likely exploited: not watched
		{AdvisoryID: "CVE-2099-0002", Ecosystem: "Debian:12", Package: "bind9", Version: "1:9.18.1-1", Binaries: bind}, // KEV: watched
		{AdvisoryID: "CVE-2099-0003", Ecosystem: "Debian:12", Package: "zlib", Version: "1", Binaries: []string{"zlib1g"}},
	}, now); err != nil {
		t.Fatal(err)
	}

	full, err := Build(ctx, st, Filter{Org: "acme", Scope: store.AllScope, Host: "web-01"}, now)
	if err != nil || len(full.Hosts) != 1 {
		t.Fatalf("build: %v", err)
	}
	h := full.Hosts[0]
	for _, f := range h.Findings {
		if want := map[string]string{"bind9": "bind9"}[f.Package]; f.ClientOnly != want {
			t.Errorf("%s %s: ClientOnly %q, want %q", f.Package, f.Advisory, f.ClientOnly, want)
		}
	}
	if h.Counts.Watch != 2 || h.Counts.NoFix != 3 {
		t.Errorf("page counts: watch %d, no fix %d; want 2, 3", h.Counts.Watch, h.Counts.NoFix)
	}
	sum, err := Build(ctx, st, Filter{Org: "acme", Scope: store.AllScope, Host: "web-01", CountsOnly: true}, now)
	if err != nil || len(sum.Hosts) != 1 {
		t.Fatalf("build counts: %v", err)
	}
	if sum.Hosts[0].Counts != h.Counts {
		t.Errorf("store counts %+v\n page counts %+v", sum.Hosts[0].Counts, h.Counts)
	}
}
