// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/ingest"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

var now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

const forgeRoot = "/home/forge/example.com"

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st := storetest.New(t)
	st.CreateOrg(t.Context(), "test", "acme", "")
	st.CreateEnv(t.Context(), "test", "acme", "prod", "")
	return st
}

// pushV2 stores the v2 fixture for a new host, with the given composer.json
// PHP requirement for the Forge site.
func pushV2(t *testing.T, st *store.Store, name, phpRequirement string) store.IngestHost {
	t.Helper()
	ctx := t.Context()
	if _, _, err := st.AddHost(ctx, "test", "acme", "prod", name, nil); err != nil {
		t.Fatal(err)
	}
	host, _ := st.HostByName(ctx, "acme", name)
	raw, err := os.ReadFile("../snapshot/testdata/debian12-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	json.Unmarshal(raw, &snap)
	snap["collected_at"] = now.Format(time.RFC3339)
	for _, s := range snap["sites"].([]any) {
		site := s.(map[string]any)
		if site["root"] == forgeRoot {
			site["php_requirement"] = phpRequirement
		}
	}
	raw, _ = json.Marshal(snap)
	acc := ingest.Accepter{Store: st, Now: func() time.Time { return now }}
	if res, err := acc.Accept(ctx, host, "push", raw); err != nil || res.Status != http.StatusCreated {
		t.Fatalf("push %s: %+v %v", name, res, err)
	}
	return host
}

func date(s string) *time.Time {
	t, _ := time.Parse(time.DateOnly, s)
	return &t
}

func TestSites(t *testing.T) {
	st := newStore(t)
	ctx := t.Context()
	ok := pushV2(t, st, "app-01", "^8.2") // PHP-FPM 8.3 satisfies ^8.2
	pushV2(t, st, "app-02", "^8.4")       // ...but not ^8.4
	if err := st.ReplaceEOL(ctx, "php", []store.EOLCycle{
		{Product: "php", Cycle: "8.1", EOL: date("2025-12-31")},
		{Product: "php", Cycle: "8.3", EOL: date("2027-12-31")},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceEOL(ctx, "laravel", []store.EOLCycle{
		{Product: "laravel", Cycle: "11", EOL: date("2026-03-12")},
	}); err != nil {
		t.Fatal(err)
	}

	// One OS finding and one finding in the Forge site.
	for _, id := range []string{"DEBIAN-CVE-2099-0001", "GHSA-test-0000-0001"} {
		if err := st.PutAdvisory(ctx, store.Advisory{ID: id, Modified: now, Severity: "high", Raw: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := st.SetFindings(ctx, ok.ID, []store.Finding{
		{AdvisoryID: "DEBIAN-CVE-2099-0001", Ecosystem: "Debian:12", Package: "openssl", Version: "3.0.14-1~deb12u2", FixedVersion: "3.0.15-1~deb12u1"},
		{AdvisoryID: "GHSA-test-0000-0001", Ecosystem: "Packagist", Package: "laravel/framework", Version: "11.31.0", FixedVersion: "11.44.1", SiteRoot: forgeRoot},
	}, now); err != nil {
		t.Fatal(err)
	}

	r, err := Build(ctx, st, Filter{Scope: store.AllScope}, now)
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]Host{}
	for _, h := range r.Hosts {
		hosts[h.Name] = h
	}
	h1 := hosts["app-01"]
	if h1.Counts.Total != 2 || h1.Counts.High != 2 || h1.Counts.Fixable != 2 {
		t.Errorf("host counts should include OS and site findings: %+v", h1.Counts)
	}
	sites := map[string]Site{}
	for _, s := range h1.Sites {
		sites[s.Root] = s
	}
	if len(sites) != 3 {
		t.Fatalf("sites = %d, want 3", len(sites))
	}

	forge := sites[forgeRoot]
	if forge.Counts.Total != 1 || forge.Counts.Fixable != 1 {
		t.Errorf("site counts should be this site's only: %+v", forge.Counts)
	}
	if forge.PHPSatisfied == nil || !*forge.PHPSatisfied {
		t.Errorf("^8.2 with PHP-FPM 8.3 should be satisfied: %v", forge.PHPSatisfied)
	}
	if forge.PHPLife == nil || !forge.PHPLife.Known || forge.PHPLife.EOL {
		t.Errorf("php 8.3 lifecycle: %+v", forge.PHPLife)
	}
	if forge.FrameworkLife == nil || forge.FrameworkLife.Cycle != "11" || !forge.FrameworkLife.EOL {
		t.Errorf("laravel 11 should be EOL: %+v", forge.FrameworkLife)
	}
	if forge.DeployedAt == nil || forge.Packages != 4 || !forge.Readable {
		t.Errorf("forge site facts: %+v", forge)
	}

	legacy := sites["/var/www/legacy"]
	if legacy.PHPSatisfied != nil {
		t.Errorf("no requirement should leave PHPSatisfied nil, got %v", *legacy.PHPSatisfied)
	}
	if legacy.PHPLife == nil || !legacy.PHPLife.EOL {
		t.Errorf("php 8.1 should be EOL: %+v", legacy.PHPLife)
	}
	if legacy.Readable || legacy.Counts.Total != 0 {
		t.Errorf("legacy site: %+v", legacy)
	}
	if html := sites["/var/www/html"]; html.PHPLife != nil || html.PHPSatisfied != nil {
		t.Errorf("site without PHP-FPM: %+v", html)
	}

	var forge2 Site
	for _, s := range hosts["app-02"].Sites {
		if s.Root == forgeRoot {
			forge2 = s
		}
	}
	if forge2.PHPSatisfied == nil || *forge2.PHPSatisfied {
		t.Errorf("^8.4 with PHP-FPM 8.3 should not be satisfied: %v", forge2.PHPSatisfied)
	}

	// Findings carry their site.
	var siteFinding Finding
	for _, f := range h1.Findings {
		if f.Site != "" {
			siteFinding = f
		}
	}
	if siteFinding.Site != forgeRoot || siteFinding.Package != "laravel/framework" {
		t.Errorf("site finding = %+v", siteFinding)
	}

	var buf bytes.Buffer
	WriteText(&buf, r, 10)
	out := buf.String()
	for _, want := range []string{
		"Site: " + forgeRoot + " (example.com, www.example.com)",
		"laravel 11.31.0 (laravel 11: END OF LIFE since 2026-03-12)",
		"DOES NOT satisfy composer.json php ^8.4",
		"composer files not readable by the collector",
		"laravel/framework 11.31.0 in " + forgeRoot,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report missing %q\n%s", want, out)
		}
	}
	if strings.Count(out, "DOES NOT satisfy") != 1 {
		t.Errorf("only app-02's site should fail its requirement:\n%s", out)
	}

	// JSON includes sites.
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"php_requirement_met":false`) || !strings.Contains(string(b), `"site":"`+forgeRoot+`"`) {
		t.Error("JSON missing site fields")
	}
}
