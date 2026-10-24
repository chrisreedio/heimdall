// SPDX-License-Identifier: AGPL-3.0-or-later

package findings

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/feeds/osv"
	"github.com/chrisreedio/heimdall/internal/ingest"
	"github.com/chrisreedio/heimdall/internal/netx"
	"github.com/chrisreedio/heimdall/internal/snapshot"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/store/storetest"
)

const (
	advisoryID      = "DEBIAN-CVE-2023-5678" // fixed in 3.0.13-1~deb12u1 for Debian:12
	laravelAdvisory = "GHSA-78fx-h6xr-vch4"  // laravel/framework: fixed in 10.48.29, 11.44.1, 12.1.1
)

type fakeOSV struct {
	batches, vulnFetches atomic.Int32
	vulnerable           func(name, version string) bool
}

func (f *fakeOSV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
		f.batches.Add(1)
		var req struct {
			Queries []struct {
				Package struct{ Ecosystem, Name string }
				Version string
			}
		}
		json.NewDecoder(r.Body).Decode(&req)
		type ref struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		}
		type result struct {
			Vulns []ref `json:"vulns,omitempty"`
		}
		out := struct {
			Results []result `json:"results"`
		}{}
		for _, q := range req.Queries {
			var res result
			if q.Package.Ecosystem == "Debian:12" && f.vulnerable(q.Package.Name, q.Version) {
				res.Vulns = []ref{{ID: advisoryID, Modified: "2024-01-01T00:00:00Z"}}
			}
			if q.Package.Ecosystem == "Packagist" && q.Package.Name == "laravel/framework" && q.Version < "11.44.1" {
				res.Vulns = []ref{{ID: laravelAdvisory, Modified: "2025-03-01T00:00:00Z"}}
			}
			out.Results = append(out.Results, res)
		}
		json.NewEncoder(w).Encode(out)
	case r.URL.Path == "/v1/vulns/"+advisoryID, r.URL.Path == "/v1/vulns/"+laravelAdvisory:
		f.vulnFetches.Add(1)
		b, _ := os.ReadFile("../feeds/osv/testdata/" + strings.TrimPrefix(r.URL.Path, "/v1/vulns/") + ".json")
		w.Write(b)
	default:
		http.NotFound(w, r)
	}
}

type env struct {
	t    *testing.T
	st   *store.Store
	host store.IngestHost
	now  time.Time
	eng  *Engine
	osv  *fakeOSV
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := storetest.New(t)
	ctx := t.Context()
	st.CreateOrg(ctx, "test", "acme", "")
	st.CreateEnv(ctx, "test", "acme", "prod", "")
	if _, _, err := st.AddHost(ctx, "test", "acme", "prod", "web-01", nil); err != nil {
		t.Fatal(err)
	}
	host, _ := st.HostByName(ctx, "acme", "web-01")

	fake := &fakeOSV{vulnerable: func(name, ver string) bool {
		return name == "openssl" && strings.HasPrefix(ver, "3.0.11")
	}}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	e := &env{t: t, st: st, host: host, now: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC), osv: fake}
	e.eng = &Engine{
		Store:       st,
		OSV:         &osv.Client{HTTP: netx.NewForTest(srv.Client()), BaseURL: srv.URL},
		Now:         func() time.Time { return e.now },
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxAge:      6 * time.Hour,
		Concurrency: 2,
	}
	return e
}

// report stores a Debian 12 snapshot with openssl/libssl3 at the given
// version, optionally with a pending upgrade on libssl3.
func (e *env) report(opensslVersion, pending string) {
	e.t.Helper()
	b, err := os.ReadFile("../snapshot/testdata/debian12.json")
	if err != nil {
		e.t.Fatal(err)
	}
	var s snapshot.Snapshot
	json.Unmarshal(b, &s)
	for i := range s.Packages {
		if s.Packages[i].SourceName == "openssl" {
			s.Packages[i].Version, s.Packages[i].SourceVersion = opensslVersion, opensslVersion
		}
	}
	s.Updates = nil
	if pending != "" {
		yes := true
		s.Updates = []snapshot.Update{{Name: "libssl3", Arch: "amd64", Version: pending, Security: &yes}}
	}
	s.CollectedAt = e.now
	raw, _ := json.Marshal(s)
	acc := ingest.Accepter{Store: e.st, Now: func() time.Time { return e.now }}
	res, err := acc.Accept(e.t.Context(), e.host, "push", raw)
	if err != nil || res.Status != http.StatusCreated {
		e.t.Fatalf("store snapshot: %+v %v", res, err)
	}
}

func (e *env) open() []store.ReportFinding {
	e.t.Helper()
	fs, err := e.st.OpenFindings(e.t.Context(), e.host.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return fs
}

func TestFindingLifecycle(t *testing.T) {
	e := newEnv(t)
	e.report("3.0.11-1~deb12u2", "3.0.13-1~deb12u1")

	res, err := e.eng.EvaluateHost(t.Context(), e.host)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ecosystem != "Debian:12" || res.Findings != 1 || res.Added != 1 {
		t.Fatalf("result = %+v", res)
	}
	fs := e.open()
	if len(fs) != 1 {
		t.Fatalf("open findings = %+v", fs)
	}
	f := fs[0]
	if f.Package != "openssl" || !slices.Equal(f.Binaries, []string{"libssl3", "openssl"}) {
		t.Errorf("grouping: package %q binaries %v", f.Package, f.Binaries)
	}
	if f.FixedVersion != "3.0.13-1~deb12u1" || !f.FixPending {
		t.Errorf("fix: %q pending=%v", f.FixedVersion, f.FixPending)
	}
	if !slices.Contains(f.CVEs, "CVE-2023-5678") {
		t.Errorf("CVEs = %v (distro records keep the CVE in upstream)", f.CVEs)
	}
	if f.KEV {
		t.Error("not in KEV yet")
	}

	// KEV joins through the CVE alias.
	if err := e.st.ReplaceKEV(t.Context(), []store.KEVEntry{{CVE: "CVE-2023-5678", DateAdded: e.now, KnownRansomware: true}}); err != nil {
		t.Fatal(err)
	}
	if f := e.open()[0]; !f.KEV || !f.KEVRansomware {
		t.Errorf("KEV not joined: %+v", f)
	}

	// Cached: no new OSV calls within MaxAge.
	batches, fetches := e.osv.batches.Load(), e.osv.vulnFetches.Load()
	if _, err := e.eng.EvaluateHost(t.Context(), e.host); err != nil {
		t.Fatal(err)
	}
	if e.osv.batches.Load() != batches || e.osv.vulnFetches.Load() != fetches {
		t.Error("cache not used")
	}

	// The host upgrades: the finding resolves.
	e.now = e.now.Add(24 * time.Hour)
	e.report("3.0.13-1~deb12u1", "")
	res, err = e.eng.EvaluateHost(t.Context(), e.host)
	if err != nil {
		t.Fatal(err)
	}
	if res.Findings != 0 || res.Resolved != 1 || len(e.open()) != 0 {
		t.Fatalf("after upgrade: %+v, open %d", res, len(e.open()))
	}
	if e.osv.vulnFetches.Load() != fetches {
		t.Error("advisory refetched although unchanged")
	}
}

// A site's Composer packages are matched against Packagist, and findings
// carry the site's root.
func TestSiteFindings(t *testing.T) {
	e := newEnv(t)
	b, err := os.ReadFile("../snapshot/testdata/debian12-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var s snapshot.Snapshot
	json.Unmarshal(b, &s)
	s.CollectedAt = e.now
	push := func(s snapshot.Snapshot) {
		t.Helper()
		raw, _ := json.Marshal(s)
		acc := ingest.Accepter{Store: e.st, Now: func() time.Time { return e.now }}
		if res, err := acc.Accept(t.Context(), e.host, "push", raw); err != nil || res.Status != http.StatusCreated {
			t.Fatalf("store snapshot: %+v %v", res, err)
		}
	}
	push(s)

	res, err := e.eng.EvaluateHost(t.Context(), e.host)
	if err != nil {
		t.Fatal(err)
	}
	var site []store.ReportFinding
	for _, f := range e.open() {
		if f.SiteRoot != "" {
			site = append(site, f)
		}
	}
	if len(site) != 1 || res.Findings < 1 {
		t.Fatalf("site findings = %+v (result %+v)", site, res)
	}
	f := site[0]
	if f.SiteRoot != "/home/forge/example.com" || f.Package != "laravel/framework" || f.Version != "11.31.0" {
		t.Errorf("finding = %+v", f)
	}
	// The lowest fixed version above 11.31.0, not 12.1.1 or 10.48.29.
	if f.FixedVersion != "11.44.1" || !slices.Contains(f.CVEs, "CVE-2025-27515") {
		t.Errorf("fixed %q, CVEs %v", f.FixedVersion, f.CVEs)
	}

	// The site upgrades Laravel: the finding resolves.
	e.now = e.now.Add(time.Hour)
	s.CollectedAt = e.now
	for i, p := range s.Sites[0].ComposerPackages {
		if p.Name == "laravel/framework" {
			s.Sites[0].ComposerPackages[i].Version = "11.44.1"
		}
	}
	s.Sites[0].FrameworkVersion = "11.44.1"
	push(s)
	if res, err = e.eng.EvaluateHost(t.Context(), e.host); err != nil || res.Resolved != 1 {
		t.Fatalf("after upgrade: %+v %v", res, err)
	}
}

func TestUnsupportedOSIsSkipped(t *testing.T) {
	inv := store.HostInventory{OSID: "plan9", OSVersion: "4"}
	if _, ok := HostEcosystem(inv); ok {
		t.Fatal("plan9 should be unsupported")
	}
}

func TestPickFixed(t *testing.T) {
	tests := []struct {
		installed string
		fixed     []string
		want      string
	}{
		{"3.0.11-1", []string{"3.0.13-1", "3.0.12-1"}, "3.0.12-1"}, // lowest fix above installed
		{"3.0.14-1", []string{"3.0.13-1"}, ""},                     // already past every fix
		{"3.0.11-1", nil, ""},                                      // no fix published
	}
	for _, tt := range tests {
		if got := pickFixed("dpkg", tt.installed, tt.fixed); got != tt.want {
			t.Errorf("pickFixed(%q, %v) = %q, want %q", tt.installed, tt.fixed, got, tt.want)
		}
	}
	// rpm advisories may omit the epoch the installed package carries.
	if got := pickFixed("rpm", "1:3.0.7-24.el9", []string{"3.0.7-27.el9"}); got != "3.0.7-27.el9" {
		t.Errorf("rpm epoch: got %q", got)
	}
}

// EPSS scores attach to findings through the advisory's CVE IDs.
func TestEPSSJoin(t *testing.T) {
	e := newEnv(t)
	e.report("3.0.11-1~deb12u2", "")
	if _, err := e.eng.EvaluateHost(t.Context(), e.host); err != nil {
		t.Fatal(err)
	}
	cves, err := e.st.OpenFindingCVEs(t.Context())
	if err != nil || !slices.Contains(cves, "CVE-2023-5678") {
		t.Fatalf("open CVEs = %v %v", cves, err)
	}
	if err := e.st.PutEPSS(t.Context(), []store.EPSSScore{{CVE: "CVE-2023-5678", Score: 0.42, Percentile: 0.97, Date: e.now}}); err != nil {
		t.Fatal(err)
	}
	if f := e.open()[0]; f.EPSS != 0.42 {
		t.Errorf("EPSS = %v", f.EPSS)
	}
}
