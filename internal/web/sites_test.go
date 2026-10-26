// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/ingest"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

const siteRoot = "/home/forge/example.com"

// seedSites stores app-01 with the v2 fixture (a Forge Laravel site) and a
// critical Composer finding with a hostile-looking summary in that site.
func (e *env) seedSites() store.IngestHost {
	e.t.Helper()
	ctx := e.t.Context()
	e.st.CreateOrg(ctx, "test", "acme", "Acme")
	e.st.CreateEnv(ctx, "test", "acme", "prod", "")
	if _, _, err := e.st.AddHost(ctx, "test", "acme", "prod", "app-01", nil); err != nil {
		e.t.Fatal(err)
	}
	host, _ := e.st.HostByName(ctx, "acme", "app-01")
	raw, err := os.ReadFile("../snapshot/testdata/debian12-v2.json")
	if err != nil {
		e.t.Fatal(err)
	}
	var snap map[string]any
	json.Unmarshal(raw, &snap)
	snap["collected_at"] = testNow.Format(time.RFC3339)
	raw, _ = json.Marshal(snap)
	acc := ingest.Accepter{Store: e.st, Now: func() time.Time { return testNow }}
	if res, err := acc.Accept(ctx, host, "push", raw); err != nil || res.Status != http.StatusCreated {
		e.t.Fatalf("seed v2 snapshot: %+v %v", res, err)
	}
	if err := e.st.PutAdvisory(ctx, store.Advisory{
		ID: "GHSA-test-0000-0001", Modified: testNow, Summary: `<img src=x onerror=alert(1)> in laravel`,
		Severity: "critical", CVSS: 9.1, Raw: []byte(`{}`), Aliases: []string{"CVE-2099-1111"},
	}); err != nil {
		e.t.Fatal(err)
	}
	if _, _, err := e.st.SetFindings(ctx, host.ID, []store.Finding{{
		AdvisoryID: "GHSA-test-0000-0001", Ecosystem: "Packagist", Package: "laravel/framework",
		Version: "11.31.0", Binaries: []string{"laravel/framework"}, FixedVersion: "11.44.1", SiteRoot: siteRoot,
	}}, testNow); err != nil {
		e.t.Fatal(err)
	}
	return host
}

func TestSitesPage(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seedSites()
	w := e.get("/sites", signedIn(e))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	b := w.Body.String()
	for _, want := range []string{"example.com", siteRoot, "/hosts/acme/app-01", "8.3", "11.31.0", "nginx", `aria-current="page">Sites`} {
		if !strings.Contains(b, want) {
			t.Errorf("sites page missing %q", want)
		}
	}
	// The critical finding is counted for the site.
	if !regexp.MustCompile(`<td class="num">1</td>`).MatchString(b) {
		t.Error("critical count not shown")
	}
	// The unreadable fixture site is flagged.
	if !strings.Contains(b, "unreadable") {
		t.Error("unreadable site not flagged")
	}
}

func TestHostPageSites(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seedSites()
	w := e.get("/hosts/acme/app-01", signedIn(e))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	b := w.Body.String()
	if !strings.Contains(b, "composer update laravel/framework --with-dependencies") {
		t.Error("composer command missing")
	}
	if !strings.Contains(b, "run in the site root") {
		t.Error("site root note missing")
	}
	if !strings.Contains(b, `<h3 id="os-packages">OS packages</h3>`) || !strings.Contains(b, "<h2>Sites</h2>") {
		t.Error("OS and site sections missing")
	}
	if strings.Contains(b, "<img src=x") || !strings.Contains(b, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Error("advisory summary not escaped")
	}
	// Folded by package (closed: there are several sites, listed above
	// them), and the line under the chips points at them.
	for _, want := range []string{`<details class="site-findings">`, `<ul class="site-index small">`, `<a href="#site-0">`, `class="pkg-list"`, `<a href="#sites">1 site' Composer packages</a>: 1 fixable now`} {
		if !strings.Contains(b, want) {
			t.Errorf("host page missing %q", want)
		}
	}
	// The Composer finding belongs to its site, not the OS table.
	os, sites, _ := strings.Cut(b, "<h2>Sites</h2>")
	if strings.Contains(os, "CVE-2099-1111") || !strings.Contains(sites, "CVE-2099-1111") {
		t.Error("site finding rendered in the wrong section")
	}
}

func TestAttnText(t *testing.T) {
	for _, c := range []struct {
		fixable, watch int
		want           string
	}{{46, 16, "46 fixable now · 16 to watch (no fix yet)"}, {3, 0, "3 fixable now"}, {0, 2, "2 to watch (no fix yet)"}, {0, 0, "nothing needs attention"}} {
		if got := attnText(c.fixable, c.watch); got != c.want {
			t.Errorf("attnText(%d, %d) = %q", c.fixable, c.watch, got)
		}
	}
}

func TestComposerCommandFiltersNames(t *testing.T) {
	if composerCommand("x", nil) != nil {
		t.Fatal("no findings, no command")
	}
	cmd := composerCommand("x", []report.Finding{
		{Package: "laravel/framework", Fixed: "11.44.1"},
		{Package: "evil/pkg; rm -rf /", Fixed: "1.0"}, // unsafe name: dropped
		{Package: "guzzlehttp/psr7", Fixed: ""},       // no fix: dropped
		{Package: "laravel/framework", Fixed: "11.44.1"},
		{Package: "symfony/http-foundation", Fixed: "7.1.7"},
	})
	if cmd == nil || cmd.Text != "composer update laravel/framework symfony/http-foundation --with-dependencies" {
		t.Fatalf("command = %+v", cmd)
	}
}

func TestDashboardSitesTile(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seedSites()
	b := e.get("/", signedIn(e)).Body.String()
	m := regexp.MustCompile(`<a class="tile[^"]*" href="/sites"><span class="n">(\d+)</span>`).FindStringSubmatch(b)
	if m == nil || m[1] != "1" {
		t.Fatalf("sites tile = %v", m)
	}
}
