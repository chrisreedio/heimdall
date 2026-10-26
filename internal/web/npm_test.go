// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/ingest"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

// seedNpmSite stores app-01 with the v2 fixture's Laravel site as v4, with
// npm packages, and findings: Laravel (Composer), axios (a fix within its
// range), @acme/legacy (a fix that needs a new major) and vite (a critical
// dev dependency).
func (e *env) seedNpmSite() store.IngestHost {
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
	snap["format"] = "heimdall.snapshot/v4"
	snap["collected_at"] = testNow.Format(time.RFC3339)
	snap["containers"], snap["lockfiles"] = []any{}, []any{}
	sites := snap["sites"].([]any)
	sites[0].(map[string]any)["npm_packages"] = []map[string]any{
		{"name": "axios", "version": "1.6.0", "dev": false},
		{"name": "@acme/legacy", "version": "1.2.0", "dev": false},
		{"name": "vite", "version": "5.0.10", "dev": true},
	}
	raw, _ = json.Marshal(snap)
	acc := ingest.Accepter{Store: e.st, Now: func() time.Time { return testNow }}
	if res, err := acc.Accept(ctx, host, "push", raw); err != nil || res.Status != http.StatusCreated {
		e.t.Fatalf("seed v4 snapshot: %+v %v", res, err)
	}
	for _, a := range []store.Advisory{
		{ID: "GHSA-test-0000-0001", Severity: "high", Summary: "laravel issue"},
		{ID: "GHSA-test-0000-0002", Severity: "medium", Summary: "axios issue"},
		{ID: "GHSA-test-0000-0003", Severity: "high", Summary: "legacy issue"},
		{ID: "GHSA-test-0000-0004", Severity: "critical", Summary: "vite dev server issue"},
	} {
		a.Modified, a.Raw = testNow, []byte(`{}`)
		if err := e.st.PutAdvisory(ctx, a); err != nil {
			e.t.Fatal(err)
		}
	}
	if _, _, err := e.st.SetFindings(ctx, host.ID, []store.Finding{
		{AdvisoryID: "GHSA-test-0000-0001", Ecosystem: "Packagist", Package: "laravel/framework", Version: "11.31.0",
			Binaries: []string{"laravel/framework"}, FixedVersion: "11.44.1", SiteRoot: siteRoot},
		{AdvisoryID: "GHSA-test-0000-0002", Ecosystem: "npm", Package: "axios", Version: "1.6.0",
			Binaries: []string{"axios"}, FixedVersion: "1.7.4", SiteRoot: siteRoot},
		{AdvisoryID: "GHSA-test-0000-0003", Ecosystem: "npm", Package: "@acme/legacy", Version: "1.2.0",
			Binaries: []string{"@acme/legacy"}, FixedVersion: "2.0.0", SiteRoot: siteRoot},
		{AdvisoryID: "GHSA-test-0000-0004", Ecosystem: "npm", Package: "vite", Version: "5.0.10",
			Binaries: []string{"vite"}, FixedVersion: "5.0.12", SiteRoot: siteRoot, Dev: true},
	}, testNow); err != nil {
		e.t.Fatal(err)
	}
	return host
}

// The host page's site card splits Composer and npm, each with its own
// fix command; the dev dependency is listed, badged, and left out of the
// commands and of what needs attention.
func TestHostPageNpmSite(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seedNpmSite()
	w := e.get("/hosts/acme/app-01", signedIn(e))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	b := w.Body.String()
	_, sites, _ := strings.Cut(b, "<h2>Sites</h2>")
	composer, npm, ok := strings.Cut(sites, "<h4>npm")
	if !ok || !strings.Contains(composer, "<h4>Composer") {
		t.Fatalf("no Composer and npm sections:\n%s", sites)
	}
	if !strings.Contains(composer, "composer update laravel/framework --with-dependencies") || strings.Contains(composer, "axios") {
		t.Error("Composer section: wrong command or findings")
	}
	for _, want := range []string{"package-lock.json", "npm update axios</pre>", "npm install @acme/legacy@2.0.0</pre>",
		"need a newer major version", "run in the site root", ">dev</span>", "vite", "1 on dev dependencies", "laravel/framework"} {
		if want == "laravel/framework" {
			if strings.Contains(npm, want) {
				t.Error("npm section lists a Composer package")
			}
			continue
		}
		if !strings.Contains(npm, want) {
			t.Errorf("npm section missing %q", want)
		}
	}
	if strings.Contains(npm, "vite@") || strings.Contains(npm, "update axios vite") {
		t.Error("the dev dependency is in a fix command")
	}
	// The line under the chips adds up: 3 fixable, the dev one not among them.
	if !strings.Contains(b, `<a href="#sites">1 site' Composer and npm packages</a>: 3 fixable now`) {
		t.Error("attention line wrong")
	}
	if !strings.Contains(b, "<li><span class=\"k\">npm packages</span><span class=\"v\">3 <span class=\"muted\">(1 dev)</span>") {
		t.Error("npm package count missing")
	}
}

func TestSitePageNpm(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seedNpmSite()
	base := "/hosts/acme/app-01/site?root=" + siteRoot
	b := e.get(base, signedIn(e)).Body.String()
	for _, want := range []string{"Composer and npm findings", "composer update laravel/framework --with-dependencies",
		"npm update axios</pre>", "npm install @acme/legacy@2.0.0</pre>", "on dev dependencies</span>"} {
		if !strings.Contains(b, want) {
			t.Errorf("site page missing %q", want)
		}
	}
	// Needs attention (the default) leaves the dev finding out; all shows it.
	if strings.Contains(b, "vite dev server issue") {
		t.Error("dev finding shown as needing attention")
	}
	all := e.get(base+"&show=all&view=all", signedIn(e)).Body.String()
	if !strings.Contains(all, "vite dev server issue") || !strings.Contains(all, ">dev</span>") || !strings.Contains(all, `<span class="tag">npm</span>`) {
		t.Error("show all: dev finding missing or unbadged")
	}
	// The critical filter matches the chip's count, which leaves dev out.
	if crit := e.get(base+"&sev=critical", signedIn(e)).Body.String(); strings.Contains(crit, "vite dev server issue") {
		t.Error("critical filter shows the dev finding")
	}

	sites := e.get("/sites", signedIn(e)).Body.String()
	// Critical 0 (the dev one is left out), high 2, fixable 3 plus the dev one.
	_, row, _ := strings.Cut(sites, "<tbody>")
	if !strings.Contains(row, `<td class="num">0</td>
    <td class="num">2</td>
    <td class="num">3<div`) || !strings.Contains(row, "+1 dev</div>") {
		t.Errorf("/sites: counts or dev note wrong:\n%s", row)
	}
}

func TestNpmCommandsFilterNames(t *testing.T) {
	if npmCommands("x", nil) != nil {
		t.Fatal("no findings, no command")
	}
	f := func(name, installed, fixed string) report.Finding {
		return report.Finding{Ecosystem: "npm", Package: name, Version: installed, Fixed: fixed}
	}
	cmds := npmCommands("x", []report.Finding{
		f("axios", "1.6.0", "1.6.8"),
		f("axios", "1.6.0", "1.7.4"), // two advisories: the higher fix covers both
		f("@vue/compiler-sfc", "3.4.0", "3.4.31"),
		f("semver", "6.3.0", "7.5.2"), // a new major
		f("tar", "0.4.1", "0.5.0"),    // 0.x: a new minor is outside ^
		f("evil; rm -rf /", "1.0.0", "1.0.1"),
		f("--registry=http://x", "1.0.0", "1.0.1"),
		f("-rf", "1.0.0", "1.0.1"),
		f(".hidden", "1.0.0", "1.0.1"),
		f("Lodash", "4.17.20", "4.17.21"),
		f("lodash", "4.17.20", "4.17.21 || 5"),
		f("minimist", "1.2.5", "^1.2.6"),
		f("qs", "6.5.0", ""), // no fix
		{Ecosystem: "npm", Package: "vite", Version: "5.0.10", Fixed: "5.0.12", Dev: true}, // dev
		{Ecosystem: "Packagist", Package: "laravel/framework", Version: "11.0.0", Fixed: "11.44.1"},
	})
	if len(cmds) != 2 {
		t.Fatalf("commands = %+v", cmds)
	}
	if cmds[0].Text != "npm update @vue/compiler-sfc axios" {
		t.Errorf("update = %q", cmds[0].Text)
	}
	if cmds[1].Text != "npm install semver@7.5.2 tar@0.5.0" {
		t.Errorf("install = %q", cmds[1].Text)
	}
	if !strings.Contains(cmds[0].Label, "run in the site root") || !strings.Contains(cmds[1].Label, "newer major") {
		t.Errorf("labels %q / %q", cmds[0].Label, cmds[1].Label)
	}
	// Composer's command ignores npm findings, even ones with a slash.
	if c := composerCommand("x", []report.Finding{{Ecosystem: "npm", Package: "acme/x", Fixed: "1.0.1"}}); c != nil {
		t.Errorf("composer command for an npm finding: %+v", c)
	}
}

func TestInCaretRange(t *testing.T) {
	for _, c := range []struct {
		installed, fixed string
		want             bool
	}{
		{"1.6.0", "1.7.4", true}, {"1.6.0", "2.0.0", false}, {"0.4.1", "0.4.9", true}, {"0.4.1", "0.5.0", false},
		{"7.5.0-beta.1", "7.5.2", true}, {"7.5", "7.5.2", false}, {"", "1.0.0", false},
	} {
		if got := inCaretRange(c.installed, c.fixed); got != c.want {
			t.Errorf("inCaretRange(%q, %q) = %v", c.installed, c.fixed, got)
		}
	}
}
