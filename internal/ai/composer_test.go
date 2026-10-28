// SPDX-License-Identifier: AGPL-3.0-or-later

package ai

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

const sheetFix = "composer update phpoffice/phpspreadsheet --with-dependencies"

// composerHosts are web-01 (sites a.example.dev and b.example.dev) and
// staging-01 (app.example.com), each site with a fixable phpspreadsheet
// finding. a.example.dev also has a monolog finding, but monolog is only
// in b.example.dev's composer.lock, so no command may name it.
func composerHosts() []hostData {
	site := func(root, name string) report.Site { return report.Site{Root: root, ServerNames: []string{name}} }
	// inv is a host's sites: each root, then its locked package names.
	inv := func(sites ...[]string) store.HostInventory {
		var out store.HostInventory
		for _, l := range sites {
			s := store.InventorySite{Root: l[0]}
			for _, p := range l[1:] {
				s.Packages = append(s.Packages, store.AppPackage{Name: p, Version: "1.0.0"})
			}
			out.Sites = append(out.Sites, s)
		}
		return out
	}
	sheet := func(root string) report.Finding {
		return report.Finding{Site: root, Package: "phpoffice/phpspreadsheet", Version: "1.29.0", Fixed: "1.29.9", Severity: "high"}
	}
	a, b, c := "/var/www/a/current", "/var/www/b/current", "/srv/app/current"
	return []hostData{
		{host: store.IngestHost{Name: "web-01"}, pm: "dpkg",
			rep: report.Host{Name: "web-01", Sites: []report.Site{site(a, "a.example.dev"), site(b, "b.example.dev")},
				Findings: []report.Finding{sheet(a), sheet(b), {Site: a, Package: "monolog/monolog", Version: "2.0.0", Fixed: "2.10.0"}}},
			inv: inv([]string{a, "phpoffice/phpspreadsheet"}, []string{b, "phpoffice/phpspreadsheet", "monolog/monolog"})},
		{host: store.IngestHost{Name: "staging-01"}, pm: "dpkg",
			rep: report.Host{Name: "staging-01", Sites: []report.Site{site(c, "app.example.com")}, Findings: []report.Finding{sheet(c)}},
			inv: inv([]string{c, "phpoffice/phpspreadsheet"})},
	}
}

func composerAllowed(data []hostData) Allowed {
	a := Allowed{Hosts: map[string]HostAllowed{}}
	for _, d := range data {
		a.Hosts[d.host.Name] = d.allowed(false)
	}
	return a
}

// The brief's facts and allowlist carry each site's Composer update (the
// host explanation's do too), naming only the packages in that site's own
// lockfile.
func TestFleetComposerCommands(t *testing.T) {
	data := composerHosts()
	allowed := composerAllowed(data)
	if got := allowed.Hosts["web-01"].Commands; !slices.Equal(got, []string{sheetFix, sheetFix}) {
		t.Errorf("web-01 allowed: %q", got)
	}
	if got := allowed.Hosts["staging-01"].Sites; !slices.Equal(got, []SiteCommand{{Site: "app.example.com", Command: sheetFix}}) {
		t.Errorf("staging-01 sites: %+v", got)
	}
	hf := Sources{}.fact(data[0], detailLevels[0], 3, false)
	if len(hf.Commands) != 2 || hf.Commands[0].Label != "In /var/www/a/current: update the Composer packages with fixes" {
		t.Errorf("web-01 fleet facts: %+v", hf.Commands)
	}
	for _, cmd := range []string{"composer update monolog/monolog --with-dependencies",
		"composer update monolog/monolog phpoffice/phpspreadsheet --with-dependencies", "composer update laravel/framework"} {
		if got := checkCommand(cmd, allowed.Hosts["web-01"]); got != "" {
			t.Errorf("%q allowed on web-01", cmd)
		}
	}
	// A package in another site's lockfile only (monolog is in b's) is
	// never added to a's command.
	if strings.Contains(strings.Join(allowed.Hosts["web-01"].Commands, " "), "monolog") {
		t.Error("monolog suggested without a site that has both its finding and its lockfile entry")
	}
}

// The same Composer update on two hosts and three sites is one step with
// one command, labelled with each host's sites; the model's steps per host
// are merged into it.
func TestFleetComposerStep(t *testing.T) {
	allowed := composerAllowed(composerHosts())
	text := answer(
		map[string]any{"title": "Update phpoffice/phpspreadsheet", "why": "High.", "hosts": []string{"web-01"},
			"commands": []map[string]any{{"hosts": []string{"web-01"}, "command": sheetFix}}},
		map[string]any{"title": "Update phpoffice/phpspreadsheet on staging-01", "why": "High.", "hosts": []string{"staging-01"},
			"commands": []map[string]any{{"hosts": []string{"staging-01"}, "command": sheetFix}}},
		map[string]any{"title": "Update monolog", "why": "x", "hosts": []string{"web-01"},
			"commands": []map[string]any{{"hosts": []string{"web-01"}, "command": "composer update monolog/monolog --with-dependencies"}}},
	)
	res, err := Parse(text, allowed)
	if err != nil {
		t.Fatal(err)
	}
	res = Reconcile(res, allowed)
	if len(res.Actions) != 1 {
		t.Fatalf("actions: %+v", res.Actions)
	}
	a := res.Actions[0]
	if !slices.Equal(a.Hosts, []string{"web-01", "staging-01"}) || len(a.Commands) != 1 || !a.Labelled() {
		t.Fatalf("step: %+v", a)
	}
	c := a.Commands[0]
	if c.Command != sheetFix || !slices.Equal(c.SitesOf("web-01"), []string{"a.example.dev", "b.example.dev"}) ||
		!slices.Equal(c.SitesOf("staging-01"), []string{"app.example.com"}) {
		t.Errorf("command: %+v", c)
	}
	// Stored and read back, the sites stay; an old stored command has none.
	b, _ := json.Marshal(res)
	back, ok := Decode(b)
	if !ok || !slices.Equal(back.Actions[0].Commands[0].SitesOf("staging-01"), []string{"app.example.com"}) {
		t.Errorf("decoded: %+v", back)
	}
	old, ok := Decode([]byte(`{"summary":"s","actions":[{"title":"Update","why":"w","host":"web-01","command":"` + sheetFix + `"}]}`))
	if !ok || old.Actions[0].Commands[0].Sites != nil || old.Actions[0].Labelled() {
		t.Errorf("old command: %+v", old.Actions[0])
	}
}
