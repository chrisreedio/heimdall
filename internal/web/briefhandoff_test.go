// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"html"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/ai"
	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/handoff"
	"github.com/realmwatch/heimdall/internal/ingest"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

const laravelFix = "composer update laravel/framework --with-dependencies"

// seedComposerHost stores a host in org with the v2 fixture's packages and
// one Laravel site per server name (root /var/www/<name>), each with a
// fixable laravel/framework finding. It returns the host and its roots.
func (e *env) seedComposerHost(org, name string, sites ...string) (store.IngestHost, []string) {
	e.t.Helper()
	ctx := e.t.Context()
	e.st.CreateOrg(ctx, "test", org, strings.ToUpper(org[:1])+org[1:])
	e.st.CreateEnv(ctx, "test", org, "prod", "")
	if _, _, err := e.st.AddHost(ctx, "test", org, "prod", name, nil); err != nil {
		e.t.Fatal(err)
	}
	host, _ := e.st.HostByName(ctx, org, name)
	raw, err := os.ReadFile("../snapshot/testdata/debian12-v2.json")
	if err != nil {
		e.t.Fatal(err)
	}
	var snap map[string]any
	json.Unmarshal(raw, &snap)
	snap["collected_at"] = testNow.Format(time.RFC3339)
	var list []any
	var roots []string
	var fs []store.Finding
	for _, s := range sites {
		root := "/var/www/" + s
		roots = append(roots, root)
		list = append(list, map[string]any{"root": root, "document_root": root + "/public", "server_names": []string{s},
			"web_server": "nginx", "readable": true, "framework": "laravel", "framework_version": "11.31.0",
			"composer_packages": []map[string]string{{"name": "laravel/framework", "version": "11.31.0"}}})
		fs = append(fs, store.Finding{AdvisoryID: "GHSA-test-0000-0001", Ecosystem: "Packagist", Package: "laravel/framework",
			Version: "11.31.0", Binaries: []string{"laravel/framework"}, FixedVersion: "11.44.1", SiteRoot: root})
	}
	snap["sites"] = list
	raw, _ = json.Marshal(snap)
	acc := ingest.Accepter{Store: e.st, Now: func() time.Time { return testNow }}
	if res, err := acc.Accept(ctx, host, "push", raw); err != nil || res.Status != http.StatusCreated {
		e.t.Fatalf("seed %s: %+v %v", name, res, err)
	}
	if err := e.st.PutAdvisory(ctx, store.Advisory{ID: "GHSA-test-0000-0001", Modified: testNow, Summary: "laravel",
		Severity: "high", CVSS: 8.1, Raw: []byte(`{}`)}); err != nil {
		e.t.Fatal(err)
	}
	if _, _, err := e.st.SetFindings(ctx, host.ID, fs, testNow); err != nil {
		e.t.Fatal(err)
	}
	return host, roots
}

// briefStep is the brief's Composer step on the dashboard page, from its
// title to the end of its list item.
func briefStep(t *testing.T, page, org string) string {
	t.Helper()
	i := strings.Index(page, `id="ai-brief-`+org+`"`)
	if i < 0 {
		t.Fatalf("no %s brief", org)
	}
	s := page[i:]
	s = s[strings.Index(s, `<ol class="ai-actions">`):]
	return s[:strings.Index(s, "</li>")]
}

// The fleet brief's Composer step on two hosts and three sites: one command
// box labelled with each host's sites, and one hand-off button per site,
// each to its host's own org; a second org's brief links to that org.
func TestAIBriefHandoffs(t *testing.T) {
	fd := newFakeDiscord(t)
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.Agents = []handoff.Agent{fd.agent("pr-bot", testBotID)}
		c.AI = &fakeAI{}
	})
	web, webRoots := e.seedComposerHost("acme", "web-01", "a.example.dev", "b.example.dev")
	_, stagingRoots := e.seedComposerHost("acme", "staging-01", "app.example.com")
	other, otherRoots := e.seedComposerHost("beta", "web-09", "shop.example.com")
	storeRun(t, e.st, web.OrgID, 0, ai.Result{Summary: "s", Actions: []ai.Action{{
		Title: "Update laravel/framework", Why: "High.", Hosts: []string{"web-01", "staging-01"},
		Commands: []ai.Command{{Hosts: []string{"web-01", "staging-01"}, Command: laravelFix,
			Sites: map[string][]string{"web-01": {"a.example.dev", "b.example.dev"}, "staging-01": {"app.example.com"}}}},
	}}}, testNow)
	storeRun(t, e.st, other.OrgID, 0, ai.Result{Summary: "s", Actions: []ai.Action{
		step("Update Laravel", "x", "web-09", laravelFix)}}, testNow)
	both := func(acme, beta store.Role) {
		e.auth.viewer = &auth.Viewer{UserID: 7, DisplayName: "Jane", SessionToken: goodToken,
			Scope: store.Scope{Orgs: map[int64]store.Role{web.OrgID: acme, other.OrgID: beta}}}
	}
	both(store.RoleOperator, store.RoleOperator)
	page := e.get("/", signedIn(e)).Body.String()
	li := briefStep(t, page, "acme")
	if strings.Count(li, `<div class="codebox ai-cmd">`) != 1 || strings.Count(li, `class="ai-cmdhosts small"`) != 2 {
		t.Errorf("one command box labelled with both hosts' sites:\n%s", li)
	}
	for _, want := range []string{
		handoffURL("acme", "web-01", webRoots[0], ""), handoffURL("acme", "web-01", webRoots[1], ""),
		handoffURL("acme", "staging-01", stagingRoots[0], ""),
		`">a.example.dev</a>`, `">b.example.dev</a>`, `">app.example.com</a>`, "Hand off to agent:",
	} {
		if !strings.Contains(html.UnescapeString(li), want) {
			t.Errorf("acme step lacks %q:\n%s", want, li)
		}
	}
	if n := strings.Count(li, "handoff-btn"); n != 3 {
		t.Errorf("%d hand-off buttons, want one per site", n)
	}
	beta := html.UnescapeString(briefStep(t, page, "beta"))
	if !strings.Contains(beta, `href="`+handoffURL("beta", "web-09", otherRoots[0], "")+`"`) || !strings.Contains(beta, ">Hand off to agent</a>") {
		t.Errorf("beta step: its own org's slug, one unlabelled button:\n%s", beta)
	}

	// A viewer in acme sees acme's brief without buttons; beta's still has its own.
	both(store.RoleViewer, store.RoleOperator)
	page = e.get("/", signedIn(e)).Body.String()
	if li := briefStep(t, page, "acme"); strings.Contains(li, "handoff-btn") {
		t.Errorf("viewer sees hand-off buttons:\n%s", li)
	}
	if !strings.Contains(briefStep(t, page, "beta"), "handoff-btn") {
		t.Error("operator in beta lost beta's button")
	}
}

// Without agents there are no buttons, and a brief stored before commands
// knew their sites still renders, offering each of the host's sites.
func TestAIBriefHandoffsOldAndOff(t *testing.T) {
	old := `{"summary":"s","actions":[{"title":"Update Laravel on web-01","why":"x","host":"web-01","command":"` + laravelFix + `"}]}`
	stored := func(e *env, orgID int64) {
		id, err := e.st.StartAIRun(t.Context(), orgID, 0, store.AIBrief, "user:1", "demo", testNow, time.Minute, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.st.FinishAIRun(t.Context(), id, "ok", "m", 1, 1, "", []byte(old), testNow); err != nil {
			t.Fatal(err)
		}
	}
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.AI = &fakeAI{} })
	host, _ := e.seedComposerHost("acme", "web-01", "a.example.dev", "b.example.dev")
	stored(e, host.OrgID)
	asRole(e, host.OrgID, store.RoleAdmin)
	li := briefStep(t, e.get("/", signedIn(e)).Body.String(), "acme")
	if !strings.Contains(li, laravelFix) || strings.Contains(li, "handoff-btn") || strings.Contains(li, "ai-cmdhosts") {
		t.Errorf("no agents: the command, no buttons, no labels:\n%s", li)
	}

	fd := newFakeDiscord(t)
	e = newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.Agents = []handoff.Agent{fd.agent("pr-bot", testBotID)}
		c.AI = &fakeAI{}
	})
	host, _ = e.seedComposerHost("acme", "web-01", "a.example.dev", "b.example.dev")
	stored(e, host.OrgID)
	asRole(e, host.OrgID, store.RoleOperator)
	li = briefStep(t, e.get("/", signedIn(e)).Body.String(), "acme")
	if strings.Count(li, "handoff-btn") != 2 || !strings.Contains(li, "<strong>Update Laravel</strong>") {
		t.Errorf("old brief: both sites offered:\n%s", li)
	}
}

// Two hosts with a site of the same name: those buttons name the host too.
func TestAIHandoffSameSiteName(t *testing.T) {
	h := func(name string) handoffHost {
		return handoffHost{Org: "acme", Host: report.Host{Name: name,
			Sites:    []report.Site{{Root: "/var/www/a", ServerNames: []string{"example.com"}}, {Root: "/var/www/b", ServerNames: []string{name + ".example.dev"}}},
			Findings: []report.Finding{{Site: "/var/www/a", Package: "laravel/framework", Fixed: "11.44.1"}, {Site: "/var/www/b", Package: "laravel/framework", Fixed: "11.44.1"}}}}
	}
	view := &aiView{View: ai.View{Result: &ai.Result{Actions: []ai.Action{{Title: "Update Laravel", Hosts: []string{"web-01", "web-02"},
		Commands: []ai.Command{{Hosts: []string{"web-01", "web-02"}, Command: laravelFix}}}}}}}
	aiHandoffs(view, map[string]handoffHost{"web-01": h("web-01"), "web-02": h("web-02")})
	var got []string
	for _, l := range view.Handoffs[0] {
		got = append(got, l.Site)
	}
	if want := "web-01 · example.com|web-01.example.dev|web-02 · example.com|web-02.example.dev"; strings.Join(got, "|") != want {
		t.Errorf("labels %q, want %q", got, want)
	}
}
