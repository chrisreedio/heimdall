// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// Sites that deploy one repository share a button on the brief, labelled
// by the repository and opening its representative site; a site with no
// known repository keeps its own. The host page groups the same way, a
// viewer gets none, and the rate limit holds per repository too.
func TestAIBriefHandoffsByRepo(t *testing.T) {
	fd := newFakeDiscord(t)
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.Agents = []handoff.Agent{fd.agent("pr-bot", testBotID)}
		c.AI = &fakeAI{}
	})
	ctx := t.Context()
	staging, sRoots := e.seedComposerHost("acme", "staging-01", "app.example.dev", "beta.example.dev")
	web, wRoots := e.seedComposerHost("acme", "web-01", "www.example.com")
	// One repository, reached two ways (detected over https, set by hand over ssh).
	if err := e.st.SetDetectedSiteRepos(ctx, staging.ID, map[string]string{sRoots[0]: "https://github.com/acme/app.git"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetSiteRepo(ctx, "test", web.ID, wRoots[0], "git@github.com:acme/app"); err != nil {
		t.Fatal(err)
	}
	// app.example.dev sorts first by name, but it's labelled staging.
	if err := e.st.SetSiteLabel(ctx, "test", staging.ID, sRoots[0], "staging"); err != nil {
		t.Fatal(err)
	}
	all := ai.Command{Hosts: []string{"staging-01", "web-01"}, Command: laravelFix,
		Sites: map[string][]string{"staging-01": {"app.example.dev", "beta.example.dev"}, "web-01": {"www.example.com"}}}
	runs := 0
	brief := func(why string) string {
		runs++
		storeRun(t, e.st, web.OrgID, 0, ai.Result{Summary: "s", Actions: []ai.Action{
			{Title: "Update laravel/framework", Why: why, Hosts: all.Hosts, Commands: []ai.Command{all}}}}, testNow.Add(time.Duration(runs-3)*time.Hour))
		return html.UnescapeString(briefStep(t, e.get("/", signedIn(e)).Body.String(), "acme"))
	}
	asRole(e, web.OrgID, store.RoleOperator)
	li := brief("High.")
	if n := strings.Count(li, "handoff-btn"); n != 2 {
		t.Errorf("%d hand-off buttons, want one for the repository and one for the site without one:\n%s", n, li)
	}
	for _, want := range []string{
		`href="` + handoffURL("acme", "web-01", wRoots[0], "") + `" title="One pull request on acme/app for 2 sites: ` +
			`staging-01 · app.example.dev, web-01 · www.example.com. It sends web-01 · www.example.com's findings.">acme/app</a>`,
		`href="` + handoffURL("acme", "staging-01", sRoots[1], "") + `">beta.example.dev</a>`,
	} {
		if !strings.Contains(li, want) {
			t.Errorf("step lacks %q:\n%s", want, li)
		}
	}
	// Naming a site (here in a path, which stays plain) narrows the step
	// to it and its repository's other sites.
	if li := brief("Run it in /var/www/app.example.dev/current."); !strings.Contains(li, `<div class="muted small ai-why">Run it in /var/www/app.example.dev/current.</div>`) ||
		strings.Count(li, "handoff-btn") != 1 || !strings.Contains(li, ">acme/app</a>") {
		t.Errorf("the step naming a site's path: a plain path, one button for its repository:\n%s", li)
	}

	// The host page's triage card groups too: with beta.example.dev on the
	// same repository, staging-01's two sites get one labelled button.
	if err := e.st.SetSiteRepo(ctx, "test", staging.ID, sRoots[1], "https://github.com/acme/app"); err != nil {
		t.Fatal(err)
	}
	storeRun(t, e.st, staging.OrgID, staging.ID, ai.Result{Summary: "x", Actions: []ai.Action{
		step("Update Laravel", "x", "staging-01", laravelFix)}}, testNow)
	page := html.UnescapeString(e.get("/hosts/acme/staging-01", signedIn(e)).Body.String())
	card := page[strings.Index(page, `id="ai-triage"`):]
	card = card[:strings.Index(card, "</section>")]
	if strings.Count(card, "handoff-btn") != 1 || !strings.Contains(card, `href="`+handoffURL("acme", "staging-01", sRoots[1], "")+`"`) ||
		!strings.Contains(card, ">acme/app</a>") || !strings.Contains(card, "Hand off to agent:") {
		t.Errorf("host page: one button for the repository, opening the production site:\n%s", card)
	}

	// Sending for one site holds the repository's other sites for the agent.
	send := func(host, root string) *httptest.ResponseRecorder {
		t.Helper()
		cp := e.get(handoffURL("acme", host, root, "pr-bot"), signedIn(e)).Body.String()
		d, id := digestRe.FindStringSubmatch(cp), requestIDRe.FindStringSubmatch(cp)
		if d == nil || id == nil {
			t.Fatalf("confirm page for %s %s:\n%s", host, root, cp)
		}
		return e.post("/hosts/acme/"+host+"/handoff", url.Values{"csrf": {auth.CSRFToken(goodToken)}, "root": {root},
			"agent": {"pr-bot"}, "request_id": {id[1]}, "digest": {d[1]}}, signedIn(e), origin(e.baseURL))
	}
	if w := send("web-01", wRoots[0]); w.Code != http.StatusSeeOther {
		t.Fatalf("first send: %d", w.Code)
	}
	w := send("staging-01", sRoots[0])
	if w.Code != http.StatusTooManyRequests || !strings.Contains(html.UnescapeString(w.Body.String()), "Another site on acme/app was handed to pr-bot") {
		t.Errorf("same repository right after: %d", w.Code)
	}
	if n := len(fd.sent()); n != 1 {
		t.Errorf("posted %d messages, want 1", n)
	}

	// A viewer gets no buttons on either.
	asRole(e, web.OrgID, store.RoleViewer)
	if li := briefStep(t, e.get("/", signedIn(e)).Body.String(), "acme"); strings.Contains(li, "handoff-btn") {
		t.Errorf("viewer sees hand-off buttons:\n%s", li)
	}
	if page := e.get("/hosts/acme/staging-01", signedIn(e)).Body.String(); strings.Contains(page, "handoff-btn") {
		t.Error("viewer sees the host page's hand-off button")
	}
}

// A repository's button opens the site with the most of the step's
// findings, then a production one, then the first by name; the tooltip
// says when the sites aren't on the same versions.
func TestAIHandoffRepresentative(t *testing.T) {
	const two = "composer update laravel/framework guzzlehttp/guzzle --with-dependencies"
	site := func(root, name string) report.Site { return report.Site{Root: root, ServerNames: []string{name}} }
	fix := func(root, pkg, installed string) report.Finding {
		return report.Finding{Site: root, Package: pkg, Version: installed, Fixed: "99.0.0"}
	}
	repo := "https://github.com/acme/app"
	cases := []struct {
		name     string
		labels   map[string]string
		findings []report.Finding
		want     string // the representative's root
		differ   bool
	}{
		{"most findings", map[string]string{"/a": "production", "/b": "staging"},
			[]report.Finding{fix("/a", "laravel/framework", "11.31.0"), fix("/b", "laravel/framework", "11.20.0"), fix("/b", "guzzlehttp/guzzle", "7.0.0")}, "/b", true},
		{"production on a tie", map[string]string{"/a": "staging", "/b": "production"},
			[]report.Finding{fix("/a", "laravel/framework", "11.31.0"), fix("/b", "laravel/framework", "11.31.0")}, "/b", false},
		{"name on a tie", map[string]string{"/a": "production", "/b": "production"},
			[]report.Finding{fix("/a", "laravel/framework", "11.31.0"), fix("/b", "laravel/framework", "11.31.0")}, "/a", false},
	}
	for _, c := range cases {
		hosts := map[string]handoffHost{"web-01": {Org: "acme", Labels: c.labels,
			Repos: map[string]string{"/a": repo, "/b": repo, "/c": ""},
			Host: report.Host{Name: "web-01", Sites: []report.Site{site("/a", "a.example.com"), site("/b", "b.example.com"), site("/c", "c.example.com")},
				Findings: append(c.findings, fix("/c", "laravel/framework", "11.31.0"))}}}
		view := &aiView{View: ai.View{Result: &ai.Result{Actions: []ai.Action{{Title: "Update", Hosts: []string{"web-01"},
			Commands: []ai.Command{{Hosts: []string{"web-01"}, Command: two}}}}}}}
		aiHandoffs(view, hosts)
		links := view.Handoffs[0]
		if len(links) != 2 || links[0].Site != "acme/app" || links[1].Site != "c.example.com" || links[1].Title != "" {
			t.Fatalf("%s: links %+v", c.name, links)
		}
		if want := handoffURL("acme", "web-01", c.want, ""); links[0].URL != want {
			t.Errorf("%s: opens %s, want %s", c.name, links[0].URL, want)
		}
		if differ := strings.Contains(links[0].Title, "aren't all on the same versions"); differ != c.differ {
			t.Errorf("%s: title %q", c.name, links[0].Title)
		}
	}

	// Alone, a repository with one site is a plain button; with two it's labelled.
	one := map[string]handoffHost{"web-01": {Org: "acme", Repos: map[string]string{"/a": repo},
		Host: report.Host{Name: "web-01", Sites: []report.Site{site("/a", "a.example.com")}, Findings: []report.Finding{fix("/a", "laravel/framework", "1")}}}}
	view := &aiView{View: ai.View{Result: &ai.Result{Actions: []ai.Action{step("Update", "x", "web-01", laravelFix)}}}}
	aiHandoffs(view, one)
	if l := view.Handoffs[0]; len(l) != 1 || l[0].Site != "" || !strings.Contains(l[0].Title, "acme/app") {
		t.Errorf("one site: %+v", l)
	}
}
