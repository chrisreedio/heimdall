// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/handoff"
	"github.com/realmwatch/heimdall/internal/store"
)

var fileRe = regexp.MustCompile(`(?s)<pre class="handoff-msg" id="handoff-file">(.*?)</pre>`)

// handoffFile opens a confirm page and returns its status, the attached
// file it shows, and the form to send it.
func handoffFile(t *testing.T, e *env, path string) (int, handoff.FileData, url.Values, string) {
	t.Helper()
	w := e.get(path, signedIn(e))
	page := w.Body.String()
	var f handoff.FileData
	m := fileRe.FindStringSubmatch(page)
	if m == nil {
		return w.Code, f, nil, page
	}
	if err := json.Unmarshal([]byte(html.UnescapeString(m[1])), &f); err != nil {
		t.Fatalf("file: %v", err)
	}
	form := url.Values{"csrf": {auth.CSRFToken(goodToken)}}
	send := page[strings.Index(page, `class="actions handoff-send"`):]
	for _, name := range []string{"root", "agent", "target", "branch", "request_id", "digest"} {
		if v := regexp.MustCompile(`name="` + name + `" value="([^"]*)"`).FindStringSubmatch(send); v != nil {
			form.Set(name, html.UnescapeString(v[1]))
		}
	}
	return w.Code, f, form, page
}

// One repository deployed from three branches by three sites on two
// hosts, plus a fourth in an org the viewer can only view.
func seedThreeBranches(t *testing.T, e *env) (prod store.IngestHost, root string) {
	t.Helper()
	ctx := t.Context()
	web, webRoots := e.seedComposerHost("acme", "web-01", "app.example.com")
	staging, stagingRoots := e.seedComposerHost("acme", "staging-01", "staging.example.com", "beta.example.com")
	other, otherRoots := e.seedComposerHost("beta", "web-09", "shop.example.com")
	repo := "https://github.com/acme/app"
	e.st.SetDetectedSiteRepos(ctx, web.ID, map[string]string{webRoots[0]: repo})
	e.st.SetDetectedSiteRepos(ctx, staging.ID, map[string]string{stagingRoots[0]: repo, stagingRoots[1]: repo})
	e.st.SetDetectedSiteRepos(ctx, other.ID, map[string]string{otherRoots[0]: repo})
	e.st.SetDetectedSiteBranches(ctx, web.ID, map[string]store.DetectedRef{webRoots[0]: {Branch: "main"}})
	e.st.SetDetectedSiteBranches(ctx, staging.ID, map[string]store.DetectedRef{stagingRoots[0]: {Branch: "dev"}})
	// The beta site's release has no .git: an operator set its branch.
	e.st.SetSiteBranch(ctx, "user:1", staging.ID, stagingRoots[1], "env/beta")
	e.st.SetDetectedSiteBranches(ctx, other.ID, map[string]store.DetectedRef{otherRoots[0]: {Branch: "release"}})
	e.auth.viewer = &auth.Viewer{UserID: 7, DisplayName: "Jane", SessionToken: goodToken,
		Scope: store.Scope{Orgs: map[int64]store.Role{web.OrgID: store.RoleOperator, other.OrgID: store.RoleViewer}}}
	return web, webRoots[0]
}

func siteKeys(f handoff.FileData) []string {
	var out []string
	for _, s := range f.Sites {
		b := "null"
		if s.Branch != nil {
			b = *s.Branch
		}
		out = append(out, s.Host+" "+s.Site+" "+b+" "+s.Label)
	}
	return out
}

func TestHandoffSites(t *testing.T) {
	fd := newFakeDiscord(t)
	e := handoffEnv(t, fd.agent("pr-bot", testBotID))
	_, root := seedThreeBranches(t, e)
	path := handoffURL("acme", "web-01", root, "")

	code, f, _, page := handoffFile(t, e, path)
	if code != http.StatusOK {
		t.Fatalf("confirm page: %d", code)
	}
	// Three sites, three branches; the view-only org's site isn't listed.
	want := []string{"web-01 app.example.com main production", "staging-01 beta.example.com env/beta production", "staging-01 staging.example.com dev staging"}
	if got := siteKeys(f); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("sites:\n got %q\nwant %q", got, want)
	}
	if f.Host != "web-01" || f.SitePath != root || f.Target.Mode != "default" || f.SuggestedBranch == "" {
		t.Errorf("top level: %s %s %+v", f.Host, f.SitePath, f.Target)
	}
	if len(f.Sites[2].Installed) != 1 || f.Sites[2].Installed[0].Installed != "11.31.0" {
		t.Errorf("installed: %+v", f.Sites[2].Installed)
	}
	for _, want := range []string{`value="branch:dev"`, `value="branch:env/beta"`, `value="branch:main"`, `value="each" data-autosubmit`,
		"Where the pull request goes", "Sites on this repository", "set by an operator", "3 sites, 3 branches (`sites`)."} {
		if !strings.Contains(html.UnescapeString(page), want) {
			t.Errorf("confirm page lacks %q", want)
		}
	}
	if strings.Contains(page, "shop.example.com") || strings.Contains(page, "web-09") || strings.Contains(page, "release") {
		t.Error("a site the viewer can't operate on is listed")
	}

	// One branch: the file says so, and the agent works on it.
	code, f, _, _ = handoffFile(t, e, path+"&target=branch:dev")
	if code != http.StatusOK || f.Target.Mode != "branch" || strings.Join(f.Target.Branches, ",") != "dev" ||
		!strings.HasSuffix(f.SuggestedBranch, "-dev") || !strings.Contains(f.Steps[0], "check out the branch in `target.branches`") {
		t.Errorf("branch target: %d %+v %q", code, f.Target, f.SuggestedBranch)
	}
	// A branch the sites don't have is refused, never sent as text.
	for _, bad := range []string{"&target=branch:release", "&target=branch:x%3Breboot", "&target=branch&branch=nope", "&target=all"} {
		if code, f, _, page := handoffFile(t, e, path+bad); code != http.StatusBadRequest || f.Target.Mode != "default" ||
			!strings.Contains(html.UnescapeString(page), "isn't one of these sites' branches") {
			t.Errorf("%s: %d %+v", bad, code, f.Target)
		}
	}

	// Each branch, sent: what's posted is what was shown.
	code, f, form, page := handoffFile(t, e, path+"&target=each")
	if code != http.StatusOK || f.Target.Mode != "each" || len(f.Target.PullRequests) != 3 || f.SuggestedBranch != "" ||
		form.Get("target") != "each" {
		t.Fatalf("each: %d %+v %v", code, f.Target, form)
	}
	if !strings.Contains(page, "its own pull request, against dev") {
		t.Error("the sites table doesn't say what each site gets")
	}
	// The digest covers the target: the "each" digest with another target
	// is a changed message.
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("target", "branch")
	bad.Set("branch", "main")
	if w := e.post("/hosts/acme/web-01/handoff", bad, signedIn(e), origin(e.baseURL)); w.Code != http.StatusConflict {
		t.Errorf("another target with this digest: %d", w.Code)
	}
	bad.Set("branch", "x; reboot")
	if w := e.post("/hosts/acme/web-01/handoff", bad, signedIn(e), origin(e.baseURL)); w.Code != http.StatusBadRequest {
		t.Errorf("invalid branch sent: %d", w.Code)
	}
	if len(fd.sent()) != 0 {
		t.Fatal("posted before a valid confirm")
	}
	w := e.post("/hosts/acme/web-01/handoff", form, signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("send: %d", w.Code)
	}
	sent := fd.sent()
	if len(sent) != 1 {
		t.Fatalf("posted %d", len(sent))
	}
	var posted handoff.FileData
	json.Unmarshal([]byte(sent[0]["_file"].(string)), &posted)
	if posted.Target.Mode != "each" || len(posted.Sites) != 3 || posted.RequestID != form.Get("request_id") {
		t.Errorf("posted file: %+v", posted.Target)
	}
	content, _ := sent[0]["content"].(string)
	if !strings.Contains(content, "Open one pull request per branch in `target.branches` (3)") || !strings.Contains(content, `"mode":"each"`) && !strings.Contains(content, `"mode": "each"`) {
		t.Errorf("posted content: %s", content)
	}
	// The repository's rate limit holds for its other sites.
	_, _, form2, _ := handoffFile(t, e, handoffURL("acme", "staging-01", "/var/www/staging.example.com", ""))
	if w := e.post("/hosts/acme/staging-01/handoff", form2, signedIn(e), origin(e.baseURL)); w.Code != http.StatusTooManyRequests {
		t.Errorf("another site on the repository right after: %d", w.Code)
	}
}

// A site whose branch is unknown is listed as such and not targeted by
// "each"; with no branch known at all (a snapshot from before branches, or
// no .git), "each" is off and refused.
func TestHandoffUnknownBranch(t *testing.T) {
	fd := newFakeDiscord(t)
	e := handoffEnv(t, fd.agent("pr-bot", testBotID))
	_, root := seedThreeBranches(t, e)
	old, oldRoots := e.seedComposerHost("acme", "web-02", "old.example.com")
	e.st.SetDetectedSiteRepos(t.Context(), old.ID, map[string]string{oldRoots[0]: "git@github.com:acme/app.git"})

	_, f, _, page := handoffFile(t, e, handoffURL("acme", "web-01", root, "")+"&target=each")
	if len(f.Sites) != 4 || f.Sites[2].Host != "web-02" || f.Sites[2].Branch != nil || strings.Join(f.Target.Branches, ",") != "dev,env/beta,main" {
		t.Errorf("sites %q, target %+v", siteKeys(f), f.Target)
	}
	if !strings.Contains(page, "branch unknown: not targeted") || !strings.Contains(html.UnescapeString(page), "1 site with an unknown branch isn't targeted") {
		t.Error("the unknown branch isn't shown as not targeted")
	}

	// No branches at all.
	e2 := handoffEnv(t, fd.agent("pr-bot", testBotID))
	host := e2.seedSites()
	asRole(e2, host.OrgID, store.RoleOperator)
	path := handoffURL("acme", "app-01", siteRoot, "")
	code, f, form, page := handoffFile(t, e2, path)
	if code != http.StatusOK || len(f.Sites) != 1 || f.Sites[0].Branch != nil || f.Target.Mode != "default" {
		t.Errorf("no branches: %d %+v", code, f.Sites)
	}
	if !strings.Contains(page, `value="each" disabled`) || !strings.Contains(html.UnescapeString(page), "No site's branch is known") {
		t.Error("each isn't disabled with no known branch")
	}
	form.Set("target", "each")
	if w := e2.post("/hosts/acme/app-01/handoff", form, signedIn(e2), origin(e2.baseURL)); w.Code != http.StatusBadRequest {
		t.Errorf("each with no branches: %d", w.Code)
	}
}

func TestSiteBranchForm(t *testing.T) {
	e := handoffEnv(t)
	host := e.seedSites()
	asRole(e, host.OrgID, store.RoleOperator)
	page := func() string {
		return html.UnescapeString(e.get(siteURL("acme", "app-01", siteRoot), signedIn(e)).Body.String())
	}
	if p := page(); !strings.Contains(p, "Unknown (no git checkout found, common with zero-downtime deploys)") || !strings.Contains(p, `action="/sites/branch"`) {
		t.Error("unknown branch not shown, or no form")
	}
	e.st.SetDetectedSiteBranches(t.Context(), host.ID, map[string]store.DetectedRef{siteRoot: {Commit: strings.Repeat("ab", 20)}})
	if p := page(); !strings.Contains(p, "detached at <code>abababababab</code>") {
		t.Error("detached HEAD not shown")
	}
	e.st.SetDetectedSiteBranches(t.Context(), host.ID, map[string]store.DetectedRef{siteRoot: {Branch: "dev"}})
	if p := page(); !strings.Contains(p, `<code class="path">dev</code>`) || !strings.Contains(p, "found by the collector in <code>.git/HEAD</code>") {
		t.Error("detected branch not shown")
	}
	post := func(branch string) string {
		w := e.post("/sites/branch", url.Values{"csrf": {auth.CSRFToken(goodToken)}, "org": {"acme"}, "host": {"app-01"},
			"root": {siteRoot}, "branch": {branch}}, signedIn(e), origin(e.baseURL))
		return w.Header().Get("Location")
	}
	if loc := post("env/beta"); !strings.Contains(loc, "branch=saved") {
		t.Fatalf("save: %s", loc)
	}
	if p := page(); !strings.Contains(p, `<code class="path">env/beta</code>`) || !strings.Contains(p, "set by an operator (the collector found <code>dev</code>)") {
		t.Error("manual branch not shown")
	}
	if loc := post("main; reboot"); !strings.Contains(loc, "branch=invalid") {
		t.Errorf("invalid: %s", loc)
	}
	if r, _ := e.st.SiteRepos(t.Context(), host.ID); r[siteRoot].Branch() != "env/beta" {
		t.Errorf("branch = %+v", r[siteRoot])
	}
	asRole(e, host.OrgID, store.RoleViewer)
	if w := e.post("/sites/branch", url.Values{"csrf": {auth.CSRFToken(goodToken)}, "org": {"acme"}, "host": {"app-01"},
		"root": {siteRoot}, "branch": {"x"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("viewer: %d", w.Code)
	}
	if strings.Contains(page(), `action="/sites/branch"`) {
		t.Error("viewer sees the branch form")
	}
}
