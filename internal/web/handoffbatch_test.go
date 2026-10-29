// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/ai"
	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

// One host, three sites on three repositories, and a step whose text
// names only one of them: the command lists all three, so all three get a
// button labelled by repository, plus "All 3".
func TestAIHandoffCommandSitesWin(t *testing.T) {
	const fix = "composer update livewire/livewire --with-dependencies"
	var sites []report.Site
	var findings []report.Finding
	repos := map[string]string{}
	for _, n := range []string{"a", "b", "c"} {
		root := "/home/app/" + n + ".example.com"
		sites = append(sites, report.Site{Root: root, ServerNames: []string{n + ".example.com"}})
		findings = append(findings, report.Finding{Site: root, Package: "livewire/livewire", Version: "3.5.0", Fixed: "3.6.4"})
		repos[root] = "https://github.com/acme/" + n
	}
	hosts := map[string]handoffHost{"web-01": {Org: "acme", Repos: repos, Labels: map[string]string{},
		Host: report.Host{Name: "web-01", Sites: sites, Findings: findings}}}
	view := &aiView{View: ai.View{Result: &ai.Result{Actions: []ai.Action{{Title: "Patch Livewire",
		Why: "c.example.com has the critical CVE. Run the Composer command in /home/app/c.example.com.", Hosts: []string{"web-01"},
		Commands: []ai.Command{{Hosts: []string{"web-01"}, Command: fix,
			Sites: map[string][]string{"web-01": {"a.example.com", "b.example.com", "c.example.com"}}}}}}}}}
	aiHandoffs(view, hosts)
	var got []string
	for _, l := range view.Handoffs[0] {
		got = append(got, l.Site)
	}
	if want := "acme/a|acme/b|acme/c"; strings.Join(got, "|") != want {
		t.Errorf("buttons %q, want %q", got, want)
	}
	all, ok := view.HandoffAll[0]
	if !ok || all.Site != "All 3" || !strings.HasPrefix(all.URL, "/handoff/batch?") {
		t.Fatalf("All button: %+v", all)
	}
	q, _ := url.ParseQuery(strings.TrimPrefix(all.URL, "/handoff/batch?"))
	if len(q["o"]) != 3 || len(q["h"]) != 3 || q["r"][2] != "/home/app/c.example.com" || q.Get("back") != "/" {
		t.Errorf("All button's query: %v", q)
	}

	// An old brief's command (no site list) is still narrowed by the text.
	view.Result.Actions[0].Commands[0].Sites = nil
	view.Handoffs, view.HandoffAll = nil, nil
	aiHandoffs(view, hosts)
	if l := view.Handoffs[0]; len(l) != 1 || l[0].Site != "acme/c" || view.HandoffAll != nil {
		t.Errorf("old brief: %+v", l)
	}
}

// batchEnv seeds acme with web-01 (two sites on two repositories) and
// web-02 (one site with none), and returns the batch page's path for all
// three.
func batchEnv(t *testing.T) (*env, *fakeDiscord, store.IngestHost, string) {
	t.Helper()
	fd := newFakeDiscord(t)
	e := handoffEnv(t, fd.agent("pr-bot", testBotID))
	web1, r1 := e.seedComposerHost("acme", "web-01", "a.example.com", "b.example.com")
	_, r2 := e.seedComposerHost("acme", "web-02", "c.example.com")
	if err := e.st.SetDetectedSiteRepos(t.Context(), web1.ID, map[string]string{r1[0]: "https://github.com/acme/a", r1[1]: "https://github.com/acme/b"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetSiteBranch(t.Context(), "test", web1.ID, r1[1], "dev"); err != nil {
		t.Fatal(err)
	}
	asRole(e, web1.OrgID, store.RoleOperator)
	q := url.Values{"back": {"/"}}
	for _, s := range [][2]string{{"web-01", r1[0]}, {"web-01", r1[1]}, {"web-02", r2[0]}} {
		q.Add("o", "acme")
		q.Add("h", s[0])
		q.Add("r", s[1])
	}
	return e, fd, web1, "/handoff/batch?" + q.Encode()
}

var hiddenRe = regexp.MustCompile(`<input type="hidden" name="([a-z_]+)" value="([^"]*)">`)

// batchForm reads the batch confirm page's send form.
func batchForm(t *testing.T, page string) url.Values {
	t.Helper()
	f := url.Values{"csrf": {auth.CSRFToken(goodToken)}, "agent": {"pr-bot"}, "back": {"/"}}
	form := page[strings.Index(page, `class="actions handoff-send"`):]
	form = form[:strings.Index(form, "</form>")]
	for _, m := range hiddenRe.FindAllStringSubmatch(form, -1) {
		if m[1] != "csrf" && m[1] != "agent" && m[1] != "back" {
			f.Add(m[1], html.UnescapeString(m[2]))
		}
	}
	return f
}

func TestHandoffBatch(t *testing.T) {
	e, fd, web1, path := batchEnv(t)
	w := e.get(path, signedIn(e))
	page := html.UnescapeString(w.Body.String())
	if w.Code != http.StatusOK || !strings.Contains(page, "3 repositories") || strings.Count(page, `<section class="handoff-item`) != 3 ||
		!strings.Contains(page, "acme/a") || !strings.Contains(page, "acme/b") || !strings.Contains(page, "web-02 · c.example.com") ||
		!strings.Contains(page, "Post 3 to Discord") {
		t.Fatalf("batch page: %d\n%s", w.Code, page)
	}
	f := batchForm(t, page)
	if len(f["request_id"]) != 3 || len(f["digest"]) != 3 || len(f["o"]) != 3 || f.Get("target") != "default" {
		t.Fatalf("form: %v", f)
	}

	// A changed digest sends nothing.
	bad := url.Values{}
	for k, v := range f {
		bad[k] = append([]string(nil), v...)
	}
	bad["digest"][1] = strings.Repeat("0", 64)
	if w := e.post("/handoff/batch", bad, signedIn(e), origin(e.baseURL)); w.Code != http.StatusConflict || len(fd.sent()) != 0 {
		t.Fatalf("changed digest: %d, %d posted", w.Code, len(fd.sent()))
	}

	w = e.post("/handoff/batch", f, signedIn(e), origin(e.baseURL))
	res := html.UnescapeString(w.Body.String())
	if w.Code != http.StatusOK || !strings.Contains(res, "Posted 3 of 3.") || len(fd.sent()) != 3 {
		t.Fatalf("send: %d, %d posted\n%s", w.Code, len(fd.sent()), res)
	}
	// Each is the message its own button sends.
	for i, b := range fd.sent() {
		if c, _ := b["content"].(string); !strings.Contains(c, "<@"+testBotID+">") {
			t.Errorf("message %d: %q", i, c)
		}
	}
	rows, err := e.st.AuditFrom(t.Context(), "192.0.2.1", true, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rows {
		if r.Action == "handoff.send" && r.OrgID == web1.OrgID {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d handoff.send entries, want 3: %+v", n, rows)
	}

	// Sent again right away: each is held by its rate limit.
	f2 := batchForm(t, html.UnescapeString(e.get(path, signedIn(e)).Body.String()))
	w = e.post("/handoff/batch", f2, signedIn(e), origin(e.baseURL))
	if res := html.UnescapeString(w.Body.String()); !strings.Contains(res, "Posted 0 of 3.") || !strings.Contains(res, "3 skipped") || len(fd.sent()) != 3 {
		t.Errorf("again: %d posted\n%s", len(fd.sent()), res)
	}
}

func TestHandoffBatchTargetAndChecks(t *testing.T) {
	e, _, web1, path := batchEnv(t)
	// Each branch: acme/b's site is on dev, so it targets dev; the others
	// have no known branch and stay on their default branch.
	page := html.UnescapeString(e.get(path+"&target=each", signedIn(e)).Body.String())
	if !strings.Contains(page, "its own pull request, against dev") || strings.Count(page, " · each branch") != 1 {
		t.Errorf("each branch:\n%s", page)
	}

	for name, p := range map[string]string{
		"no sites":       "/handoff/batch",
		"uneven":         "/handoff/batch?o=acme&h=web-01",
		"unknown host":   "/handoff/batch?o=acme&h=web-09&r=%2Fvar%2Fwww%2Fa.example.com",
		"other org":      "/handoff/batch?o=other&h=web-01&r=%2Fvar%2Fwww%2Fa.example.com",
		"unknown site":   "/handoff/batch?o=acme&h=web-01&r=%2Fnope",
		"too many sites": "/handoff/batch?" + strings.Repeat("o=acme&h=web-01&r=%2Fvar%2Fwww%2Fa.example.com&", handoffBatchMax+1),
	} {
		if w := e.get(p, signedIn(e)); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", name, w.Code)
		}
	}
	// A viewer can't hand off, so the page isn't there.
	asRole(e, web1.OrgID, store.RoleViewer)
	if w := e.get(path, signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("viewer: %d", w.Code)
	}
	// Two sites on one repository are one hand-off.
	asRole(e, web1.OrgID, store.RoleOperator)
	if err := e.st.SetSiteRepo(t.Context(), "test", web1.ID, "/var/www/b.example.com", "https://github.com/acme/a"); err != nil {
		t.Fatal(err)
	}
	page = html.UnescapeString(e.get(path, signedIn(e)).Body.String())
	if n := strings.Count(page, `<section class="handoff-item`); n != 2 || !strings.Contains(page, "Post 2 to Discord") {
		t.Errorf("same repository twice: %d items\n%s", n, page)
	}
}
