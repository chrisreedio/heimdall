// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"html"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/ai"
	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/handoff"
	"github.com/chrisreedio/heimdall/internal/notify"
	"github.com/chrisreedio/heimdall/internal/store"
)

const testBotID = "123456789012345678"

// fakeDiscord is an httptest server standing in for discord.com: it
// records every webhook body and answers with status.
type fakeDiscord struct {
	mu     sync.Mutex
	bodies []map[string]any
	paths  []string
	status int
	srv    *httptest.Server
}

func newFakeDiscord(t *testing.T) *fakeDiscord {
	f := &fakeDiscord{status: http.StatusNoContent}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt == "multipart/form-data" {
			// payload_json plus files[0], recorded as "_file" and "_filename".
			if err := r.ParseMultipartForm(1 << 20); err == nil {
				json.Unmarshal([]byte(r.FormValue("payload_json")), &m)
				if fh := r.MultipartForm.File["files[0]"]; len(fh) == 1 {
					fr, _ := fh[0].Open()
					b, _ := io.ReadAll(fr)
					m["_file"], m["_filename"] = string(b), fh[0].Filename
				}
			}
		} else {
			b, _ := io.ReadAll(r.Body)
			json.Unmarshal(b, &m)
		}
		f.mu.Lock()
		f.bodies, f.paths = append(f.bodies, m), append(f.paths, r.URL.Path)
		status := f.status
		f.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// agent posts through notify.Discord, as the hub does, with the client
// pointed at the fake instead of discord.com.
func (f *fakeDiscord) agent(name, id string) handoff.Agent {
	u, _ := url.Parse(f.srv.URL)
	tr := roundTrip(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		if r.URL.Host != notify.DiscordHost {
			panic("posting somewhere other than discord.com: " + r.URL.Host)
		}
		r.URL.Scheme, r.URL.Host = u.Scheme, u.Host
		return http.DefaultTransport.RoundTrip(r)
	})
	return handoff.Agent{Name: name, UserID: id, Poster: &notify.Discord{Label: "discord:agents",
		URL:    "https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz",
		Client: &http.Client{Transport: tr}, Retry: notify.Retry{Attempts: 1}}}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (f *fakeDiscord) sent() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.bodies...)
}

func handoffEnv(t *testing.T, agents ...handoff.Agent) *env {
	return newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.Agents = agents })
}

func asRole(e *env, orgID int64, role store.Role) {
	e.auth.viewer = &auth.Viewer{UserID: 7, DisplayName: "Jane <@&1> Operator", SessionToken: goodToken,
		Scope: store.Scope{Orgs: map[int64]store.Role{orgID: role}}}
}

var (
	digestRe    = regexp.MustCompile(`name="digest" value="([0-9a-f]{64})"`)
	requestIDRe = regexp.MustCompile(`name="request_id" value="([0-9a-f]{16})"`)
	msgRe       = regexp.MustCompile(`(?s)<pre class="handoff-msg" id="handoff-msg">(.*?)</pre>`)
)

// confirm opens the confirm page and returns its form, ready to send.
func confirm(t *testing.T, e *env, agent string) (url.Values, string) {
	t.Helper()
	path := handoffURL("acme", "app-01", siteRoot, agent)
	w := e.get(path, signedIn(e))
	if w.Code != http.StatusOK {
		t.Fatalf("confirm page: %d", w.Code)
	}
	page := w.Body.String()
	d, id, m := digestRe.FindStringSubmatch(page), requestIDRe.FindStringSubmatch(page), msgRe.FindStringSubmatch(page)
	if d == nil || id == nil || m == nil {
		t.Fatalf("confirm page lacks the form or message:\n%s", page)
	}
	return url.Values{"csrf": {auth.CSRFToken(goodToken)}, "root": {siteRoot}, "agent": {agent},
		"request_id": {id[1]}, "digest": {d[1]}}, html.UnescapeString(m[1])
}

func TestHandoffOffWithoutAgents(t *testing.T) {
	e := handoffEnv(t)
	e.seedSites()
	if page := e.get(siteURL("acme", "app-01", siteRoot), signedIn(e)).Body.String(); strings.Contains(page, "Hand off") {
		t.Error("button shown with no agents configured")
	}
	if page := e.get("/hosts/acme/app-01", signedIn(e)).Body.String(); strings.Contains(page, "Hand off") {
		t.Error("host page button shown with no agents configured")
	}
	if w := e.get(handoffURL("acme", "app-01", siteRoot, ""), signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("confirm page with no agents: %d", w.Code)
	}
}

func TestHandoffSend(t *testing.T) {
	fd := newFakeDiscord(t)
	e := handoffEnv(t, fd.agent("pr-bot", testBotID), fd.agent("other-bot", "98765432109876543"))
	host := e.seedSites()
	asRole(e, host.OrgID, store.RoleOperator)

	page := e.get(siteURL("acme", "app-01", siteRoot), signedIn(e)).Body.String()
	if !strings.Contains(page, ">Hand off to agent</a>") || strings.Contains(page, "pr-bot") {
		t.Error("the site page's button should say \"Hand off to agent\", never the agent's name")
	}
	form, shown := confirm(t, e, "pr-bot")
	cp := e.get(handoffURL("acme", "app-01", siteRoot, "pr-bot"), signedIn(e)).Body.String()
	for _, want := range []string{`<select name="agent"`, `<option value="other-bot">`, "What this shares", "repo unknown",
		"Who it pings:</strong> only pr-bot"} {
		if !strings.Contains(cp, want) {
			t.Errorf("confirm page lacks %q", want)
		}
	}

	// CSRF and Origin are required.
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("csrf", "nope")
	if w := e.post("/hosts/acme/app-01/handoff", bad, signedIn(e), origin(e.baseURL)); w.Code != http.StatusForbidden {
		t.Errorf("bad CSRF: %d", w.Code)
	}
	if w := e.post("/hosts/acme/app-01/handoff", form, signedIn(e), origin("https://evil.example")); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin: %d", w.Code)
	}
	// A message that differs from the one shown isn't sent.
	bad = url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("digest", strings.Repeat("0", 64))
	if w := e.post("/hosts/acme/app-01/handoff", bad, signedIn(e), origin(e.baseURL)); w.Code != http.StatusConflict {
		t.Errorf("changed message: %d", w.Code)
	}
	if len(fd.sent()) != 0 {
		t.Fatal("posted before a valid confirm")
	}

	w := e.post("/hosts/acme/app-01/handoff", form, signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusSeeOther || !strings.HasSuffix(w.Header().Get("Location"), "&handoff=sent") {
		t.Fatalf("send: %d %s", w.Code, w.Header().Get("Location"))
	}
	sent := fd.sent()
	if len(sent) != 1 {
		t.Fatalf("posted %d messages", len(sent))
	}
	msg := sent[0]
	if msg["content"] != shown {
		t.Errorf("posted message differs from the one shown:\n%q\n%q", msg["content"], shown)
	}
	am, _ := json.Marshal(msg["allowed_mentions"])
	if string(am) != `{"parse":[],"users":["`+testBotID+`"]}` {
		t.Errorf("allowed_mentions = %s", am)
	}
	content, _ := msg["content"].(string)
	for _, want := range []string{"<@" + testBotID + ">", `"laravel/framework"`, `"fixed": "11.44.1"`, `"GHSA-test-0000-0001"`,
		`"repo": null`, "**Repo unknown:**", `"link": "http://127.0.0.1:8080/hosts/acme/app-01/site?root=%2Fhome%2Fforge%2Fexample.com"`,
		`"command": "composer update laravel/framework --with-dependencies"`} {
		if !strings.Contains(content, want) {
			t.Errorf("message lacks %q:\n%s", want, content)
		}
	}
	// The whole request rides along as a file, the same one the confirm
	// page showed, listed in attachments.
	file, _ := msg["_file"].(string)
	if msg["_filename"] != "heimdall-handoff-"+form.Get("request_id")+".json" || !strings.Contains(cp, "Attached file: <code>heimdall-handoff-") {
		t.Errorf("attachment name %v", msg["_filename"])
	}
	att, _ := json.Marshal(msg["attachments"])
	if !strings.Contains(string(att), `"filename":"heimdall-handoff-`+form.Get("request_id")+`.json"`) || !strings.Contains(string(att), `"id":0`) {
		t.Errorf("attachments = %s", att)
	}
	var fdata handoff.FileData
	if err := json.Unmarshal([]byte(file), &fdata); err != nil || fdata.Format != handoff.FileFormat || len(fdata.Packages) == 0 ||
		len(fdata.Advisories) == 0 || fdata.Advisories[0].URL != "https://github.com/advisories/GHSA-test-0000-0001" || len(fdata.Steps) == 0 {
		t.Errorf("attached file (%v): %s", err, file)
	}
	if strings.Contains(file, "<@&1>") || strings.Contains(file, "onerror") {
		t.Errorf("display name or advisory text reached the file unescaped: %s", file)
	}
	if strings.Contains(content, "<@&1>") || strings.Contains(content, "onerror") {
		t.Errorf("display name or advisory text reached the message unescaped: %s", content)
	}
	if at, _ := e.st.LastAuditAt(t.Context(), "handoff.send"); at.IsZero() {
		t.Error("handoff.send not audited")
	}

	// Rate limited per site and agent; another agent isn't held up.
	form2, _ := confirm(t, e, "pr-bot")
	if w := e.post("/hosts/acme/app-01/handoff", form2, signedIn(e), origin(e.baseURL)); w.Code != http.StatusTooManyRequests {
		t.Errorf("second send: %d", w.Code)
	}
	form3, _ := confirm(t, e, "other-bot")
	if w := e.post("/hosts/acme/app-01/handoff", form3, signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Errorf("other agent: %d", w.Code)
	}
	if n := len(fd.sent()); n != 2 {
		t.Errorf("posted %d messages, want 2", n)
	}
}

func TestHandoffRoles(t *testing.T) {
	fd := newFakeDiscord(t)
	e := handoffEnv(t, fd.agent("pr-bot", testBotID))
	host := e.seedSites()
	asRole(e, host.OrgID, store.RoleViewer)
	if page := e.get(siteURL("acme", "app-01", siteRoot), signedIn(e)).Body.String(); strings.Contains(page, "Hand off") || strings.Contains(page, `action="/sites/repo"`) {
		t.Error("viewer sees the hand-off button or the repository form")
	}
	if w := e.get(handoffURL("acme", "app-01", siteRoot, ""), signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("viewer confirm page: %d", w.Code)
	}
	f := url.Values{"csrf": {auth.CSRFToken(goodToken)}, "root": {siteRoot}, "agent": {"pr-bot"},
		"request_id": {"0123456789abcdef"}, "digest": {strings.Repeat("0", 64)}}
	if w := e.post("/hosts/acme/app-01/handoff", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("viewer send: %d", w.Code)
	}
	// Another org's operator: same 404 as a missing host.
	asRole(e, host.OrgID+100, store.RoleAdmin)
	if w := e.get(handoffURL("acme", "app-01", siteRoot, ""), signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("out of scope: %d", w.Code)
	}
	asRole(e, host.OrgID, store.RoleOperator)
	for _, path := range []string{handoffURL("acme", "app-01", siteRoot, "nobody"), handoffURL("acme", "app-01", "/not/a/site", ""),
		handoffURL("acme", "nope", siteRoot, "")} {
		if w := e.get(path, signedIn(e)); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
	if len(fd.sent()) != 0 {
		t.Error("something was posted")
	}
}

func TestHandoffDiscordFailure(t *testing.T) {
	fd := newFakeDiscord(t)
	fd.status = http.StatusNotFound // a deleted webhook
	e := handoffEnv(t, fd.agent("pr-bot", testBotID))
	host := e.seedSites()
	asRole(e, host.OrgID, store.RoleOperator)
	form, _ := confirm(t, e, "pr-bot")
	w := e.post("/hosts/acme/app-01/handoff", form, signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusSeeOther || !strings.HasSuffix(w.Header().Get("Location"), "&handoff=failed") {
		t.Fatalf("send: %d %s", w.Code, w.Header().Get("Location"))
	}
	page := e.get(w.Header().Get("Location"), signedIn(e)).Body.String()
	if !strings.Contains(page, "post the hand-off to Discord") {
		t.Error("no failure notice")
	}
}

func TestSiteRepoForm(t *testing.T) {
	e := handoffEnv(t)
	host := e.seedSites()
	asRole(e, host.OrgID, store.RoleOperator)
	post := func(repo string) *httptest.ResponseRecorder {
		return e.post("/sites/repo", url.Values{"csrf": {auth.CSRFToken(goodToken)}, "org": {"acme"}, "host": {"app-01"},
			"root": {siteRoot}, "repo": {repo}}, signedIn(e), origin(e.baseURL))
	}
	if w := post("https://user:ghp_SECRET@github.com/acme/example.com.git"); w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "repo=saved") {
		t.Fatalf("save: %d %s", w.Code, w.Header().Get("Location"))
	}
	page := e.get(siteURL("acme", "app-01", siteRoot), signedIn(e)).Body.String()
	if !strings.Contains(page, `href="https://github.com/acme/example.com"`) || strings.Contains(page, "SECRET") {
		t.Errorf("site page repository:\n%s", page)
	}
	if hp := e.get("/hosts/acme/app-01", signedIn(e)).Body.String(); !strings.Contains(hp, `href="https://github.com/acme/example.com"`) {
		t.Error("host page site card lacks the repository link")
	}
	if w := post("file:///etc/passwd"); !strings.Contains(w.Header().Get("Location"), "repo=invalid") {
		t.Errorf("invalid: %s", w.Header().Get("Location"))
	}
	asRole(e, host.OrgID, store.RoleViewer)
	if w := post("https://github.com/evil/x"); w.Code != http.StatusNotFound {
		t.Errorf("viewer: %d", w.Code)
	}
	if r, _ := e.st.SiteRepos(t.Context(), host.ID); r[siteRoot].Repo() != "https://github.com/acme/example.com" {
		t.Errorf("repo = %+v", r)
	}
}

// AI plan steps get a hand-off button only when they're a Composer
// update for one of the host's sites; OS patching and reboots never do.
func TestHandoffOnAIPlan(t *testing.T) {
	fd := newFakeDiscord(t)
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.Agents = []handoff.Agent{fd.agent("pr-bot", testBotID)}
		c.AI = &fakeAI{}
	})
	host := e.seedSites()
	storeRun(t, e.st, host.OrgID, host.ID, ai.Result{Summary: "x", Actions: []ai.Action{
		{Title: "Patch the OS", Why: "x", Host: "app-01", Command: "sudo apt-get install --only-upgrade libssl3"},
		{Title: "Update Laravel", Why: "x", Host: "app-01", Command: "composer update laravel/framework --with-dependencies"},
		{Title: "Reboot", Why: "x", Host: "app-01", Command: "sudo reboot"},
	}}, testNow.Add(-time.Hour))
	page := e.get("/hosts/acme/app-01", signedIn(e)).Body.String()
	if n := strings.Count(page, `class="ai-handoff"`); n != 1 {
		t.Fatalf("%d AI steps have a hand-off button, want 1", n)
	}
	step := page[strings.Index(page, "<strong>Update Laravel</strong>"):]
	if j, end := strings.Index(step, `class="ai-handoff"`), strings.Index(step, "</li>"); j < 0 || j > end {
		t.Error("the button isn't on the Composer step")
	}
	asRole(e, host.OrgID, store.RoleViewer)
	if page := e.get("/hosts/acme/app-01", signedIn(e)).Body.String(); strings.Contains(page, `class="ai-handoff"`) {
		t.Error("viewer sees the AI step's hand-off button")
	}
}
