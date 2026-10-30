// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

// Acting from the phone: Defense approves and dismisses ban proposals,
// with the same actions, roles and audit as /bans.

func TestDefenseBanCards(t *testing.T) {
	t.Parallel()
	e, _, _, mine, theirs := newBansEnv(t)
	ctx := t.Context()
	b := e.get("/defense", signedIn(e)).Body.String()
	for _, want := range []string{`id="ban-` + strconv.FormatInt(mine, 10) + `"`, `id="ban-` + strconv.FormatInt(theirs, 10) + `"`,
		"203.0.113.66", "for <strong>7 days</strong>", "203.0.113.0/24", "app-01", "nothing known", "score 13.2",
		`action="/bans/` + strconv.FormatInt(mine, 10) + `/approve"`, `action="/bans/` + strconv.FormatInt(mine, 10) + `/reject"`,
		`<input type="hidden" name="back" value="/defense">`, ">Approve</button>", ">Dismiss</button>", "No bans in force."} {
		if !strings.Contains(b, want) {
			t.Errorf("Defense lacks %s", want)
		}
	}

	// Approve: back to Defense at the ban, which is now in force.
	path := "/bans/" + strconv.FormatInt(mine, 10) + "/approve"
	if w := e.post(path, csrfForm("back", "/defense"), signedIn(e)); w.Code != http.StatusForbidden {
		t.Errorf("no Origin: %d", w.Code)
	}
	if w := e.post(path, url.Values{"back": {"/defense"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusForbidden {
		t.Errorf("no CSRF: %d", w.Code)
	}
	w := e.post(path, csrfForm("back", "/defense"), signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/defense?done=approve#ban-"+strconv.FormatInt(mine, 10) {
		t.Fatalf("approve: %d %s", w.Code, w.Header().Get("Location"))
	}
	if b, _ := e.st.BanByID(ctx, mine); b.Status != store.BanPending || b.DecidedBy != "user:1" {
		t.Errorf("after approve: %s by %s", b.Status, b.DecidedBy)
	}
	b = e.get("/defense?done=approve", signedIn(e)).Body.String()
	active, _, _ := strings.Cut(b[strings.Index(b, "Bans in force"):], "Repeat offenders")
	if !strings.Contains(b, "Approved: it goes to Cloudflare") || !strings.Contains(active, `<li id="ban-`+strconv.FormatInt(mine, 10)+`">`) ||
		!strings.Contains(active, "7 days once written") {
		t.Error("the approved ban isn't listed in force")
	}

	// Dismiss is /bans's reject.
	w = e.post("/bans/"+strconv.FormatInt(theirs, 10)+"/reject", csrfForm("back", "/defense"), signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/defense?done=reject#ban-"+strconv.FormatInt(theirs, 10) {
		t.Fatalf("dismiss: %d %s", w.Code, w.Header().Get("Location"))
	}
	if b, _ := e.st.BanByID(ctx, theirs); b.Status != store.BanRejected {
		t.Errorf("after dismiss: %s", b.Status)
	}
	if !strings.Contains(e.get("/defense?done=reject", signedIn(e)).Body.String(), "Dismissed.") {
		t.Error("no Dismissed notice")
	}
	audits, _ := e.st.BanAudits(ctx, 50)
	seen := map[string]bool{}
	for _, a := range audits {
		seen[a.Action+":"+a.Actor] = true
	}
	if !seen["approve:user:1"] || !seen["reject:user:1"] {
		t.Errorf("ban audit: %v", seen)
	}
	// A "back" that isn't Defense goes to /bans, as before.
	e2, _, _, id, _ := newBansEnv(t)
	if w := e2.post("/bans/"+strconv.FormatInt(id, 10)+"/approve", csrfForm("back", "https://evil.example.com/"), signedIn(e2), origin(e2.baseURL)); !strings.HasPrefix(w.Header().Get("Location"), "/bans?done=approve") {
		t.Errorf("foreign back: %s", w.Header().Get("Location"))
	}
}

func TestDefenseRoles(t *testing.T) {
	t.Parallel()
	e, acme, _, mine, theirs := newBansEnv(t)
	// An operator in acme decides acme's proposal, and doesn't see the other org's.
	e.auth.viewer = &auth.Viewer{UserID: 2, Kind: "local", SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleOperator}}}
	b := e.get("/defense", signedIn(e)).Body.String()
	if !strings.Contains(b, `id="ban-`+strconv.FormatInt(mine, 10)+`"`) || strings.Contains(b, "203.0.113.77") {
		t.Error("operator's Defense is wrong")
	}
	if w := e.post("/bans/"+strconv.FormatInt(theirs, 10)+"/reject", csrfForm("back", "/defense"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("other org's: %d", w.Code)
	}
	if w := e.post("/bans/"+strconv.FormatInt(mine, 10)+"/reject", csrfForm("back", "/defense"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Errorf("operator dismiss: %d", w.Code)
	}
	// A viewer sees no proposals and can't act.
	e, acme, _, mine, _ = newBansEnv(t)
	e.auth.viewer = &auth.Viewer{UserID: 3, Kind: "local", SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleViewer}}}
	if b := e.get("/defense", signedIn(e)).Body.String(); strings.Contains(b, "Ban proposals waiting") || strings.Contains(b, "203.0.113.66") {
		t.Error("a viewer sees ban proposals")
	}
	if w := e.post("/bans/"+strconv.FormatInt(mine, 10)+"/approve", csrfForm("back", "/defense"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("viewer approve: %d", w.Code)
	}
	if b, _ := e.st.BanByID(t.Context(), mine); b.Status != store.BanProposed {
		t.Errorf("viewer changed it: %s", b.Status)
	}
}

// Alerts: Acknowledge and Mute on each open anomaly the viewer may triage.
func TestAlertsAcknowledge(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	host := e.seed()
	e.st.CreateLocalUser(t.Context(), "test", "admin@example.com", "", true, "$argon2id$x", []byte("secretsecretsecret12"))
	for _, rule := range []string{"package_change", "unexpected_reboot"} {
		if _, err := e.st.AddAnomaly(t.Context(), host.ID, 0, store.Anomaly{Rule: rule, Severity: "medium", Summary: rule + " seen"}, testNow); err != nil {
			t.Fatal(err)
		}
	}
	b := e.get("/alerts", signedIn(e)).Body.String()
	for _, want := range []string{`id="anomaly-1"`, `action="/anomalies/1/ack"`, `action="/anomalies/2/suppress"`,
		`<input type="hidden" name="back" value="/alerts">`, ">Acknowledge</button>", "Mute this signal on web-01"} {
		if !strings.Contains(b, want) {
			t.Errorf("Alerts lacks %s", want)
		}
	}
	if w := e.post("/anomalies/1/ack", url.Values{"note": {"x"}, "back": {"/alerts"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusForbidden {
		t.Errorf("no CSRF: %d", w.Code)
	}
	w := e.post("/anomalies/1/ack", csrfForm("note", "our deploy", "back", "/alerts"), signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/alerts?done=ack" {
		t.Fatalf("ack: %d %s", w.Code, w.Header().Get("Location"))
	}
	w = e.post("/anomalies/2/suppress", csrfForm("note", "runs Livepatch", "back", "/alerts", "rule", "unexpected_reboot", "days", "7"), signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/alerts?done=suppress" {
		t.Fatalf("mute: %d %s", w.Code, w.Header().Get("Location"))
	}
	b = e.get("/alerts?done=ack", signedIn(e)).Body.String()
	if !strings.Contains(b, "Acknowledged.") || strings.Contains(b, "/anomalies/1/ack") || strings.Contains(b, "/anomalies/2/ack") {
		t.Error("acknowledged anomalies still listed")
	}
	if !auditHas(t, e, "anomaly.ack") || !auditHas(t, e, "anomaly.suppress") {
		t.Error("not audited")
	}

	// A viewer sees the alert but no form, and can't acknowledge.
	e.st.AddAnomaly(t.Context(), host.ID, 0, store.Anomaly{Rule: "package_change", Severity: "high", Summary: "again"}, testNow)
	e.auth.viewer = &auth.Viewer{UserID: 2, Kind: "local", SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{host.OrgID: store.RoleViewer}}}
	b = e.get("/alerts", signedIn(e)).Body.String()
	if !strings.Contains(b, `id="anomaly-3"`) || strings.Contains(b, "/anomalies/3/ack") {
		t.Error("viewer's Alerts is wrong")
	}
	if w := e.post("/anomalies/3/ack", csrfForm("note", "x", "back", "/alerts"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusForbidden {
		t.Errorf("viewer ack: %d", w.Code)
	}
}

// The desktop sidebar links Alerts and Defense (tabs on phones, so hidden
// on More) and the Security settings, for admins.
func TestSidebarLinks(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seed()
	b := e.get("/hosts", signedIn(e)).Body.String()
	side := b[strings.Index(b, `<aside class="side">`):strings.Index(b, "</aside>")]
	for _, want := range []string{`<a href="/alerts" class="side-item tabbed" title="Alerts">`, `<a href="/defense" class="side-item tabbed" title="Defense">`,
		`<a href="/admin/security" class="side-item" title="Security">`} {
		if !strings.Contains(side, want) {
			t.Errorf("sidebar lacks %s", want)
		}
	}
	if strings.Index(side, `href="/alerts"`) > strings.Index(side, `href="/anomalies"`) {
		t.Error("Alerts should lead the Security section")
	}
	if !strings.Contains(e.get("/alerts", signedIn(e)).Body.String(), `<a href="/alerts" class="side-item tabbed" title="Alerts" aria-current="page">`) {
		t.Error("Alerts isn't marked current on its page")
	}
	e.auth.viewer = &auth.Viewer{UserID: 2, Kind: "local", SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{1: store.RoleViewer}}}
	if b := e.get("/hosts", signedIn(e)).Body.String(); strings.Contains(b, `href="/admin/security"`) || !strings.Contains(b, `href="/defense"`) {
		t.Error("a viewer's sidebar is wrong")
	}
}

// ── Step-up codes ──────────────────────────────────────────────────────────

// setStepUp saves the step-up setting as an admin would, and returns the
// response's status.
func (e *env) setStepUp(mode string) int {
	e.t.Helper()
	return e.post("/admin/security", csrfForm("stepup", mode), signedIn(e), origin(e.baseURL)).Code
}

func TestStepUpOff(t *testing.T) {
	t.Parallel()
	e := adminEnv(t)
	if b := e.get("/admin/security", signedIn(e)).Body.String(); !strings.Contains(b, `value="off" checked`) || strings.Contains(b, "data-stepup") {
		t.Error("step-up isn't off by default")
	}
	if w := e.post("/admin/branding/name", csrfForm("name", "Acme"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Errorf("off: an admin action was stopped: %d", w.Code)
	}
	if w := e.post("/admin/security", csrfForm("stepup", "always"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusBadRequest {
		t.Errorf("unknown setting: %d", w.Code)
	}
}

func TestStepUpAdminOnly(t *testing.T) {
	t.Parallel()
	e, acme, _, mine, _ := newBansEnv(t)
	ctx := t.Context()
	if code := e.setStepUp("admin"); code != http.StatusSeeOther {
		t.Fatalf("save: %d", code)
	}
	if !auditHas(t, e, "setting.stepup") {
		t.Error("the setting isn't audited")
	}
	if v, _, _ := e.st.Setting(ctx, "stepup"); v != "admin" {
		t.Errorf("stored %q", v)
	}

	// An admin action asks: the prompt keeps the form, and nothing is saved.
	w := e.post("/admin/branding/name", csrfForm("name", "Acme Ops"), signedIn(e), origin(e.baseURL),
		func(r *http.Request) { r.Header.Set("Referer", e.baseURL+"/admin/branding") })
	b := w.Body.String()
	if w.Code != http.StatusUnauthorized || !strings.Contains(b, "Confirm it&#39;s you") || !strings.Contains(b, `<form method="post" action="/admin/branding/name"`) ||
		!strings.Contains(b, `<input type="hidden" name="name" value="Acme Ops">`) || !strings.Contains(b, `name="stepup_code"`) ||
		!strings.Contains(b, `href="/admin/branding">Cancel`) {
		t.Fatalf("prompt: %d\n%s", w.Code, b)
	}
	if br, _ := e.st.Branding(ctx); br.Name != "" {
		t.Fatal("saved without a code")
	}
	// Pages tell app.js which actions need a code.
	if b := e.get("/bans", signedIn(e)).Body.String(); !strings.Contains(b, `data-stepup="/admin/ /cloudflare/lists"`) || !strings.Contains(b, `<dialog class="stepup-dialog"`) {
		t.Error("no step-up dialog on the page")
	}
	// A ban isn't an admin action.
	if w := e.post("/bans/"+strconv.FormatInt(mine, 10)+"/approve", csrfForm(), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Errorf("admin-only asked for a ban: %d", w.Code)
	}
	// A wrong code asks again, with why.
	w = e.post("/admin/branding/name", csrfForm("name", "Acme Ops", stepUpField, "111111"), signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "That code didn&#39;t work") {
		t.Errorf("wrong code: %d", w.Code)
	}
	// The code, with the form: saved.
	if w := e.post("/admin/branding/name", csrfForm("name", "Acme Ops", stepUpField, "246810"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("with a code: %d %s", w.Code, w.Body.String())
	}
	if br, _ := e.st.Branding(ctx); br.Name != "Acme Ops" {
		t.Errorf("name %q", br.Name)
	}
	// Fresh for 5 minutes: no prompt, no dialog.
	e.clock.add(4 * time.Minute)
	if w := e.post("/admin/branding/name", csrfForm("name", "Acme"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Errorf("inside the window: %d", w.Code)
	}
	if strings.Contains(e.get("/bans", signedIn(e)).Body.String(), "data-stepup") {
		t.Error("dialog while fresh")
	}
	// Stale: asked again, and a code that was used is refused.
	e.clock.add(2 * time.Minute)
	if w := e.post("/admin/branding/name", csrfForm("name", "Other"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusUnauthorized {
		t.Errorf("stale: %d", w.Code)
	}
	if w := e.post("/admin/branding/name", csrfForm("name", "Other", stepUpField, "246810"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusUnauthorized ||
		!strings.Contains(w.Body.String(), "already used") {
		t.Errorf("replayed: %d", w.Code)
	}
	if br, _ := e.st.Branding(ctx); br.Name != "Acme" {
		t.Errorf("name %q", br.Name)
	}
	// Changing the setting is an admin action too.
	if code := e.setStepUp("off"); code != http.StatusUnauthorized {
		t.Errorf("turning it off without a code: %d", code)
	}
	// Non-admins aren't asked: their admin POSTs end as not found.
	e.auth.viewer = &auth.Viewer{UserID: 2, Kind: "local", SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleOperator}}}
	if w := e.post("/admin/branding/name", csrfForm("name", "x"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("non-admin: %d", w.Code)
	}
}

func TestStepUpEveryAction(t *testing.T) {
	t.Parallel()
	e, acme, _, mine, theirs := newBansEnv(t)
	ctx := t.Context()
	e.setStepUp("every")
	path := "/bans/" + strconv.FormatInt(mine, 10) + "/approve"
	w := e.post(path, csrfForm("back", "/defense"), signedIn(e), origin(e.baseURL))
	if b := w.Body.String(); w.Code != http.StatusUnauthorized || !strings.Contains(b, "Approving a ban needs the code") ||
		!strings.Contains(b, `<input type="hidden" name="back" value="/defense">`) {
		t.Fatalf("ban prompt: %d", w.Code)
	}
	if b, _ := e.st.BanByID(ctx, mine); b.Status != store.BanProposed {
		t.Fatal("approved without a code")
	}
	// The prompt's form, sent with a code, carries the action out.
	w = e.post(path, csrfForm("back", "/defense", stepUpField, "246810"), signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/defense?done=approve") {
		t.Fatalf("with a code: %d %s", w.Code, w.Header().Get("Location"))
	}
	// ...and the next one, a minute later, doesn't ask.
	e.clock.add(time.Minute)
	if w := e.post("/bans/"+strconv.FormatInt(theirs, 10)+"/reject", csrfForm(), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Errorf("second action: %d", w.Code)
	}
	// An operator is asked for bans too, and the page's dialog covers them.
	e.clock.add(10 * time.Minute)
	e.auth.viewer = &auth.Viewer{UserID: 2, Kind: "local", SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleOperator}}}
	if b := e.get("/defense", signedIn(e)).Body.String(); !strings.Contains(b, `data-stepup="/bans/ /anomalies/"`) {
		t.Error("operator's dialog paths")
	}
	if w := e.post("/bans/pause", csrfForm(), signedIn(e), origin(e.baseURL)); w.Code != http.StatusUnauthorized {
		t.Errorf("pause without a code: %d", w.Code)
	}
	if w := e.post("/anomalies/1/ack", csrfForm("note", "x"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusUnauthorized {
		t.Errorf("ack without a code: %d", w.Code)
	}
	// Pages and other POSTs are untouched.
	if w := e.get("/bans", signedIn(e)); w.Code != http.StatusOK {
		t.Errorf("GET /bans: %d", w.Code)
	}
}

// An upload can't carry its file through the prompt: the code goes on its
// own to /stepup, which returns to the page.
func TestStepUpUpload(t *testing.T) {
	t.Parallel()
	e := adminEnv(t)
	e.st.SetSetting(t.Context(), "test", "stepup", "admin", testNow)
	w := e.brandPost("logo", nil, "logo", []byte("x"))
	if b := w.Body.String(); w.Code != http.StatusUnauthorized || !strings.Contains(b, `action="/stepup"`) || !strings.Contains(b, "choose it again") {
		t.Fatalf("upload prompt: %d", w.Code)
	}
	w = e.post("/stepup", csrfForm("next", "/admin/branding", stepUpField, "246811"), signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/branding" {
		t.Fatalf("/stepup: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := e.post("/stepup", csrfForm("next", "//evil.example.com", stepUpField, "246812"), signedIn(e), origin(e.baseURL)); w.Header().Get("Location") != "/" {
		t.Errorf("open redirect: %s", w.Header().Get("Location"))
	}
}

// SSO users have no code: they sign in with Microsoft again (prompt=login),
// and the action is sent on when they're back.
func TestStepUpSSO(t *testing.T) {
	t.Parallel()
	sso := &fakeSSO{}
	e, acme, _, mine, _ := newBansEnv(t, func(c *Config) { c.SSO = sso })
	e.st.SetSetting(t.Context(), "test", "stepup", "every", testNow)
	e.auth.viewer = &auth.Viewer{UserID: 2, Email: "alice@example.com", Kind: "entra", SessionToken: goodToken,
		Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleOperator}}}
	if strings.Contains(e.get("/defense", signedIn(e)).Body.String(), "data-stepup") {
		t.Error("SSO users get the code dialog")
	}
	path := "/bans/" + strconv.FormatInt(mine, 10) + "/approve"
	w := e.post(path, csrfForm("back", "/defense"), signedIn(e), origin(e.baseURL))
	b := w.Body.String()
	if w.Code != http.StatusUnauthorized || !strings.Contains(b, "Sign in with Microsoft") || !strings.Contains(b, `action="/stepup/sso"`) {
		t.Fatalf("SSO prompt: %d\n%s", w.Code, b)
	}
	_, rest, _ := strings.Cut(b, `name="p" value="`)
	pending, _, _ := strings.Cut(rest, `"`)

	// To Microsoft with prompt=login, and back.
	w = e.post("/stepup/sso", csrfForm("p", pending), signedIn(e), origin(e.baseURL))
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusSeeOther || loc.Host != "login.microsoftonline.com" || loc.Query().Get("prompt") != "login" {
		t.Fatalf("to Microsoft: %d %s", w.Code, loc)
	}
	w = e.get("/auth/callback?code=good&state=" + url.QueryEscape(loc.Query().Get("state")))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/stepup/done?p="+pending) {
		t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
	if len(e.auth.identities) != 0 || w.Header().Get("Set-Cookie") != "" {
		t.Error("a step-up started a new session")
	}
	if b, _ := e.st.BanByID(t.Context(), mine); b.Status != store.BanProposed {
		t.Fatal("approved before coming back")
	}
	// /stepup/done sends the waiting form on (app.js submits it).
	b = e.get("/stepup/done?p="+pending, signedIn(e)).Body.String()
	if !strings.Contains(b, `<form method="post" action="`+path+`" class="row" data-resume>`) || !strings.Contains(b, `<input type="hidden" name="back" value="/defense">`) {
		t.Fatalf("resume page:\n%s", b)
	}
	if w := e.post(path, csrfForm("back", "/defense"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("resumed: %d", w.Code)
	}
	if b, _ := e.st.BanByID(t.Context(), mine); b.Status != store.BanPending {
		t.Errorf("after the step-up: %s", b.Status)
	}
	if w := e.get("/stepup/done?p="+pending, signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("done twice: %d", w.Code)
	}

	// Signing in as someone else doesn't count.
	e.clock.add(10 * time.Minute)
	w = e.post("/bans/pause", csrfForm(), signedIn(e), origin(e.baseURL))
	_, rest, _ = strings.Cut(w.Body.String(), `name="p" value="`)
	pending, _, _ = strings.Cut(rest, `"`)
	w = e.post("/stepup/sso", csrfForm("p", pending), signedIn(e), origin(e.baseURL))
	loc, _ = url.Parse(w.Header().Get("Location"))
	e.get("/auth/callback?code=nobody&state=" + url.QueryEscape(loc.Query().Get("state")))
	if w := e.get("/stepup/done?p="+pending, signedIn(e)); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "different Microsoft account") {
		t.Errorf("wrong account: %d", w.Code)
	}
	if p, _ := e.st.BanPaused(t.Context()); p.Paused {
		t.Error("paused after a wrong-account step-up")
	}
	// Someone else's pending action is not found.
	e.auth.viewer = &auth.Viewer{UserID: 3, Kind: "entra", SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleOperator}}}
	if w := e.post("/stepup/sso", csrfForm("p", pending), signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("another user's: %d", w.Code)
	}
}
