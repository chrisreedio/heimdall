// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/ingest"
	"github.com/realmwatch/heimdall/internal/search"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

const goodToken = "tok-valid"

type fakeAuth struct {
	loggedOut  []string
	viewer     *auth.Viewer // overrides the default admin viewer when set
	identities []store.EntraIdentity
}

func (f *fakeAuth) LoginIdentity(_ context.Context, id store.EntraIdentity, roles []string, ip, ua string) (string, error) {
	f.identities = append(f.identities, id)
	if id.ObjectID == "unprovisioned" {
		return "", auth.ErrNotProvisioned
	}
	return goodToken, nil
}

func (f *fakeAuth) Login(_ context.Context, email, password, code, ip, ua string) (string, error) {
	switch {
	case email == "throttled@example.com":
		return "", auth.ErrThrottled
	case email == "admin@example.com" && password == "correct horse" && code == "123456":
		return goodToken, nil
	}
	return "", auth.ErrInvalidLogin
}

func (f *fakeAuth) Session(_ context.Context, token string) (*auth.Viewer, error) {
	if token == goodToken && f.viewer != nil {
		return f.viewer, nil
	}
	if token == goodToken {
		return &auth.Viewer{UserID: 1, Email: "admin@example.com", IsAdmin: true, Scope: store.AllScope, SessionToken: token}, nil
	}
	return nil, auth.ErrNoSession
}

func (f *fakeAuth) Logout(_ context.Context, token string) error {
	f.loggedOut = append(f.loggedOut, token)
	return nil
}

type env struct {
	t       *testing.T
	h       http.Handler
	st      *store.Store
	auth    *fakeAuth
	baseURL string
	cookie  string
	dbPath  string
}

var testNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func newEnv(t *testing.T, baseURL string, sf SearchFunc) *env {
	t.Helper()
	return newEnvCfg(t, baseURL, sf, nil)
}

// newEnvCfg is newEnv with a hook to adjust the Config (local login is on
// by default, SSO off).
func newEnvCfg(t *testing.T, baseURL string, sf SearchFunc, adjust func(*Config)) *env {
	t.Helper()
	st, dbPath := storetest.NewPath(t)
	if sf == nil {
		sf = func(context.Context, string, store.Scope) (*search.Result, error) { return &search.Result{}, nil }
	}
	fa := &fakeAuth{}
	cfg := Config{BaseURL: baseURL, StaleAfter: 72 * time.Hour, Version: "test", SessionMax: 12 * time.Hour, LocalLogin: true}
	if adjust != nil {
		adjust(&cfg)
	}
	h, err := New(cfg, st, fa, sf, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	cookie := "heimdall"
	if strings.HasPrefix(baseURL, "https") {
		cookie = "__Host-heimdall"
	}
	return &env{t: t, h: h, st: st, auth: fa, baseURL: baseURL, cookie: cookie, dbPath: dbPath}
}

// seed creates web-01 with a stored snapshot and one KEV-free finding whose
// advisory summary looks hostile.
func (e *env) seed() store.IngestHost {
	e.t.Helper()
	ctx := e.t.Context()
	e.st.CreateOrg(ctx, "test", "acme", "Acme")
	e.st.CreateEnv(ctx, "test", "acme", "prod", "")
	if _, _, err := e.st.AddHost(ctx, "test", "acme", "prod", "web-01", []string{"web"}); err != nil {
		e.t.Fatal(err)
	}
	if _, _, err := e.st.AddHost(ctx, "test", "acme", "prod", "db-01", nil); err != nil {
		e.t.Fatal(err)
	}
	host, _ := e.st.HostByName(ctx, "acme", "web-01")
	raw, err := os.ReadFile("../snapshot/testdata/debian12.json")
	if err != nil {
		e.t.Fatal(err)
	}
	var snap map[string]any
	json.Unmarshal(raw, &snap)
	snap["collected_at"] = testNow.Format(time.RFC3339)
	raw, _ = json.Marshal(snap)
	acc := ingest.Accepter{Store: e.st, Now: func() time.Time { return testNow }}
	if res, err := acc.Accept(ctx, host, "push", raw); err != nil || res.Status != http.StatusCreated {
		e.t.Fatalf("seed snapshot: %+v %v", res, err)
	}
	if err := e.st.PutAdvisory(ctx, store.Advisory{
		ID: "DEBIAN-CVE-2099-0001", Modified: testNow, Summary: `<script>alert("x")</script> in openssl`,
		Severity: "critical", CVSS: 9.8, Raw: []byte(`{}`), Aliases: []string{"CVE-2099-0001"},
	}); err != nil {
		e.t.Fatal(err)
	}
	if _, _, err := e.st.SetFindings(ctx, host.ID, []store.Finding{{
		AdvisoryID: "DEBIAN-CVE-2099-0001", Ecosystem: "Debian:12", Package: "openssl",
		Version: "3.0.14-1~deb12u2", Binaries: []string{"libssl3", "openssl"}, FixedVersion: "3.0.15-1~deb12u1",
	}}, testNow); err != nil {
		e.t.Fatal(err)
	}
	return host
}

type opt func(*http.Request)

func signedIn(e *env) opt {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: e.cookie, Value: goodToken}) }
}

func origin(o string) opt { return func(r *http.Request) { r.Header.Set("Origin", o) } }

func (e *env) get(path string, opts ...opt) *httptest.ResponseRecorder {
	e.t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func (e *env) post(path string, form url.Values, opts ...opt) *httptest.ResponseRecorder {
	e.t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func TestUnauthenticatedRedirects(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	for _, p := range []string{"/", "/hosts", "/hosts/acme/web-01", "/sites", "/search?q=x", "/nope"} {
		w := e.get(p)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("%s: status %d", p, w.Code)
		}
		loc, _ := url.Parse(w.Header().Get("Location"))
		if loc.Path != "/login" || loc.Query().Get("next") != p {
			t.Errorf("%s: redirect to %s", p, loc)
		}
	}
	// Non-GET without a session is refused outright.
	if w := e.post("/logout", url.Values{}); w.Code != http.StatusForbidden {
		t.Errorf("POST without session: %d", w.Code)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/hosts":                 "/hosts",
		"/search?q=a%20b":        "/search?q=a%20b",
		"//evil.com":             "/",
		"https://evil.com/":      "/",
		"/\\evil.com":            "/",
		"evil":                   "/",
		"":                       "/",
		"/login?next=//evil":     "/",
		"/ok\r\nSet-Cookie: x=1": "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLogin(t *testing.T) {
	for _, base := range []string{"http://127.0.0.1:8080", "https://heimdall.internal"} {
		t.Run(base, func(t *testing.T) {
			e := newEnv(t, base, nil)
			if w := e.get("/login?next=//evil.com"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="next" value="/"`) {
				t.Fatalf("login page: %d\n%s", w.Code, w.Body)
			}

			if body := e.get("/login").Body.String(); !strings.Contains(body, `name="totp"`) || !strings.Contains(body, `autocomplete="one-time-code"`) {
				t.Error("the one-time code field should be recognisable to password managers")
			}
			// "totp" is the field's name; other tests post the old "code".
			form := url.Values{"email": {"admin@example.com"}, "password": {"correct horse"}, "totp": {"123456"}, "next": {"/hosts"}}
			w := e.post("/login", form, origin(base))
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/hosts" {
				t.Fatalf("login: %d %s", w.Code, w.Header().Get("Location"))
			}
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("cookies = %v", cookies)
			}
			c := cookies[0]
			secure := strings.HasPrefix(base, "https")
			if c.Name != e.cookie || c.Value != goodToken || !c.HttpOnly || c.Secure != secure ||
				c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.MaxAge != 12*3600 {
				t.Errorf("cookie = %+v", c)
			}
			if secure && w.Header().Get("Strict-Transport-Security") == "" {
				t.Error("missing HSTS over https")
			}

			// Open redirects via next are neutralized.
			form.Set("next", "https://evil.com/")
			if w := e.post("/login", form, origin(base)); w.Header().Get("Location") != "/" {
				t.Errorf("next not sanitized: %s", w.Header().Get("Location"))
			}
		})
	}
}

func TestLoginFailures(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	base := origin(e.baseURL)
	w := e.post("/login", url.Values{"email": {"admin@example.com"}, "password": {"hunter2-secret"}, "code": {"000000"}}, base)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), auth.ErrInvalidLogin.Error()) {
		t.Fatalf("bad password: %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "hunter2-secret") {
		t.Error("password echoed back")
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("cookie set on failure")
	}
	if w := e.post("/login", url.Values{"email": {"throttled@example.com"}}, base); w.Code != http.StatusTooManyRequests {
		t.Errorf("throttled: %d", w.Code)
	}
	// Cross-site login posts are refused.
	if w := e.post("/login", url.Values{"email": {"admin@example.com"}}, origin("https://evil.com")); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin login: %d", w.Code)
	}
	if w := e.post("/login", url.Values{"email": {"admin@example.com"}}); w.Code != http.StatusForbidden {
		t.Errorf("login without Origin/Referer: %d", w.Code)
	}
}

func TestLogoutNeedsCSRFAndOrigin(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	good := auth.CSRFToken(goodToken)
	cases := []struct {
		name string
		form url.Values
		opts []opt
		want int
	}{
		{"missing csrf", url.Values{}, []opt{signedIn(e), origin(e.baseURL)}, http.StatusForbidden},
		{"wrong csrf", url.Values{"csrf": {"nope"}}, []opt{signedIn(e), origin(e.baseURL)}, http.StatusForbidden},
		{"wrong origin", url.Values{"csrf": {good}}, []opt{signedIn(e), origin("https://evil.com")}, http.StatusForbidden},
		{"no origin", url.Values{"csrf": {good}}, []opt{signedIn(e)}, http.StatusForbidden},
		{"ok", url.Values{"csrf": {good}}, []opt{signedIn(e), origin(e.baseURL)}, http.StatusSeeOther},
	}
	for _, c := range cases {
		if w := e.post("/logout", c.form, c.opts...); w.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, w.Code, c.want)
		}
	}
	if len(e.auth.loggedOut) != 1 {
		t.Errorf("logout calls = %v", e.auth.loggedOut)
	}

	// Referer works when Origin is absent.
	referer := func(r *http.Request) { r.Header.Set("Referer", e.baseURL+"/hosts") }
	if w := e.post("/logout", url.Values{"csrf": {good}}, signedIn(e), referer); w.Code != http.StatusSeeOther {
		t.Errorf("referer: %d", w.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	for _, p := range []string{"/login", "/static/app.css", "/"} {
		h := e.get(p).Header()
		if h.Get("Content-Security-Policy") != CSP {
			t.Errorf("%s: CSP = %q", p, h.Get("Content-Security-Policy"))
		}
		for k, v := range map[string]string{
			"X-Content-Type-Options":     "nosniff",
			"Referrer-Policy":            "same-origin",
			"X-Frame-Options":            "DENY",
			"Cross-Origin-Opener-Policy": "same-origin",
		} {
			if h.Get(k) != v {
				t.Errorf("%s: %s = %q", p, k, h.Get(k))
			}
		}
		if h.Get("Strict-Transport-Security") != "" {
			t.Errorf("%s: HSTS over http", p)
		}
	}
	if cc := e.get("/login").Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("login Cache-Control = %q", cc)
	}
	if !strings.Contains(CSP, "script-src 'self'") || strings.Contains(CSP, "unsafe") {
		t.Error("CSP must not allow inline script")
	}
}

func TestDashboard(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seed()
	w := e.get("/", signedIn(e))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`<a href="/hosts/acme/web-01">web-01</a>`, "critical &amp; high with a fix", "Waiting for first report", "db-01", "admin@example.com", auth.CSRFToken(goodToken)} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	// One org: no org filter.
	if strings.Contains(body, `name="org"`) {
		t.Error("org filter shown with a single org")
	}
	e.st.CreateOrg(t.Context(), "test", "globex", "Globex")
	if !strings.Contains(e.get("/", signedIn(e)).Body.String(), `name="org"`) {
		t.Error("org filter missing with two orgs")
	}
	if w := e.get("/hosts", signedIn(e)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "waiting for first report") {
		t.Errorf("hosts page: %d", w.Code)
	}
}

func TestHostPage(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seed()
	w := e.get("/hosts/acme/web-01", signedIn(e))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, `<script>alert`) {
		t.Fatal("advisory summary not escaped")
	}
	for _, want := range []string{
		"&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;",
		"CVE-2099-0001",
		"sudo apt-get install --only-upgrade openssh-server",
		"sev-critical",
		"3.0.15-1~deb12u1",
		"Debian GNU/Linux 12 (bookworm)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("host page missing %q", want)
		}
	}
	if w := e.get("/hosts/acme/nope", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("unknown host: %d", w.Code)
	}
	if w := e.get("/hosts/acme/"+url.PathEscape("bad name!"), signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("invalid host name: %d", w.Code)
	}
	if w := e.get("/hosts/acme/db-01", signedIn(e)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "hasn't reported yet") {
		t.Errorf("never-seen host: %d", w.Code)
	}
}

func TestUpgradeCommands(t *testing.T) {
	pending := []store.InventoryPackage{
		{Name: "openssl", PendingVersion: "2", PendingSecurity: true},
		{Name: "tzdata", PendingVersion: "2"},
		{Name: "evil;rm", PendingVersion: "2"},
	}
	cmds := upgradeCommands("rpm", pending)
	if len(cmds) != 2 || cmds[0].Text != "sudo dnf upgrade openssl" || cmds[1].Text != "sudo dnf upgrade openssl tzdata" {
		t.Errorf("commands = %+v", cmds)
	}
	if upgradeCommands("", pending) != nil {
		t.Error("unknown package manager should give no commands")
	}
}

func TestSearch(t *testing.T) {
	sf := func(_ context.Context, q string, _ store.Scope) (*search.Result, error) {
		if q == "bad <<" {
			return nil, errors.New(`unexpected "<<"`)
		}
		return &search.Result{Matches: []search.Match{{Org: "acme", Host: "web-01", Name: "openssl", Version: "3.0.11-1", Detail: "fixed in 3.0.13"}}}, nil
	}
	e := newEnv(t, "http://127.0.0.1:8080", sf)
	if w := e.get("/search", signedIn(e)); !strings.Contains(w.Body.String(), "openssl &lt; 3.0.13") {
		t.Error("examples missing")
	}
	w := e.get("/search?q="+url.QueryEscape("openssl < 3.0.13"), signedIn(e))
	if !strings.Contains(w.Body.String(), `<a href="/hosts/acme/web-01">web-01</a>`) || !strings.Contains(w.Body.String(), "fixed in 3.0.13") {
		t.Errorf("results missing:\n%s", w.Body)
	}
	if w := e.get("/search?q="+url.QueryEscape("bad <<"), signedIn(e)); !strings.Contains(w.Body.String(), "unexpected &#34;&lt;&lt;&#34;") {
		t.Errorf("parse error not shown:\n%s", w.Body)
	}
}

func TestStaticAndNotFound(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	for file, ctype := range map[string]string{
		"app.css":  "text/css; charset=utf-8",
		"app.js":   "text/javascript; charset=utf-8",
		"icon.svg": "image/svg+xml",
	} {
		w := e.get("/static/" + file)
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != ctype || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
			t.Errorf("%s: %d %q %q", file, w.Code, w.Header().Get("Content-Type"), w.Header().Get("Cache-Control"))
		}
	}
	for _, p := range []string{"/static/nope.css", "/static/..%2Fweb.go", "/static/web.go"} {
		if w := e.get(p); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if w := e.get("/nope", signedIn(e)); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "Not found") {
		t.Errorf("404 page: %d", w.Code)
	}
}

func TestNewRejectsBadBaseURL(t *testing.T) {
	for _, u := range []string{"", "ftp://x", "heimdall.internal"} {
		if _, err := New(Config{BaseURL: u}, nil, nil, nil, nil, time.Now); err == nil {
			t.Errorf("New(%q) should fail", u)
		}
	}
}
