// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"image/color"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestManifest(t *testing.T) {
	t.Parallel()
	e := adminEnv(t)
	get := func() webManifest {
		t.Helper()
		w := e.get("/manifest.webmanifest") // public: browsers fetch it without cookies
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/manifest+json" {
			t.Fatalf("manifest: %d %v", w.Code, w.Header())
		}
		var m webManifest
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := get()
	if m.Name != "Heimdall" || m.ShortName != "Heimdall" || m.Display != "standalone" || m.StartURL != "/" || m.Scope != "/" ||
		len(m.Icons) != 2 || m.Icons[0].Src != "/static/icon-192.png?v=test" || m.Icons[1].Sizes != "512x512" {
		t.Errorf("default manifest: %+v", m)
	}
	for _, ic := range m.Icons {
		if w := e.get(strings.Split(ic.Src, "?")[0]); w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/png" {
			t.Errorf("%s: %d", ic.Src, w.Code)
		}
	}

	e.brandPost("name", url.Values{"name": {"Acme Operations Hub"}}, "", nil)
	e.brandPost("icon", nil, "icon", testPNG(t, 512, 512, color.NRGBA{1, 2, 3, 255}))
	m = get()
	if m.Name != "Acme Operations Hub" || m.ShortName != "Acme" || m.Icons[0].Src != "/branding/icon-192.png?v=2" ||
		m.Icons[1].Src != "/branding/icon-512.png?v=2" {
		t.Errorf("branded manifest: %+v", m)
	}
	for in, want := range map[string]string{"Ops": "Ops", "Supercalifragilistic hub": "Supercalifra", "Acme Ops Hub": "Acme Ops Hub"} {
		if got := shortName(in); got != want {
			t.Errorf("shortName(%q) = %q, want %q", in, got, want)
		}
	}

	page := e.get("/", signedIn(e)).Body.String()
	for _, want := range []string{`<link rel="manifest" href="/manifest.webmanifest">`, `<link rel="apple-touch-icon" href="/branding/icon-180.png?v=2">`,
		`<meta name="apple-mobile-web-app-capable" content="yes">`, `<meta name="apple-mobile-web-app-title" content="Acme Operations Hub">`,
		`viewport-fit=cover`} {
		if !strings.Contains(page, want) {
			t.Errorf("layout lacks %s", want)
		}
	}
}

func TestServiceWorker(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "https://hub.example-tailnet.ts.net", nil)
	w := e.get("/sw.js") // at the root, so its scope is the whole hub
	body := w.Body.String()
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/javascript; charset=utf-8" ||
		w.Header().Get("Cache-Control") != "no-cache" || w.Header().Get("Content-Security-Policy") != swCSP {
		t.Fatalf("sw.js: %d %v", w.Code, w.Header())
	}
	if !strings.Contains(body, `var VERSION = "test-b0";`) || strings.Contains(body, "__PRECACHE__") ||
		!strings.Contains(body, `["/offline","/static/theme.js?v=test","/static/app.css?v=test","/static/app.js?v=test","/static/icon.svg"]`) {
		t.Errorf("sw.js not filled in:\n%s", body)
	}
	// It passes pages through and caches only versioned static files.
	if !strings.Contains(body, `req.mode === "navigate"`) || !strings.Contains(body, `"/static/"`) || strings.Contains(body, "/api/") {
		t.Error("sw.js caching rules changed")
	}
	// The offline page is public and says what to check.
	w = e.get("/offline")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Can't reach the hub") ||
		!strings.Contains(w.Body.String(), "Is Tailscale connected?") || strings.Contains(w.Body.String(), "/logout") {
		t.Errorf("offline: %d", w.Code)
	}
}

// Pages keep the strict CSP: nothing inline, only this origin, and the
// worker and manifest from here too. Only the worker's own script gets
// connect-src.
func TestCSPStaysStrict(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	csp := e.get("/", signedIn(e)).Header().Get("Content-Security-Policy")
	if csp != CSP {
		t.Fatalf("CSP: %q", csp)
	}
	for _, want := range []string{"default-src 'none'", "script-src 'self';", "style-src 'self';", "worker-src 'self'", "manifest-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %s", want)
		}
	}
	// Forms may go here and to Microsoft's sign-in, which they redirect to.
	if !strings.Contains(csp, "form-action 'self' https://login.microsoftonline.com;") {
		t.Errorf("CSP's form-action doesn't allow Microsoft's sign-in")
	}
	rest := strings.Replace(csp, " https://login.microsoftonline.com;", ";", 1)
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "*", "connect-src", "http:", "https:"} {
		if strings.Contains(rest, bad) {
			t.Errorf("CSP has %s", bad)
		}
	}
	for _, p := range []string{"/manifest.webmanifest", "/offline", "/branding/accent.css"} {
		if got := e.get(p).Header().Get("Content-Security-Policy"); got != CSP {
			t.Errorf("%s: CSP %q", p, got)
		}
	}
}

func TestPhonePages(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.News = true })
	e.seed()
	for path, want := range map[string]string{
		"/":        `class="tab" aria-current="page"><svg`,
		"/alerts":  "<h1>Alerts</h1>",
		"/defense": "Repeat offenders, last 24 hours",
		"/more":    `<b>Add to Home Screen</b>`,
	} {
		w := e.get(path, signedIn(e))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), want) || !strings.Contains(w.Body.String(), `<nav class="tabbar"`) {
			t.Errorf("%s: %d, want %q", path, w.Code, want)
		}
	}
	// The tab bar marks the section a page belongs to.
	for path, tab := range map[string]string{"/hosts": "Hosts", "/anomalies": "Alerts", "/offenders": "Defense", "/sites": "More"} {
		body := e.get(path, signedIn(e)).Body.String()
		if !strings.Contains(body, `aria-current="page">`) || !strings.Contains(body, "<span>"+tab+"</span>") {
			t.Errorf("%s: no tab", path)
			continue
		}
		i := strings.Index(body, `<nav class="tabbar"`)
		cur := body[i:]
		cur = cur[strings.Index(cur, `aria-current="page"`):]
		if !strings.Contains(cur[:strings.Index(cur, "</a>")], "<span>"+tab+"</span>") {
			t.Errorf("%s: current tab isn't %s", path, tab)
		}
	}
}

func TestHomeCards(t *testing.T) {
	t.Parallel()
	if cards := homeCards(0, 0, 0, 0, 0, 0, nil, 0, "3 days"); len(cards) != 0 {
		t.Errorf("quiet fleet: %+v", cards)
	}
	cards := homeCards(2, 1, 0, 3, 4, 0, &unknownIPs{Sessions: 1}, 5, "3 days")
	var got []string
	for _, c := range cards {
		got = append(got, c.Class+":"+c.Label)
	}
	want := "bad:known-exploited findings|warn:ban proposals waiting|warn:open anomalies|warn:privileged session from an unknown address|warn:hosts not reporting"
	if strings.Join(got, "|") != want {
		t.Errorf("cards:\n%s\nwant\n%s", strings.Join(got, "|"), want)
	}
	// High-severity anomalies move up with the other urgent cards.
	cards = homeCards(0, 0, 1, 0, 2, 1, nil, 1, "3 days")
	if cards[0].Label != "incident in the news" || cards[1].Label != "open anomalies" || cards[1].Class != "bad" || cards[2].Class != "warn" {
		t.Errorf("order: %+v", cards)
	}
	// The dashboard says all clear when there's nothing.
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	if body := e.get("/", signedIn(e)).Body.String(); !strings.Contains(body, `class="phone-home"`) {
		t.Error("no phone home")
	}
}
