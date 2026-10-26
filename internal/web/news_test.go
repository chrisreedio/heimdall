// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

// newsEnv is a hub with news on, web-01 (acme) and globex-web each
// affected by the live incident, and an unrelated breach.
func newsEnv(t *testing.T) *env {
	t.Helper()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.News = true })
	e.seed() // web-01: open finding DEBIAN-CVE-2099-0001 (alias CVE-2099-0001)
	e.seedOrg("globex", "globex-web")
	ctx := t.Context()
	g, _ := e.st.HostByName(ctx, "globex", "globex-web")
	if err := e.st.PutAdvisory(ctx, store.Advisory{ID: "CVE-2099-0002", Modified: testNow, Severity: "high", Raw: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.st.SetFindings(ctx, g.ID, []store.Finding{{AdvisoryID: "CVE-2099-0002", Ecosystem: "Debian:12",
		Package: "openssl", Version: "1"}}, testNow); err != nil {
		t.Fatal(err)
	}
	closed := testNow.Add(-48 * time.Hour)
	items := []store.NewsItem{
		{Slug: "ssl-overflow", Category: "patch", Title: `ExampleSSL <script>alert("t")</script> overflow`,
			URL: "https://news.example.test/i/ssl", Severity: "critical", PatchStatus: "patched", Status: "live",
			Summary: `Hostile <img src=x onerror=alert(1)> summary`, CVEs: []string{"CVE-2099-0001", "CVE-2099-0002"},
			StartedAt: testNow.Add(-24 * time.Hour), UpdatedAt: testNow},
		{Slug: "widget-breach", Category: "breach", Title: "Widget breach", URL: "https://news.example.test/i/w",
			Severity: "high", PatchStatus: "no-fix-needed", Status: "closed",
			StartedAt: testNow.Add(-96 * time.Hour), UpdatedAt: closed, ClosedAt: &closed},
	}
	if _, err := e.st.ReplaceNews(ctx, "https://news.example.test/incidents.json", items, "", "", testNow); err != nil {
		t.Fatal(err)
	}
	if err := e.st.MatchNews(ctx, 0, testNow); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestNewsPage(t *testing.T) {
	e := newsEnv(t)
	w := e.get("/news", signedIn(e))
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	for _, want := range []string{
		`aria-current="page">News</a>`,
		`ExampleSSL &lt;script&gt;alert(&#34;t&#34;)&lt;/script&gt; overflow`,
		`href="https://news.example.test/i/ssl" rel="noopener noreferrer"`,
		`Affects 2 of your hosts`, `href="/hosts/acme/web-01"`, `href="/hosts/globex/globex-web"`,
		`via <a href="https://news.example.test/i/ssl" rel="noopener noreferrer">news.example.test</a>`,
		`Widget breach`, `patch available`, `Affects me <span>1</span>`, `Breaches <span>1</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Feed text never becomes markup.
	if strings.Contains(body, `<script>alert`) || strings.Contains(body, `<img src=x`) {
		t.Error("feed text rendered unescaped")
	}
	if strings.Index(body, "ExampleSSL") > strings.Index(body, "Widget breach") {
		t.Error("not newest first")
	}

	me := e.get("/news?affects=me", signedIn(e)).Body.String()
	if !strings.Contains(me, "ExampleSSL") || strings.Contains(me, "Widget breach") {
		t.Error("affects=me filter")
	}
	cat := e.get("/news?category=breach", signedIn(e)).Body.String()
	if strings.Contains(cat, "ExampleSSL") || !strings.Contains(cat, "Widget breach") {
		t.Error("category filter")
	}
}

func TestNewsScope(t *testing.T) {
	e := newsEnv(t)
	acme, _ := e.st.HostByName(t.Context(), "acme", "web-01")
	e.auth.viewer = &auth.Viewer{UserID: 2, Email: "bob@example.com", SessionToken: goodToken,
		Scope: store.Scope{Orgs: map[int64]store.Role{acme.OrgID: store.RoleViewer}}}
	body := e.get("/news", signedIn(e)).Body.String()
	if !strings.Contains(body, "Affects 1 of your hosts<") || !strings.Contains(body, "web-01") || strings.Contains(body, "globex") {
		t.Error("badge shows hosts outside the viewer's scope")
	}
}

func TestNewsOnDashboardAndHost(t *testing.T) {
	e := newsEnv(t)
	dash := e.get("/", signedIn(e)).Body.String()
	if !strings.Contains(dash, `<a class="news-strip" href="/news?affects=me">`) || !strings.Contains(dash, "<strong>1</strong> in the news affects your hosts") {
		t.Error("dashboard strip missing")
	}
	if n := strings.Count(dash, `class="tile`) - strings.Count(dash, `class="tiles"`); n != 8 {
		t.Errorf("%d tiles, want the 4 x 2 grid", n)
	}
	if strings.Index(dash, "news-strip") > strings.Index(dash, `class="tiles"`) {
		t.Error("strip should sit above the tiles")
	}

	host := e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	if !strings.Contains(host, "In the news") || !strings.Contains(host, "CVE-2099-0001 · live") ||
		!strings.Contains(host, `class="badge news"`) || strings.Contains(host, `<script>alert`) {
		t.Error("host page news card or finding badge")
	}

	// Resolving the finding drops the match everywhere.
	web, _ := e.st.HostByName(t.Context(), "acme", "web-01")
	e.st.SetFindings(t.Context(), web.ID, nil, testNow.Add(time.Hour))
	e.st.MatchNews(t.Context(), web.ID, testNow.Add(time.Hour))
	if host := e.get("/hosts/acme/web-01", signedIn(e)).Body.String(); strings.Contains(host, "In the news") {
		t.Error("patched host still shows the incident")
	}
}

func TestNewsOff(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seed()
	if w := e.get("/news", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("/news with news off: %d", w.Code)
	}
	if body := e.get("/", signedIn(e)).Body.String(); strings.Contains(body, `href="/news"`) || strings.Contains(body, "news-strip") {
		t.Error("news shown while off")
	}
}
