// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"regexp"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

// fleetEnv: web-01 (acme/prod, tag web) with a known-exploited, fixable
// critical finding and a hostile-looking anomaly; db-01 waiting for its
// first report; globex-web in another org with nothing to fix.
func fleetEnv(t *testing.T) (*env, store.IngestHost) {
	t.Helper()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	web := e.seed()
	e.seedOrg("globex", "globex-web")
	ctx := t.Context()
	if err := e.st.ReplaceKEV(ctx, []store.KEVEntry{{CVE: "CVE-2099-0001", DateAdded: testNow}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.AddAnomaly(ctx, web.ID, 0, store.Anomaly{Rule: "package_drop", Severity: "high",
		Summary: `<script>alert("a")</script> packages vanished`}, testNow); err != nil {
		t.Fatal(err)
	}
	p, err := e.st.CreatePlan(ctx, "test", 0, "acme", "October <b>patching</b>")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddToPlan(ctx, "test", p.ID, web, 1); err != nil {
		t.Fatal(err)
	}
	return e, web
}

func tileN(t *testing.T, body, href string) string {
	t.Helper()
	m := regexp.MustCompile(`<a class="tile[^"]*" href="` + regexp.QuoteMeta(href) + `"><span class="n">([\d,]+)</span>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no tile linking to %s", href)
	}
	return m[1]
}

func TestDashboardAttention(t *testing.T) {
	t.Parallel()
	e, _ := fleetEnv(t)
	body := e.get("/", signedIn(e)).Body.String()
	if n := strings.Count(body, `<a class="tile`); n != 8 {
		t.Errorf("%d tiles, want the 4 x 2 grid", n)
	}
	for href, want := range map[string]string{
		"/hosts?only=kev&amp;sort=priority":     "1",
		"/hosts?only=fixable&amp;sort=priority": "1",
		"/anomalies":                            "1",
		"/hosts?only=stale&amp;sort=seen":       "0",
	} {
		if got := tileN(t, body, href); got != want {
			t.Errorf("tile %s = %s, want %s", href, got, want)
		}
	}
	for _, want := range []string{
		`id="attention"`, `<a href="/hosts/acme/web-01">web-01</a>`, `1 KEV</span>`,
		`packages dropped`, `&lt;script&gt;alert(&#34;a&#34;)&lt;/script&gt; packages vanished`,
		`October &lt;b&gt;patching&lt;/b&gt;`, `0 of 1 patched`,
		`Waiting for first report`, `db-01`, `with no fix released yet`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	if strings.Contains(body, `<script>alert`) || strings.Contains(body, `<b>patching`) {
		t.Error("anomaly summary or plan name rendered unescaped")
	}
	// Known-exploited first: web-01 outranks globex-web (only its site's lifecycle).
	if i, j := strings.Index(body, `href="/hosts/acme/web-01"`), strings.Index(body, `href="/hosts/globex/globex-web"`); i < 0 || j < 0 || i > j {
		t.Error("attention list order")
	}
	if org := e.get("/?org=globex", signedIn(e)).Body.String(); strings.Contains(org, "web-01") || tileN(t, org, "/anomalies") != "0" {
		t.Error("org filter leaks acme hosts or anomalies")
	}
}

func TestDashboardEmptyFleet(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.st.CreateOrg(t.Context(), "test", "acme", "Acme")
	body := e.get("/", signedIn(e)).Body.String()
	if !strings.Contains(body, "No hosts have reported yet") || !strings.Contains(body, "No open plans") ||
		!strings.Contains(body, "No open anomalies") || strings.Count(body, `<a class="tile`) != 8 {
		t.Error("empty dashboard")
	}
}

func TestHostsFilters(t *testing.T) {
	t.Parallel()
	e, _ := fleetEnv(t)
	names := func(path string) string {
		t.Helper()
		var out []string
		for _, m := range regexp.MustCompile(`class="h-name" href="/hosts/[^"]+">([^<]+)</a>`).FindAllStringSubmatch(e.get(path, signedIn(e)).Body.String(), -1) {
			out = append(out, m[1])
		}
		return strings.Join(out, ",")
	}
	for path, want := range map[string]string{
		"/hosts":                 "db-01,web-01,globex-web",
		"/hosts?only=kev":        "web-01",
		"/hosts?only=anomalies":  "web-01",
		"/hosts?only=waiting":    "db-01",
		"/hosts?tag=web":         "web-01",
		"/hosts?only=bogus":      "db-01,web-01,globex-web", // unknown filters are ignored
		"/hosts?sort=priority":   "web-01,globex-web,db-01",
		"/hosts?org=globex":      "globex-web",
		"/hosts?only=kev&tag=db": "",
	} {
		if got := names(path); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
	body := e.get("/hosts?only=kev", signedIn(e)).Body.String()
	for _, want := range []string{
		`<a href="/hosts?only=kev" aria-current="true" class="only-kev">Known-exploited <span>1</span></a>`,
		`<a href="/hosts?only=kev&amp;sort=priority">Priority</a>`, // sort keeps the filter
		`<span class="badge kev">1</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("hosts page missing %q", want)
		}
	}
	if !strings.Contains(e.get("/hosts?only=kev&tag=db", signedIn(e)).Body.String(), "No hosts match these filters") {
		t.Error("empty filter result message")
	}
}

func TestHostsRespectScope(t *testing.T) {
	t.Parallel()
	e, web := fleetEnv(t)
	e.auth.viewer = &auth.Viewer{UserID: 2, Email: "bob@example.com", SessionToken: goodToken,
		Scope: store.Scope{Orgs: map[int64]store.Role{web.OrgID: store.RoleViewer}}}
	for _, p := range []string{"/hosts", "/hosts?org=globex", "/hosts?sort=priority", "/"} {
		if body := e.get(p, signedIn(e)).Body.String(); strings.Contains(body, "globex-web") {
			t.Errorf("%s shows another org's host", p)
		}
	}
	if body := e.get("/hosts", signedIn(e)).Body.String(); !strings.Contains(body, `All <span>2</span>`) {
		t.Error("filter counts include hosts outside the scope")
	}
}

// The dashboard's SQL tallies agree with counting every finding.
func TestCountsOnlyMatchesFullReport(t *testing.T) {
	t.Parallel()
	e, _ := fleetEnv(t)
	ctx := t.Context()
	full, err := report.Build(ctx, e.st, report.Filter{Scope: store.AllScope}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	quick, err := report.Build(ctx, e.st, report.Filter{Scope: store.AllScope, CountsOnly: true}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Hosts) != len(quick.Hosts) {
		t.Fatalf("%d hosts vs %d", len(full.Hosts), len(quick.Hosts))
	}
	for i := range full.Hosts {
		f, q := full.Hosts[i], quick.Hosts[i]
		if f.Counts != q.Counts || len(q.Findings) != 0 {
			t.Errorf("%s: full %+v, counts-only %+v (%d findings)", f.Name, f.Counts, q.Counts, len(q.Findings))
		}
		for j := range f.Sites {
			if f.Sites[j].Counts != q.Sites[j].Counts {
				t.Errorf("%s site %s: %+v vs %+v", f.Name, f.Sites[j].Root, f.Sites[j].Counts, q.Sites[j].Counts)
			}
		}
	}
	if full.Hosts[0].Counts.KEV != 1 || full.Hosts[0].Counts.FixUrgent != 1 {
		t.Errorf("web-01 counts %+v", full.Hosts[0].Counts)
	}
}

func TestCommas(t *testing.T) {
	t.Parallel()
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 14766: "14,766", 1234567: "1,234,567", -1500: "-1,500"} {
		if got := commas(n); got != want {
			t.Errorf("commas(%d) = %q", n, got)
		}
	}
}
