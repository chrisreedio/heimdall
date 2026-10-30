// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

// failLogins records failed logins from ip on a host, an hour before testNow.
func failLogins(t *testing.T, e *env, host store.IngestHost, ip string, n int, succeeded bool) {
	t.Helper()
	at := testNow.Add(-time.Hour)
	day := store.LoginDay{Day: at.Format(time.DateOnly), Failures: n, Addresses: 1,
		Rows: []store.LoginFailure{{IP: ip, Failures: n, Usernames: 2, First: at, Last: at, Succeeded: succeeded}}}
	if err := e.st.RecordLogins(t.Context(), host.ID, store.LoginReport{Source: "journal", CountedAt: testNow, Days: []store.LoginDay{day}}, testNow); err != nil {
		t.Fatal(err)
	}
}

func TestOffendersPage(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	web := e.seed()
	ctx := t.Context()
	db, _ := e.st.HostByName(ctx, "acme", "db-01")
	if _, err := e.st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: web.OrgID, Prefix: netip.MustParsePrefix("198.51.100.4/32"),
		Kind: store.IPKindStaff, Name: "Office"}); err != nil {
		t.Fatal(err)
	}
	failLogins(t, e, web, "203.0.113.9", 7, true)
	failLogins(t, e, db, "203.0.113.9", 3, false)
	failLogins(t, e, web, "203.0.113.20", 50, false)
	failLogins(t, e, web, "198.51.100.4", 1, true) // the office: known

	body := e.get("/offenders", signedIn(e)).Body.String()
	for _, want := range []string{"<h1>Repeat offenders</h1>", `href="/offenders"`, ">Offenders</span>",
		`<a href="/ips/203.0.113.9">203.0.113.9</a>`, `<a href="/ips/203.0.113.20">203.0.113.20</a>`,
		`<span class="pill bad"`, ">then succeeded</span>", "1 on more than one host",
		"Known addresses", `<a href="/ips/198.51.100.4">198.51.100.4</a>`, ">Office</a>"} {
		if !strings.Contains(body, want) {
			t.Errorf("/offenders missing %q", want)
		}
	}
	// Ranked by hosts, then failures: the address on two hosts comes first.
	if i, j := strings.Index(body, ">203.0.113.9</a>"), strings.Index(body, ">203.0.113.20</a>"); i < 0 || j < i {
		t.Errorf("203.0.113.9 (two hosts) should rank above 203.0.113.20 (one host, more failures)")
	}
	// The known address isn't an offender.
	if i, k := strings.Index(body, `id="known"`), strings.Index(body, ">198.51.100.4</a>"); k < i {
		t.Error("the office address is listed with the offenders")
	}
	if !strings.Contains(e.get("/offenders?since=7d", signedIn(e)).Body.String(), `aria-current="true">7 days</a>`) {
		t.Error("7-day window not selected")
	}

	// A viewer in another org sees none of acme's.
	e.st.CreateOrg(ctx, "test", "globex", "")
	globex, _ := e.st.ListOrgs(ctx)
	var gid int64
	for _, o := range globex {
		if o.Slug == "globex" {
			gid = o.ID
		}
	}
	e.auth.viewer = &auth.Viewer{UserID: 2, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{gid: store.RoleViewer}}}
	body = e.get("/offenders", signedIn(e)).Body.String()
	if strings.Contains(body, "203.0.113.9") || !strings.Contains(body, "No failed logins from unknown addresses") {
		t.Error("globex viewer sees acme's failed logins")
	}
	if strings.Contains(e.get("/ips/203.0.113.9", signedIn(e)).Body.String(), "#logins") {
		t.Error("globex viewer sees acme's hosts on the IP page")
	}
}

func TestHostPageLogins(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	web := e.seed()
	ctx := t.Context()
	page := func() string { return e.get("/hosts/acme/web-01", signedIn(e)).Body.String() }
	for _, want := range []string{`id="logins"`, "Failed logins", "Not watched", `<pre id="cmd-logins">sudo heimdall-collect upgrade --watch-logins</pre>`} {
		if !strings.Contains(page(), want) {
			t.Errorf("unwatched host page missing %q", want)
		}
	}
	db, _ := e.st.HostByName(ctx, "acme", "db-01")
	failLogins(t, e, web, "203.0.113.9", 7, true)
	failLogins(t, e, db, "203.0.113.9", 3, false)
	failLogins(t, e, web, "100.101.2.3", 2, false) // the tailnet
	body := page()
	for _, want := range []string{"9 in the last 24 hours, from 2 addresses", ">watched</span>",
		`<a href="/ips/203.0.113.9">203.0.113.9</a>`, "7 failures, 2 usernames", "also 1 other host", ">then succeeded</span>",
		`<a href="/ips/100.101.2.3">100.101.2.3</a>`, "(known, not an offender)"} {
		if !strings.Contains(body, want) {
			t.Errorf("host page missing %q", want)
		}
	}
	// The offender comes before the known address.
	if i, j := strings.Index(body, ">203.0.113.9</a>"), strings.Index(body, ">100.101.2.3</a>"); i < 0 || j < i {
		t.Error("offenders should come first")
	}
	// The IP page lists where it failed.
	ip := e.get("/ips/203.0.113.9", signedIn(e)).Body.String()
	for _, want := range []string{"Failed logins from here", `href="/hosts/acme/web-01#logins"`, `href="/hosts/acme/db-01#logins"`, ">then succeeded</span>"} {
		if !strings.Contains(ip, want) {
			t.Errorf("IP page missing %q", want)
		}
	}
	// Nothing to read on the server.
	if err := e.st.RecordLogins(ctx, web.ID, store.LoginReport{Source: "none"}, testNow); err != nil {
		t.Fatal(err)
	}
	if body := page(); !strings.Contains(body, "Not counting") || !strings.Contains(body, "No sshd log found") {
		t.Error("host page should say the watch can't count")
	}
}
