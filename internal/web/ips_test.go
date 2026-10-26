// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/store"
)

// newIPEnv is an env whose resolver uses its store, with the sign-in source.
func newIPEnv(t *testing.T) *env {
	t.Helper()
	ips := &ipinfo.Resolver{}
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.IPs = ips })
	ips.Store, ips.Sources = e.st, []ipinfo.Source{ipinfo.SignIns{Store: e.st}, ipinfo.Hosts{Store: e.st}}
	return e
}

func csrfForm(kv ...string) url.Values {
	f := url.Values{"csrf": {auth.CSRFToken(goodToken)}}
	for i := 0; i+1 < len(kv); i += 2 {
		f.Set(kv[i], kv[i+1])
	}
	return f
}

func (e *env) orgID(slug string) int64 {
	e.t.Helper()
	orgs, err := e.st.ListOrgs(e.t.Context())
	if err != nil {
		e.t.Fatal(err)
	}
	for _, o := range orgs {
		if o.Slug == slug {
			return o.ID
		}
	}
	e.t.Fatalf("no org %s", slug)
	return 0
}

func TestIPsPageAdminOnly(t *testing.T) {
	e := newIPEnv(t)
	e.seed()
	e.st.CreateOrg(t.Context(), "test", "beta", "Beta")
	acme, beta := e.orgID("acme"), e.orgID("beta")
	if w := e.get("/ips", signedIn(e)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Label an address") {
		t.Fatalf("admin: %d", w.Code)
	}
	if !strings.Contains(e.get("/", signedIn(e)).Body.String(), `href="/ips"`) {
		t.Error("nav should link the IP addresses page for admins")
	}
	e.auth.viewer = &auth.Viewer{UserID: 2, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleOperator}}}
	if w := e.get("/ips", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("operator: %d", w.Code)
	}
	if strings.Contains(e.get("/", signedIn(e)).Body.String(), `href="/ips"`) {
		t.Error("nav links the IP addresses page for a non-admin")
	}
	if w := e.post("/ips/labels", csrfForm("org", "acme", "prefix", "203.0.113.7", "kind", "staff", "name", "Office"), origin(e.baseURL), signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("operator adding a label: %d", w.Code)
	}

	// An org admin manages only their org's labels.
	e.auth.viewer = &auth.Viewer{UserID: 3, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleAdmin, beta: store.RoleViewer}}}
	body := e.get("/ips", signedIn(e)).Body.String()
	if !strings.Contains(body, `id="org-acme"`) || strings.Contains(body, `id="org-beta"`) || strings.Contains(body, `<option value="">All orgs</option>`) {
		t.Error("org admin should see only their org, and can't label every org")
	}
	for _, org := range []string{"beta", ""} {
		if w := e.post("/ips/labels", csrfForm("org", org, "prefix", "203.0.113.7", "kind", "staff", "name", "Office"), origin(e.baseURL), signedIn(e)); w.Code != http.StatusForbidden {
			t.Errorf("org admin labeling %q: %d", org, w.Code)
		}
	}
}

func TestIPLabelAddRemove(t *testing.T) {
	e := newIPEnv(t)
	e.seed()
	ctx := t.Context()
	acme := e.orgID("acme")
	add := csrfForm("org", "acme", "prefix", "203.0.113.0/24", "kind", "staff", "name", "Office", "person", "alice@example.com")
	add.Del("csrf")
	if w := e.post("/ips/labels", add, origin(e.baseURL), signedIn(e)); w.Code != http.StatusForbidden {
		t.Fatalf("no CSRF: %d", w.Code)
	}
	add.Set("csrf", auth.CSRFToken(goodToken))
	if w := e.post("/ips/labels", add, signedIn(e)); w.Code != http.StatusForbidden {
		t.Fatalf("no Origin: %d", w.Code)
	}
	if w := e.post("/ips/labels", add, origin(e.baseURL), signedIn(e)); w.Code != http.StatusSeeOther {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	for k, v := range map[string]string{"prefix": "not-an-ip", "kind": "unknown", "name": ""} {
		bad := csrfForm("org", "acme", "prefix", "203.0.113.9", "kind", "staff", "name", "Office")
		bad.Set(k, v)
		if w := e.post("/ips/labels", bad, origin(e.baseURL), signedIn(e)); w.Code != http.StatusBadRequest {
			t.Errorf("bad %s: %d", k, w.Code)
		}
	}
	// A synced label: listed with its source, read-only.
	if err := e.st.ReplaceIPLabels(ctx, acme, "service:deploy", []store.IPLabel{{Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		Kind: store.IPKindAutomation, Name: "Deploy service"}}, testNow); err != nil {
		t.Fatal(err)
	}
	labels, _ := e.st.IPLabels(ctx, acme)
	if len(labels) != 2 || labels[0].Prefix.String() != "203.0.113.0/24" || labels[0].CreatedBy != "user:1" {
		t.Fatalf("labels = %+v", labels)
	}
	body := e.get("/ips", signedIn(e)).Body.String()
	for _, want := range []string{"<code>203.0.113.0/24</code>", "alice@example.com", "From service:deploy", "Deploy service",
		`action="/ips/labels/` + strconv.FormatInt(labels[0].ID, 10) + `/remove"`} {
		if !strings.Contains(body, want) {
			t.Errorf("ips page missing %q", want)
		}
	}
	if strings.Contains(body, `action="/ips/labels/`+strconv.FormatInt(labels[1].ID, 10)+`/remove"`) {
		t.Error("synced labels can't be removed")
	}
	if w := e.post("/ips/labels/"+strconv.FormatInt(labels[1].ID, 10)+"/remove", csrfForm("org", "acme"), origin(e.baseURL), signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("removing a synced label: %d", w.Code)
	}
	if w := e.post("/ips/labels/"+strconv.FormatInt(labels[0].ID, 10)+"/remove", csrfForm("org", "acme"), origin(e.baseURL), signedIn(e)); w.Code != http.StatusSeeOther {
		t.Fatalf("remove: %d", w.Code)
	}
	if labels, _ = e.st.IPLabels(ctx, acme); len(labels) != 1 {
		t.Errorf("labels after remove = %+v", labels)
	}

	// The policy toggle.
	if w := e.post("/ips/policy", csrfForm("org", "acme", "tailnet_only", "on"), origin(e.baseURL), signedIn(e)); w.Code != http.StatusSeeOther {
		t.Fatalf("policy: %d", w.Code)
	}
	if p, _ := e.st.IPPolicy(ctx, acme); !p.TailnetOnly || p.AllowServices || p.UpdatedBy != "user:1" {
		t.Errorf("policy = %+v", p)
	}
	if !strings.Contains(e.get("/ips", signedIn(e)).Body.String(), `name="tailnet_only" checked`) {
		t.Error("policy not shown on")
	}
}

func TestHostPageVerdicts(t *testing.T) {
	e := newIPEnv(t)
	host := e.seed()
	ctx := t.Context()
	if _, err := e.st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: host.OrgID, Prefix: netip.MustParsePrefix("192.0.2.0/24"),
		Kind: store.IPKindStaff, Name: "Office", Person: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.ReplaceIPLabels(ctx, 0, "service:deploy", []store.IPLabel{{Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		Kind: store.IPKindAutomation, Name: "Laravel Forge"}}, testNow); err != nil {
		t.Fatal(err)
	}
	uid, err := e.st.CreateLocalUser(ctx, "test", "bob@example.com", "Bob", true, "x", []byte("0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.CreateSession(ctx, sha256.Sum256([]byte("t")), uid, testNow.Add(-2*time.Hour), testNow.Add(time.Hour), "203.0.113.77", "ua"); err != nil {
		t.Fatal(err)
	}
	at := testNow.Add(-time.Hour).Truncate(time.Second)
	evs := []store.PrivilegeEvent{{At: at, Kind: "sudo", User: "chris", Source: "192.0.2.7"},
		{At: at.Add(time.Second), Kind: "sudo", User: "forge", Source: "198.51.100.4"},
		{At: at.Add(2 * time.Second), Kind: "root-ssh", User: "root", Source: "100.101.102.103"},
		{At: at.Add(3 * time.Second), Kind: "sudo", User: "bob", Source: "203.0.113.77"},
		{At: at.Add(4 * time.Second), Kind: "root-ssh", User: "root", Source: "203.0.113.9"},
		{At: at.Add(5 * time.Second), Kind: "sudo", User: "root", Source: "?"}}
	if _, _, err := e.st.RecordPrivilege(ctx, host.ID, evs, "on", store.PrivilegeSources, testNow); err != nil {
		t.Fatal(err)
	}
	body := e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	for _, want := range []string{
		`<a class="pill ok" href="/ips/192.0.2.7" title="staff: Office (alice), from a manual label`, `>alice</a>`,
		`<a class="pill info" href="/ips/198.51.100.4"`, `>Laravel Forge</a>`,
		`<a class="pill ok" href="/ips/100.101.102.103"`, `>Tailnet</a>`,
		`<a class="pill ok guess" href="/ips/203.0.113.77"`, `>probably Bob</a>`,
		`<a class="pill warn" href="/ips/203.0.113.9"`, `>unknown address</a>`,
		`by root from <a href="/ips/203.0.113.9">203.0.113.9</a>`,
		`1 session in the last 24 hours came from addresses Heimdall doesn't know: <a href="/ips/203.0.113.9">203.0.113.9</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("host page missing %q", want)
		}
	}
	// The dashboard says so too, linking the host.
	if dash := e.get("/", signedIn(e)).Body.String(); !strings.Contains(dash, "1 privileged session in the last 7 days came from addresses Heimdall doesn't know, on <a href=\"/hosts/acme/web-01#privilege\">web-01</a>") {
		t.Error("dashboard missing the unknown-address line")
	}
}

func TestIPPageScoping(t *testing.T) {
	e := newIPEnv(t)
	host := e.seed()
	ctx := t.Context()
	e.st.CreateOrg(ctx, "test", "beta", "Beta")
	e.st.CreateEnv(ctx, "test", "beta", "prod", "")
	if _, _, err := e.st.AddHost(ctx, "test", "beta", "prod", "secret-01", nil); err != nil {
		t.Fatal(err)
	}
	other, _ := e.st.HostByName(ctx, "beta", "secret-01")
	const ip = "203.0.113.9"
	at := testNow.Add(-time.Hour).Truncate(time.Second)
	for _, h := range []store.IngestHost{host, other} {
		if _, _, err := e.st.RecordPrivilege(ctx, h.ID, []store.PrivilegeEvent{{At: at, Kind: "root-ssh", User: "root", Source: ip}}, "on", "", testNow); err != nil {
			t.Fatal(err)
		}
		if err := e.st.RecordReportIP(ctx, h.ID, ip); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.st.Audit(ctx, store.AuditEntry{Actor: "user:1", Action: "login.success", Target: "admin@example.com", IP: ip}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Audit(ctx, store.AuditEntry{Actor: "user:1", Action: "host.rename", OrgID: other.OrgID, Target: "beta-thing", IP: ip}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: other.OrgID, Prefix: netip.MustParsePrefix(ip + "/32"),
		Kind: store.IPKindStaff, Name: "Beta office", Person: "carol"}); err != nil {
		t.Fatal(err)
	}

	// The admin sees everything.
	body := e.get("/ips/"+ip, signedIn(e)).Body.String()
	for _, want := range []string{"secret-01", "web-01", "Beta office", "Heimdall sign-ins from here", "beta-thing", "In beta:", "In acme:"} {
		if !strings.Contains(body, want) {
			t.Errorf("admin IP page missing %q", want)
		}
	}
	// A viewer of acme: only acme, no sign-ins or audit log.
	e.auth.viewer = &auth.Viewer{UserID: 2, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{host.OrgID: store.RoleViewer}}}
	w := e.get("/ips/"+ip, signedIn(e))
	body = w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `href="/hosts/acme/web-01#privilege"`) || !strings.Contains(body, `title="infra: web-01, from your hosts&#39; reports">web-01</a>`) {
		t.Fatalf("viewer IP page: %d", w.Code)
	}
	for _, leak := range []string{"secret-01", "beta", "Beta office", "carol", "sign-ins", "Audit log", "admin@example.com", "Label this address"} {
		if strings.Contains(body, leak) {
			t.Errorf("viewer IP page shows %q", leak)
		}
	}
	// Admin of acme: acme's audit entries only.
	e.auth.viewer.Scope.Orgs[host.OrgID] = store.RoleAdmin
	body = e.get("/ips/"+ip, signedIn(e)).Body.String()
	if !strings.Contains(body, "Audit log entries from here") || strings.Contains(body, "beta-thing") || strings.Contains(body, "login.success") {
		t.Error("an org admin should see only their org's audit entries")
	}
	for _, bad := range []string{"/ips/not-an-ip", "/ips/fe80::1%25eth0"} {
		if w := e.get(bad, signedIn(e)); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", bad, w.Code)
		}
	}
}

func TestTailscaleServeHeaders(t *testing.T) {
	type seen struct {
		ip   string
		user tsUser
	}
	var got seen
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.ip = clientIP(r)
		got.user, _ = r.Context().Value(tsUserKey{}).(tsUser)
	})
	req := func(remote string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		r.Header.Add("X-Forwarded-For", "198.51.100.66, 10.0.0.1")
		r.Header.Add("X-Forwarded-For", "100.101.102.103")
		r.Header.Set("Tailscale-User-Login", "alice@example.com")
		r.Header.Set("Tailscale-User-Name", "=?utf-8?q?Al=C3=AFce?=")
		return r
	}
	for _, c := range []struct {
		on     bool
		remote string
		want   seen
	}{
		{true, "127.0.0.1:5555", seen{"100.101.102.103", tsUser{"alice@example.com", "Alïce"}}},
		{true, "[::1]:5555", seen{"100.101.102.103", tsUser{"alice@example.com", "Alïce"}}},
		{true, "203.0.113.5:5555", seen{"203.0.113.5", tsUser{}}}, // not from tailscale serve: never trusted
		{false, "127.0.0.1:5555", seen{"127.0.0.1", tsUser{}}},    // option off
	} {
		got = seen{}
		s := &server{cfg: Config{BehindTailscaleServe: c.on}}
		s.fromTailscaleServe(next).ServeHTTP(httptest.NewRecorder(), req(c.remote))
		if got != c.want {
			t.Errorf("on=%v from %s: got %+v, want %+v", c.on, c.remote, got, c.want)
		}
	}

	// The sign-in records the tailnet user on the session.
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.BehindTailscaleServe = true })
	ctx := t.Context()
	uid, err := e.st.CreateLocalUser(ctx, "test", "alice@example.com", "", false, "x", []byte("0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.CreateSession(ctx, sha256.Sum256([]byte(goodToken)), uid, testNow, testNow.Add(time.Hour), "100.101.102.103", "ua"); err != nil {
		t.Fatal(err)
	}
	s := &server{st: e.st, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	r := httptest.NewRequest(http.MethodPost, "/login", nil).WithContext(context.WithValue(ctx, tsUserKey{}, tsUser{"alice@example.com", "Alice"}))
	s.noteTailscaleUser(r, goodToken)
	ins, err := e.st.SignInsFrom(ctx, "100.101.102.103", 10)
	if err != nil || len(ins) != 1 || ins[0].TailscaleUser != "Alice (alice@example.com)" || !ins[0].Open {
		t.Fatalf("sign-ins = %+v, %v", ins, err)
	}
}

// A deploy service's account from outside its ranges isn't vouched for.
func TestBadgeAccountOnly(t *testing.T) {
	v := ipinfo.Verdict{Addr: netip.MustParseAddr("203.0.113.60"), Labels: []ipinfo.Label{
		{Kind: store.IPKindAutomation, Name: "Laravel Forge", Source: "service:forge", Guess: true}}}
	if b := badgeFor(v); b.Kind != store.IPKindUnknown || b.Text != "unknown address, Laravel Forge account" {
		t.Errorf("badge %+v", b)
	}
	v.Labels = append(v.Labels, ipinfo.Label{Kind: store.IPKindAutomation, Name: "Laravel Forge", Source: "service:forge",
		Prefix: netip.MustParsePrefix("203.0.113.0/24")})
	if b := badgeFor(v); b.Kind != store.IPKindAutomation {
		t.Errorf("in range: %+v", b)
	}
}
