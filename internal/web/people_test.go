// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"crypto/sha256"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

// personEnv: alice (a user in acme, "Alice") with a manual label in acme, a
// Tailscale device for every org, a label in beta, a Heimdall session from
// 203.0.113.77, and privileged sessions on web-01 (acme) and secret-01
// (beta) from her addresses.
func personEnv(t *testing.T) (*env, store.IngestHost, store.IngestHost) {
	t.Helper()
	e := newIPEnv(t)
	host := e.seed()
	ctx := t.Context()
	e.st.CreateOrg(ctx, "test", "beta", "Beta")
	e.st.CreateEnv(ctx, "test", "beta", "prod", "")
	if _, _, err := e.st.AddHost(ctx, "test", "beta", "prod", "secret-01", nil); err != nil {
		t.Fatal(err)
	}
	other, _ := e.st.HostByName(ctx, "beta", "secret-01")
	uid, err := e.st.CreateLocalUser(ctx, "test", "alice@example.com", "Alice", false, "x", []byte("0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.Grant(ctx, "test", "alice@example.com", "acme", store.RoleOperator); err != nil {
		t.Fatal(err)
	}
	if err := e.st.CreateSession(ctx, sha256.Sum256([]byte("a")), uid, testNow.Add(-2*time.Hour), testNow.Add(time.Hour), "203.0.113.77", "ua"); err != nil {
		t.Fatal(err)
	}
	for _, l := range []store.IPLabel{
		{OrgID: host.OrgID, Prefix: netip.MustParsePrefix("203.0.113.4/32"), Kind: store.IPKindStaff, Name: "Alice home", Person: "alice@example.com"},
		{OrgID: other.OrgID, Prefix: netip.MustParsePrefix("198.51.100.9/32"), Kind: store.IPKindStaff, Name: "Beta office", Person: "Alice@example.com"},
		{OrgID: host.OrgID, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Kind: store.IPKindStaff, Name: "Bob home", Person: "bob@example.com"},
	} {
		if _, err := e.st.AddIPLabel(ctx, "test", l); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.st.ReplaceIPLabels(ctx, 0, "tailscale", []store.IPLabel{{Prefix: netip.MustParsePrefix("100.101.102.103/32"),
		Kind: store.IPKindStaff, Name: "laptop-01", Person: "alice@example.com"}}, testNow); err != nil {
		t.Fatal(err)
	}
	at := testNow.Add(-time.Hour).Truncate(time.Second)
	if _, _, err := e.st.RecordPrivilege(ctx, host.ID, []store.PrivilegeEvent{
		{At: at, Kind: "sudo", User: "alice", Source: "203.0.113.4"},
		{At: at.Add(time.Second), Kind: "sudo", User: "alice", Source: "203.0.113.77"}, // probably her: she signed in from it
		{At: at.Add(2 * time.Second), Kind: "sudo", User: "bob", Source: "192.0.2.7"},
	}, "on", store.PrivilegeSources, testNow); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.st.RecordPrivilege(ctx, other.ID, []store.PrivilegeEvent{{At: at, Kind: "root-ssh", User: "root", Source: "198.51.100.9"}},
		"on", store.PrivilegeSources, testNow); err != nil {
		t.Fatal(err)
	}
	return e, host, other
}

func TestPersonPage(t *testing.T) {
	e, host, other := personEnv(t)
	// A global admin sees it all, by email or display name.
	for _, p := range []string{"/ips/person/alice@example.com", "/ips/person/Alice"} {
		w := e.get(p, signedIn(e))
		body := w.Body.String()
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", p, w.Code)
		}
		for _, want := range []string{"<h1>Alice</h1>", "Alice home", "laptop-01", "tailscale", "Beta office", "secret-01",
			`href="/hosts/acme/web-01#privilege"`, `href="/ips/203.0.113.4">203.0.113.4</a>`, `href="/ips/203.0.113.77">203.0.113.77</a>`,
			"Heimdall sign-ins", "Signed in to Heimdall from", `name="back" value="/ips/person/`,
			`name="person" maxlength="200" value="alice@example.com"`, `<option value="staff" selected>`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing %q", p, want)
			}
		}
		if strings.Contains(body, "Bob home") || strings.Contains(body, "192.0.2.7") {
			t.Errorf("%s: shows someone else's", p)
		}
	}

	// An org admin of acme: acme's and every org's labels, acme's hosts,
	// no sign-ins, and nothing of beta's.
	e.auth.viewer = &auth.Viewer{UserID: 3, Email: "carol@example.com", SessionToken: goodToken,
		Scope: store.Scope{Orgs: map[int64]store.Role{host.OrgID: store.RoleAdmin}}}
	body := e.get("/ips/person/alice@example.com", signedIn(e)).Body.String()
	for _, want := range []string{"Alice home", "laptop-01", "web-01", "Add an address for Alice", `<option value="acme">`} {
		if !strings.Contains(body, want) {
			t.Errorf("org admin: missing %q", want)
		}
	}
	for _, leak := range []string{"Beta office", "198.51.100.9", "secret-01", "beta", `id="person-signins"`, "Signed in to Heimdall from", "All orgs"} {
		if strings.Contains(body, leak) {
			t.Errorf("org admin sees %q", leak)
		}
	}
	// A viewer of beta only: beta's label and host; alice isn't a user
	// they can see, and they can't label.
	e.auth.viewer = &auth.Viewer{UserID: 4, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{other.OrgID: store.RoleViewer}}}
	body = e.get("/ips/person/alice@example.com", signedIn(e)).Body.String()
	if !strings.Contains(body, "Beta office") || !strings.Contains(body, "secret-01") || !strings.Contains(body, "Not a Heimdall user you can see") {
		t.Error("beta viewer: missing beta's")
	}
	for _, leak := range []string{"Alice home", "web-01", "203.0.113.4", "203.0.113.77", "Add an address", "<h1>Alice</h1>"} {
		if strings.Contains(body, leak) {
			t.Errorf("beta viewer sees %q", leak)
		}
	}
	if w := e.get("/ips/person/"+strings.Repeat("x", 201), signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("long name: %d", w.Code)
	}
}

func TestPersonLinks(t *testing.T) {
	e, _, _ := personEnv(t)
	// The staff badge links the person; the address keeps its IP page.
	host := e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	for _, want := range []string{`href="/ips/person/alice@example.com"`, `from <a href="/ips/203.0.113.4">203.0.113.4</a>`,
		`href="/ips/person/Alice"`} {
		if !strings.Contains(host, want) {
			t.Errorf("host page missing %q", want)
		}
	}
	if !strings.Contains(e.get("/ips/203.0.113.4", signedIn(e)).Body.String(), `(<a href="/ips/person/alice@example.com">alice@example.com</a>)`) {
		t.Error("IP page should link the person")
	}
	if !strings.Contains(e.get("/ips", signedIn(e)).Body.String(), `<a href="/ips/person/bob@example.com">bob@example.com</a>`) {
		t.Error("/ips should link the person")
	}
	if !strings.Contains(e.get("/admin/users", signedIn(e)).Body.String(), `href="/ips/person/alice@example.com"`) {
		t.Error("Users page should link each user's addresses")
	}

	// Adding from the person page returns there.
	f := csrfForm("org", "acme", "prefix", "203.0.113.5", "kind", "staff", "name", "Alice phone", "person", "alice@example.com",
		"back", "/ips/person/alice@example.com")
	if w := e.post("/ips/labels", f, origin(e.baseURL), signedIn(e)); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ips/person/alice@example.com" {
		t.Fatalf("add: %d %s", w.Code, w.Header().Get("Location"))
	}
	f.Set("back", "https://evil.example.com/")
	f.Set("prefix", "203.0.113.6")
	if w := e.post("/ips/labels", f, origin(e.baseURL), signedIn(e)); w.Header().Get("Location") != "/ips" {
		t.Errorf("back elsewhere: %s", w.Header().Get("Location"))
	}
}

func TestLabelItsMe(t *testing.T) {
	e, _, _ := personEnv(t)
	ip := e.get("/ips/203.0.113.9", signedIn(e)).Body.String()
	if !strings.Contains(ip, `href="/ips?addr=203.0.113.9&amp;me=1"`) {
		t.Error(`IP page should offer "It's me"`)
	}
	body := e.get("/ips?addr=203.0.113.9&me=1", signedIn(e)).Body.String()
	for _, want := range []string{`name="prefix" required maxlength="64" value="203.0.113.9"`, `<option value="staff" selected>`,
		`name="person" maxlength="200" value="admin@example.com"`, `value="admin&#39;s address"`,
		`<datalist id="label-people">`, `<option value="alice@example.com">`, `<option value="bob@example.com">`} {
		if !strings.Contains(body, want) {
			t.Errorf("/ips?me=1 missing %q", want)
		}
	}
	// An org admin's suggestions are the people of their orgs.
	acme := e.orgID("acme")
	e.auth.viewer = &auth.Viewer{UserID: 3, Email: "carol@example.com", SessionToken: goodToken,
		Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleAdmin}}}
	if !strings.Contains(e.get("/ips", signedIn(e)).Body.String(), `<option value="alice@example.com">`) {
		t.Error("org admin should be offered alice, a user in their org")
	}
}

func TestLabelResolvesUnknownSource(t *testing.T) {
	e, host, _ := personEnv(t)
	for _, src := range []string{"203.0.113.50", "203.0.113.51"} {
		if _, err := e.st.AddAnomaly(t.Context(), host.ID, 0, store.Anomaly{Rule: "privilege_unknown_source", Severity: "high",
			Summary: "Privileged access from an unknown address, " + src, Detail: map[string]any{"key": "2026-10-22 " + src, "source": src}}, testNow); err != nil {
			t.Fatal(err)
		}
	}
	f := csrfForm("org", "acme", "prefix", "203.0.113.50", "kind", "staff", "name", "Alice home", "person", "alice@example.com")
	if w := e.post("/ips/labels", f, origin(e.baseURL), signedIn(e)); w.Code != http.StatusSeeOther {
		t.Fatalf("add: %d", w.Code)
	}
	open, closed, _ := strings.Cut(e.get("/anomalies", signedIn(e)).Body.String(), "Closed in the last 30 days")
	if strings.Contains(open, "203.0.113.50") || !strings.Contains(open, "203.0.113.51") {
		t.Error("only the labeled address's anomaly should close")
	}
	if !strings.Contains(closed, "Closed by Heimdall itself") ||
		!strings.Contains(closed, "resolved: 203.0.113.50 is now known (staff: alice@example.com, label &#39;Alice home&#39;)") {
		t.Error("closed list should show it auto-resolved, with the note")
	}
}
