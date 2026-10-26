// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

func TestHostPagePrivilege(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	host := e.seed()
	page := func() string {
		t.Helper()
		return e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	}
	// Never enabled: flagged, with the command that turns it on.
	for _, want := range []string{"Privileged access", "Not watched", ">privilege watch off</span>",
		"<code>sudo heimdall-collect upgrade --watch-privilege-users</code>"} {
		if !strings.Contains(page(), want) {
			t.Errorf("unwatched host page missing %q", want)
		}
	}
	ctx := t.Context()
	at := testNow.Add(-time.Hour).Truncate(time.Second)
	events := []store.PrivilegeEvent{{At: at, Kind: "sudo"}, {At: at.Add(time.Second), Kind: "sudo"},
		{At: at.Add(2 * time.Second), Kind: "root-ssh"}, {At: testNow.Add(-48 * time.Hour), Kind: "su"}}
	if _, _, err := e.st.RecordPrivilege(ctx, host.ID, events, "on", "", testNow); err != nil {
		t.Fatal(err)
	}
	body := page()
	for _, want := range []string{"Privileged access", "2 sudo, 1 root SSH in the last 24 hours", "watched"} {
		if !strings.Contains(body, want) {
			t.Errorf("host page missing %q", want)
		}
	}
	if strings.Contains(body, "priv-recent") {
		t.Error("recent events listed for a host that doesn't record who")
	}
	who := []store.PrivilegeEvent{{At: at.Add(3 * time.Second), Kind: "sudo", User: "chris", Source: "203.0.113.7"},
		{At: at.Add(4 * time.Second), Kind: "root-ssh", User: "root", Source: "2001:db8::1"}}
	if _, _, err := e.st.RecordPrivilege(ctx, host.ID, who, "on", "", testNow); err != nil {
		t.Fatal(err)
	}
	body = page()
	for _, want := range []string{`by chris from <a href="/ips/203.0.113.7">203.0.113.7</a>`,
		`root SSH <span class="priv-who">by root from <a href="/ips/2001:db8::1">2001:db8::1</a></span>`} {
		if !strings.Contains(body, want) {
			t.Errorf("host page missing %q", want)
		}
	}
	// What the hook records, as the collector reports it.
	for detail, want := range map[string]string{"": "privilege detail unknown", store.PrivilegeKinds: "who not recorded",
		store.PrivilegeUsers: "no source IP", store.PrivilegeSources: ""} {
		if _, _, err := e.st.RecordPrivilege(ctx, host.ID, nil, "on", detail, testNow); err != nil {
			t.Fatal(err)
		}
		body, hosts := page(), e.get("/hosts?only=privilege", signedIn(e)).Body.String()
		if want == "" {
			if strings.Contains(body, "priv-fix") || strings.Contains(hosts, `href="/hosts/acme/web-01"`) {
				t.Errorf("%s: flagged a fully watched host", detail)
			}
			if !strings.Contains(e.get("/", signedIn(e)).Body.String(), "all record who and where") {
				t.Error("dashboard should say every Linux host is fully watched")
			}
			continue
		}
		if !strings.Contains(body, ">"+want+"</span>") || !strings.Contains(hosts, `href="/hosts/acme/web-01"`) || !strings.Contains(hosts, ">"+want+"</span>") {
			t.Errorf("%q: host page or list doesn't flag %q", detail, want)
		}
	}
	if _, _, err := e.st.RecordPrivilege(ctx, host.ID, nil, "partial", "", testNow); err != nil {
		t.Fatal(err)
	}
	if body := page(); !strings.Contains(body, "privilege watch partly removed") {
		t.Error("host page missing the watch-off warning")
	}
}
