// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

func TestHostPageTailnet(t *testing.T) {
	off := newEnv(t, "http://127.0.0.1:8080", nil)
	off.seed()
	if body := off.get("/hosts/acme/web-01", signedIn(off)).Body.String(); strings.Contains(body, `id="tailnet"`) {
		t.Error("Tailnet card shown with [tailscale] off")
	}

	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.Tailnet = true })
	e.seed()
	ctx := t.Context()
	page := func() string { t.Helper(); return e.get("/hosts/acme/web-01", signedIn(e)).Body.String() }
	hosts := func() string { t.Helper(); return e.get("/hosts?only=tailnet", signedIn(e)).Body.String() }
	if strings.Contains(page(), `id="tailnet"`) || strings.Contains(e.get("/hosts", signedIn(e)).Body.String(), "Not on tailnet") {
		t.Error("Tailnet card or filter shown before any sync")
	}

	devs := []store.TailnetDevice{
		{ID: "nWEB01", Name: "web-01.tail1234.ts.net", Hostname: "web-01", Addresses: []string{"100.64.0.5", "fd7a:115c:a1e0::5"},
			Tags: []string{"tag:server"}, OS: "linux", ClientVersion: "1.88.0", LastSeen: testNow.Add(-3 * 24 * time.Hour),
			KeyExpiry: testNow.Add(5 * 24 * time.Hour)},
		{ID: "nLAPTOP", Name: "laptop-01.tail1234.ts.net", Hostname: "laptop-01", Addresses: []string{"100.101.102.103"},
			User: "alice@example.com", Online: true},
	}
	if err := e.st.ReplaceTailnetDevices(ctx, devs, "oauth", time.Time{}, testNow); err != nil {
		t.Fatal(err)
	}
	body := page()
	for _, want := range []string{`id="tailnet"`, `title="web-01.tail1234.ts.net">web-01`, "last seen 3 days ago", ">tag:server</span>",
		"Tailscale 1.88.0", "node key expires", "<code>100.64.0.5</code> · <code>fd7a:115c:a1e0::5</code>"} {
		if !strings.Contains(body, want) {
			t.Errorf("host page missing %q", want)
		}
	}
	if i, j := strings.Index(body, `id="tailnet"`), strings.Index(body, `id="privilege"`); i < 0 || j < 0 || i > j {
		t.Error("Tailnet card should come right before the privilege card")
	}
	if strings.Contains(hosts(), `href="/hosts/acme/web-01"`) {
		t.Error("web-01 is on the tailnet but listed as not")
	}

	// Renamed on the tailnet: no longer matches by name.
	devs[0].Name, devs[0].Hostname = "web-99.tail1234.ts.net", "web-99"
	if err := e.st.ReplaceTailnetDevices(ctx, devs, "oauth", time.Time{}, testNow); err != nil {
		t.Fatal(err)
	}
	if body := page(); !strings.Contains(body, "Not on the tailnet") {
		t.Error("unmatched host doesn't say it's not on the tailnet")
	}
	list := hosts()
	if !strings.Contains(list, `href="/hosts/acme/web-01"`) || !strings.Contains(list, "Not on tailnet") {
		t.Error("/hosts?only=tailnet doesn't list web-01")
	}
	if strings.Contains(list, `href="/hosts/acme/db-01"`) {
		t.Error("a host that never reported is flagged")
	}

	// Reports coming from its tailnet address match it again.
	host, _ := e.st.HostByName(ctx, "acme", "web-01")
	if err := e.st.RecordReportIP(ctx, host.ID, "100.64.0.5"); err != nil {
		t.Fatal(err)
	}
	if body := page(); !strings.Contains(body, `title="web-99.tail1234.ts.net">web-99`) {
		t.Error("not matched by report address")
	}
}
