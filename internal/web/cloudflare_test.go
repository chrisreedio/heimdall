// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/cloudflare"
	"github.com/chrisreedio/heimdall/internal/store"
)

const (
	cfZone  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfZone2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// seedCloudflare: app-01 (acme) serves example.com from 203.0.113.10;
// web-09 (other org) reports from 203.0.113.20. example.com is proxied,
// www.example.com and origin.example.com expose app-01, other.example.com
// exposes web-09 and old.example.com is dangling. A second zone only has
// acme's records.
func (e *env) seedCloudflare() (acme, other int64) {
	e.t.Helper()
	ctx := e.t.Context()
	host := e.seedSites()
	if err := e.st.RecordReportIP(ctx, host.ID, "203.0.113.10"); err != nil {
		e.t.Fatal(err)
	}
	o, _ := e.st.CreateOrg(ctx, "test", "other", "Other")
	e.st.CreateEnv(ctx, "test", "other", "prod", "")
	if _, _, err := e.st.AddHost(ctx, "test", "other", "prod", "web-09", nil); err != nil {
		e.t.Fatal(err)
	}
	h2, _ := e.st.HostByName(ctx, "other", "web-09")
	e.st.RecordReportIP(ctx, h2.ID, "203.0.113.20")
	rec := func(name, typ, content string, proxied bool) store.CloudflareRecord {
		return store.CloudflareRecord{Name: name, Type: typ, Content: content, Proxied: proxied, TTL: 1}
	}
	err := e.st.ReplaceCloudflareZones(ctx, []store.CloudflareZone{
		{ID: cfZone, Name: "example.com", Plan: "Pro Website", Status: "active"},
		{ID: cfZone2, Name: "example.net", Plan: "Free Website", Status: "active"},
	}, map[string][]store.CloudflareRecord{
		cfZone: {
			rec("example.com", "A", "203.0.113.10", true),
			rec("www.example.com", "A", "203.0.113.10", false),
			rec("origin.example.com", "A", "203.0.113.10", false),
			rec("other.example.com", "A", "203.0.113.20", false),
			rec("old.example.com", "A", "192.0.2.99", true),
		},
		cfZone2: {rec("app.example.net", "A", "203.0.113.10", true)},
	}, testNow)
	if err != nil {
		e.t.Fatal(err)
	}
	sum, _ := json.Marshal(cloudflare.Summary{Total: 42, Requests: 9000, Actions: []cloudflare.Count{{Key: "block", N: 40}, {Key: "managed_challenge", N: 2}},
		Countries: []cloudflare.Count{{Key: "NL", N: 30}}, Paths: []cloudflare.Count{{Key: "/wp-login.php", N: 20}}})
	for _, z := range []string{cfZone, cfZone2} {
		if err := e.st.SetCloudflareSecurity(ctx, z, store.CloudflareSecurityOK, "", sum,
			[]store.CloudflareDaily{{Day: "2026-10-21", Dim: "total", Count: 100}}, testNow); err != nil {
			e.t.Fatal(err)
		}
	}
	e.st.RecordCloudflareSync(ctx, "zones", nil, testNow)
	return host.OrgID, o.ID
}

func TestCloudflarePageAdmin(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seedCloudflare()
	w := e.get("/cloudflare", signedIn(e))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	b := w.Body.String()
	for _, want := range []string{"origin.example.com", "other.example.com", "web-09", "old.example.com", "Dangling records",
		"block 40", "/wp-login.php", "9,000", "legacy.example.com", "no record in example.com", "Pro Website", "100"} {
		if !strings.Contains(b, want) {
			t.Errorf("admin page missing %q", want)
		}
	}
}

func TestCloudflarePageScoping(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	acme, _ := e.seedCloudflare()
	// An operator in acme sees acme's records only, no dangling list, and
	// no counts for example.com, which also holds another org's record.
	e.auth.viewer = &auth.Viewer{UserID: 2, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleOperator}}}
	w := e.get("/cloudflare", signedIn(e))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	b := w.Body.String()
	for _, want := range []string{"origin.example.com", "www.example.com", "shared zone", "example.net", "block 40"} {
		if !strings.Contains(b, want) {
			t.Errorf("operator page missing %q", want)
		}
	}
	for _, leak := range []string{"other.example.com", "web-09", "203.0.113.20", "old.example.com", "Dangling"} {
		if strings.Contains(b, leak) {
			t.Errorf("operator page shows %q", leak)
		}
	}
	// Viewers don't get the overview.
	e.auth.viewer = &auth.Viewer{UserID: 3, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleViewer}}}
	if w := e.get("/cloudflare", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("viewer: %d", w.Code)
	}
}

func TestCloudflareSiteCard(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	path := "/hosts/acme/app-01/site?root=" + siteRoot
	// Nothing synced: no card.
	e.seedSites()
	if b := e.get(path, signedIn(e)).Body.String(); strings.Contains(b, `id="cloudflare"`) {
		t.Error("card shown with nothing synced")
	}
	if b := e.get("/cloudflare", signedIn(e)).Body.String(); !strings.Contains(b, "Nothing synced yet") {
		t.Error("empty overview")
	} else if !strings.Contains(b, `href="https://dash.cloudflare.com/profile/api-tokens?`) || !strings.Contains(b, "Create the token in Cloudflare") {
		t.Error("empty overview has no token link for an admin")
	}

	e = newEnv(t, "http://127.0.0.1:8080", nil)
	acme, _ := e.seedCloudflare()
	b := e.get(path, signedIn(e)).Body.String()
	for _, want := range []string{`id="cloudflare"`, "example.com", "proxied", "not proxied", "block 40", `href="/cloudflare"`} {
		if !strings.Contains(b, want) {
			t.Errorf("site card missing %q", want)
		}
	}
	// A viewer sees the site's names but not the shared zone's counts or
	// the overview link.
	e.auth.viewer = &auth.Viewer{UserID: 3, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleViewer}}}
	b = e.get(path, signedIn(e)).Body.String()
	if !strings.Contains(b, `id="cloudflare"`) || strings.Contains(b, "block 40") || strings.Contains(b, `href="/cloudflare"`) {
		t.Errorf("viewer card wrong")
	}
}

func TestCloudflareNavLink(t *testing.T) {
	for _, on := range []bool{false, true} {
		e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.Cloudflare = on })
		e.seed()
		w := e.get("/", signedIn(e))
		if got := strings.Contains(w.Body.String(), `<a href="/cloudflare"`); got != on {
			t.Errorf("cloudflare on=%v: link shown=%v", on, got)
		}
	}
}
