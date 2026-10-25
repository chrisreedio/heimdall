// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/store"
)

func cfOn(c *Config) { c.Cloudflare = true }

func idCell(name string) string { return `<td class="id">` + name + `</td>` }

func TestSurfacePageCloudflareOff(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seedCloudflare() // stored, but [cloudflare] is off: ignored
	w := e.get("/surface", signedIn(e))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	b := w.Body.String()
	for _, want := range []string{"Cloudflare is off", idCell("example.com"), idCell("www.example.com"), idCell("legacy.example.com"),
		"not on Cloudflare", "1 critical", `href="/surface"`, "Laravel"} {
		if !strings.Contains(b, want) {
			t.Errorf("page missing %q", want)
		}
	}
	for _, no := range []string{"origin exposed", idCell("old.example.com"), "Recent changes", `id="zones"`} {
		if strings.Contains(b, no) {
			t.Errorf("page shows %q with Cloudflare off", no)
		}
	}
}

func TestSurfacePageCloudflareOn(t *testing.T) {
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, cfOn)
	acme, other := e.seedCloudflare()
	ctx := t.Context()
	if err := e.st.SetSurfaceSettings(ctx, cfZone, store.SurfaceOK, "", "flexible", "on", "1.2", testNow); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetSurfaceSettings(ctx, cfZone2, store.SurfacePermission, "no", "", "", "", testNow); err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddSurfaceChanges(ctx, []store.SurfaceChange{
		{At: testNow, ZoneID: cfZone, Zone: "example.com", Name: "www.example.com", Kind: store.SurfaceUnproxied, Orgs: []int64{acme}},
		{At: testNow, ZoneID: cfZone, Zone: "example.com", Name: "other.example.com", Kind: store.SurfaceTarget, Old: "A 203.0.113.21", New: "A 203.0.113.20", Orgs: []int64{other}},
	}, testNow); err != nil {
		t.Fatal(err)
	}

	b := e.get("/surface", signedIn(e)).Body.String()
	for _, want := range []string{idCell("example.com"), idCell("www.example.com"), idCell("other.example.com"), idCell("old.example.com"),
		"origin exposed", "dangling", "Pro Website", "ssl-flexible", "no permission", "proxy turned off", "203.0.113.21",
		"no record in example.com", `aria-current="page">Surface`} {
		if !strings.Contains(b, want) {
			t.Errorf("admin page missing %q", want)
		}
	}
	// The vulnerable names rank first: example.com (the site with the
	// critical finding, proxied) before an unmatched dangling record.
	if i, j := strings.Index(b, idCell("example.com")), strings.Index(b, idCell("old.example.com")); i < 0 || j < 0 || i > j {
		t.Errorf("ranking: example.com at %d, old at %d", i, j)
	}
	// Filters.
	b = e.get("/surface?view=exposed", signedIn(e)).Body.String()
	if !strings.Contains(b, idCell("www.example.com")) || strings.Contains(b, idCell("example.com")) || strings.Contains(b, idCell("app.example.net")) {
		t.Error("exposed filter wrong")
	}
	b = e.get("/surface?zone=example.net", signedIn(e)).Body.String()
	if !strings.Contains(b, idCell("app.example.net")) || strings.Contains(b, idCell("www.example.com")) {
		t.Error("zone filter wrong")
	}
	b = e.get("/surface?view=unmatched", signedIn(e)).Body.String()
	if !strings.Contains(b, idCell("old.example.com")) || strings.Contains(b, idCell("www.example.com")) {
		t.Error("unmatched filter wrong")
	}
}

func TestSurfacePageScoping(t *testing.T) {
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, cfOn)
	acme, other := e.seedCloudflare()
	e.st.AddSurfaceChanges(t.Context(), []store.SurfaceChange{
		{At: testNow, ZoneID: cfZone, Zone: "example.com", Name: "other.example.com", Kind: store.SurfaceAdded, New: "A 203.0.113.20 (not proxied)", Orgs: []int64{other}},
	}, testNow)
	e.auth.viewer = &auth.Viewer{UserID: 2, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleOperator}}}
	w := e.get("/surface", signedIn(e))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	b := w.Body.String()
	for _, want := range []string{idCell("www.example.com"), "app-01", "origin exposed"} {
		if !strings.Contains(b, want) {
			t.Errorf("operator page missing %q", want)
		}
	}
	for _, leak := range []string{"other.example.com", "web-09", "203.0.113.20", "old.example.com"} {
		if strings.Contains(b, leak) {
			t.Errorf("operator page shows %q", leak)
		}
	}
	// Viewers don't get the map, nor the link to it.
	e.auth.viewer = &auth.Viewer{UserID: 3, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleViewer}}}
	if w := e.get("/surface", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("viewer: %d", w.Code)
	}
	if b := e.get("/hosts/acme/app-01", signedIn(e)).Body.String(); strings.Contains(b, `href="/surface"`) || !strings.Contains(b, "Public as") {
		t.Error("viewer host line wrong")
	}
	// Another org's operator sees none of acme's names.
	e.auth.viewer = &auth.Viewer{UserID: 4, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{other: store.RoleOperator}}}
	b = e.get("/surface", signedIn(e)).Body.String()
	if !strings.Contains(b, idCell("other.example.com")) || strings.Contains(b, "app-01") || strings.Contains(b, idCell("www.example.com")) {
		t.Error("other org's view wrong")
	}
	if !strings.Contains(b, "A 203.0.113.20 (not proxied)") {
		t.Error("own org's change missing")
	}
	// ...and can't reach acme's host page to read its line.
	if w := e.get("/hosts/acme/app-01", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("other org host page: %d", w.Code)
	}
}

func TestSurfaceLines(t *testing.T) {
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, cfOn)
	e.seedCloudflare()
	b := e.get("/hosts/acme/app-01", signedIn(e)).Body.String()
	for _, want := range []string{`id="surface-line"`, "example.com</span> (proxied)", "www.example.com</span> (not proxied, origin exposed)", `href="/surface"`} {
		if !strings.Contains(b, want) {
			t.Errorf("host line missing %q", want)
		}
	}
	b = e.get("/hosts/acme/app-01/site?root="+siteRoot, signedIn(e)).Body.String()
	if !strings.Contains(b, `id="surface-line"`) || !strings.Contains(b, "www.example.com</span> (not proxied") || strings.Contains(b, "legacy.example.com</span>") {
		t.Error("site line wrong")
	}
	// Nothing public about a site with no server names: no line.
	b = e.get("/hosts/acme/app-01/site?root=/var/www/html", signedIn(e)).Body.String()
	if strings.Contains(b, `id="surface-line"`) {
		t.Error("line for the default server")
	}
}
