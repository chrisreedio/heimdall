// SPDX-License-Identifier: AGPL-3.0-or-later

package surface

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

const (
	zA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	zB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var now = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func rec(zone, name, typ, content string, proxied bool) store.CloudflareRecord {
	return store.CloudflareRecord{ZoneID: zone, Name: name, Type: typ, Content: content, Proxied: proxied, TTL: 1}
}

// fixture: acme's web-01 (203.0.113.10) runs shop.example.com, a Laravel
// site with a critical finding; web-02 (203.0.113.11) has only a medium OS
// finding; other org's web-09 (203.0.113.20) a high one.
func fixture() Input {
	return Input{
		Now: now,
		Zones: []store.CloudflareZone{
			{ID: zA, Name: "example.com", Plan: "Pro Website", Status: "active"},
			{ID: zB, Name: "example.net", Plan: "Free Website", Status: "active"},
		},
		Records: []store.CloudflareRecord{
			rec(zA, "shop.example.com", "A", "203.0.113.10", true),
			rec(zA, "api.example.com", "A", "203.0.113.11", false),
			rec(zA, "blog.example.com", "CNAME", "acme.herokuapp.com", true),
			rec(zA, "docs.example.com", "CNAME", "acme.github.io", true),
			rec(zA, "*.example.com", "A", "203.0.113.11", true),
			rec(zA, "alias.example.com", "CNAME", "gone.example.com", false),
			rec(zA, "partner.example.com", "A", "203.0.113.20", false),
			rec(zB, "old.example.net", "A", "192.0.2.99", false),
		},
		Settings: map[string]store.SurfaceSettings{
			zA: {State: store.SurfaceOK, SSL: "flexible", AlwaysHTTPS: "off", MinTLS: "1.0", CertExpires: now.Add(5 * 24 * time.Hour)},
			zB: {State: store.SurfacePermission},
		},
		CNAMEs: map[string]store.CNAMECheck{
			"acme.herokuapp.com": {Target: "acme.herokuapp.com", Status: store.CNAMENXDomain},
			"acme.github.io":     {Target: "acme.github.io", Status: store.CNAMEOK},
		},
		Addrs: []store.ReportAddr{
			{OrgID: 1, Org: "acme", Host: "web-01", Addr: netip.MustParseAddr("203.0.113.10")},
			{OrgID: 1, Org: "acme", Host: "web-02", Addr: netip.MustParseAddr("203.0.113.11")},
			{OrgID: 2, Org: "other", Host: "web-09", Addr: netip.MustParseAddr("203.0.113.20")},
		},
		Sites: []store.SiteNames{
			{OrgID: 1, Org: "acme", Host: "web-01", Root: "/srv/shop", Names: []string{"shop.example.com"}},
			{OrgID: 1, Org: "acme", Host: "web-02", Root: "/srv/wild", Names: []string{"promo.example.com"}},
			{OrgID: 1, Org: "acme", Host: "web-02", Root: "/srv/intra", Names: []string{"intra.acme.test"}},
		},
		Hosts: []store.SurfaceHost{
			{ID: 10, OrgID: 1, Org: "acme", Name: "web-01", OS: "Debian GNU/Linux 12 (bookworm)"},
			{ID: 11, OrgID: 1, Org: "acme", Name: "web-02", OS: "Ubuntu 24.04"},
			{ID: 20, OrgID: 2, Org: "other", Name: "web-09", OS: "Rocky Linux 9"},
		},
		Stacks: []store.SurfaceSite{{HostID: 10, Root: "/srv/shop", Framework: "laravel", FrameworkVersion: "11.31.0", PHP: "8.3", WebServer: "nginx"}},
		Counts: map[int64]map[string]store.FindingCounts{
			10: {"/srv/shop": {Critical: 2, KEV: 1}, "": {Low: 3}},
			11: {"": {Medium: 1}},
			20: {"": {High: 4}},
		},
	}
}

func byName(m Map) map[string]Row {
	out := map[string]Row{}
	for _, r := range m.Rows {
		out[r.Name] = r
	}
	return out
}

func hasFlag(r Row, kind string) bool {
	return slices.ContainsFunc(r.Flags, func(f Flag) bool { return f.Kind == kind })
}

func TestBuildChain(t *testing.T) {
	m := Build(fixture())
	rows := byName(m)
	shop := rows["shop.example.com"]
	if shop.Zone != "example.com" || shop.Plan != "Pro Website" || shop.Status != Proxied || shop.Exposed ||
		len(shop.Hosts) != 1 || shop.Hosts[0].Name != "web-01" || len(shop.Sites) != 1 || shop.Sites[0].Root != "/srv/shop" ||
		shop.Sites[0].Software != "Laravel 11.31.0 · PHP 8.3 · nginx" || shop.Worst.Critical != 2 || shop.Worst.Low != 3 || shop.Worst.KEV != 1 {
		t.Errorf("shop: %+v", shop)
	}
	api := rows["api.example.com"]
	if api.Status != Unproxied || !api.Exposed || len(api.Hosts) != 1 || api.Hosts[0].Name != "web-02" || api.Worst.Medium != 1 {
		t.Errorf("api: %+v", api)
	}
	// A site name only the wildcard covers follows it to the host.
	promo := rows["promo.example.com"]
	if !promo.Wildcard || promo.Status != Proxied || len(promo.Sites) != 1 || len(promo.Hosts) != 1 || promo.Hosts[0].Name != "web-02" {
		t.Errorf("promo: %+v", promo)
	}
	// A site name in no zone is still on the map.
	intra := rows["intra.acme.test"]
	if intra.Status != OffCF || intra.Zone != "" || len(intra.Hosts) != 1 {
		t.Errorf("intra: %+v", intra)
	}
	if !rows["old.example.net"].Unmatched() || !hasFlag(rows["old.example.net"], "dangling") {
		t.Errorf("old: %+v", rows["old.example.net"])
	}
	// Zone settings: flexible SSL, HTTP allowed, old TLS, cert expiring.
	z := m.Zones[0]
	for _, k := range []string{"ssl-flexible", "http-allowed", "old-tls", "cert-expiry"} {
		if !slices.ContainsFunc(z.Flags, func(f Flag) bool { return f.Kind == k }) {
			t.Errorf("zone flags missing %s: %+v", k, z.Flags)
		}
	}
	if len(m.Zones[1].Flags) != 0 || len(shop.ZoneFlags) != 4 {
		t.Errorf("zone flags: %+v / %+v", m.Zones[1].Flags, shop.ZoneFlags)
	}
	// Coverage: shop, blog, docs, *, promo proxied; api, alias, partner not.
	if z.Proxied != 5 || z.Unproxied != 3 || z.Coverage() != 62 {
		t.Errorf("coverage %d/%d", z.Proxied, z.Unproxied)
	}
}

func TestRiskyRecords(t *testing.T) {
	rows := byName(Build(fixture()))
	blog := rows["blog.example.com"]
	if !hasFlag(blog, "third-party") || !hasFlag(blog, "takeover") || !blog.HighFlag() {
		t.Errorf("blog: %+v", blog.Flags)
	}
	docs := rows["docs.example.com"]
	if !hasFlag(docs, "third-party") || hasFlag(docs, "takeover") {
		t.Errorf("docs: %+v", docs.Flags)
	}
	if w := rows["*.example.com"]; !w.Wildcard || !hasFlag(w, "wildcard") {
		t.Errorf("wildcard: %+v", w)
	}
	if a := rows["alias.example.com"]; !hasFlag(a, "dangling-cname") {
		t.Errorf("alias: %+v", a.Flags)
	}
	if hasFlag(rows["shop.example.com"], "wildcard") {
		t.Error("shop flagged wildcard")
	}
}

func TestRanking(t *testing.T) {
	m := Build(fixture())
	var names []string
	for _, r := range m.Rows {
		names = append(names, r.Name)
	}
	// Vulnerable first (KEV + critical, then high), then the takeover,
	// then the exposed origin.
	want := []string{"shop.example.com", "partner.example.com", "blog.example.com"}
	if !slices.Equal(names[:3], want) {
		t.Fatalf("order: %v", names)
	}
	if i, j := slices.Index(names, "api.example.com"), slices.Index(names, "docs.example.com"); i > j {
		t.Errorf("exposed api after docs: %v", names)
	}
}

func TestForScoping(t *testing.T) {
	m := Build(fixture()).For(false, func(o int64) bool { return o == 1 })
	rows := byName(m)
	if _, ok := rows["partner.example.com"]; ok {
		t.Error("other org's name shown")
	}
	if _, ok := rows["old.example.net"]; ok {
		t.Error("unmatched name shown to an operator")
	}
	for _, r := range m.Rows {
		for _, h := range r.Hosts {
			if h.Org != "acme" {
				t.Errorf("%s shows host %s", r.Name, h.Name)
			}
		}
	}
	if len(m.Zones) != 1 || m.Zones[0].Name != "example.com" || m.Zones[0].Proxied != 3 || m.Zones[0].Unproxied != 1 { // shop, *, promo; api
		t.Errorf("zones: %+v", m.Zones)
	}
	if m.Rows[0].Name != "shop.example.com" {
		t.Errorf("first: %s", m.Rows[0].Name)
	}
}

func TestWithoutCloudflare(t *testing.T) {
	in := fixture()
	in.Zones, in.Records, in.Settings, in.CNAMEs, in.Addrs = nil, nil, nil, nil, nil
	m := Build(in)
	if len(m.Rows) != 3 || len(m.Zones) != 0 {
		t.Fatalf("rows %d zones %d", len(m.Rows), len(m.Zones))
	}
	for _, r := range m.Rows {
		if r.Status != OffCF || len(r.Hosts) != 1 {
			t.Errorf("%+v", r)
		}
	}
	if m.Rows[0].Name != "shop.example.com" || !m.Rows[0].Match(ViewVulnerable, "") || m.Rows[1].Match(ViewVulnerable, "") {
		t.Errorf("rank or view: %+v", m.Rows)
	}
}
