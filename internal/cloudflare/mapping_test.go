// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"net/netip"
	"testing"

	"github.com/chrisreedio/heimdall/internal/store"
)

func TestBuild(t *testing.T) {
	zones := []store.CloudflareZone{{ID: zoneA, Name: "example.com"}, {ID: zoneB, Name: "shop.example.com"}}
	rec := func(zone, name, typ, content string, proxied bool) store.CloudflareRecord {
		return store.CloudflareRecord{ZoneID: zone, Name: name, Type: typ, Content: content, Proxied: proxied}
	}
	recs := []store.CloudflareRecord{
		rec(zoneA, "example.com", "A", "203.0.113.10", true),                // proxied to web-01
		rec(zoneA, "origin.example.com", "A", "203.0.113.10", false),        // exposed
		rec(zoneA, "www.example.com", "CNAME", "origin.example.com", false), // exposed via CNAME
		rec(zoneA, "cdn.example.com", "CNAME", "example.com", false),        // CNAME to a proxied name: not exposed
		rec(zoneA, "old.example.com", "A", "192.0.2.99", true),              // dangling
		rec(zoneA, "office.example.com", "A", "198.51.100.5", false),        // labelled
		rec(zoneA, "edge.example.com", "A", "104.16.0.1", false),            // Cloudflare's own
		rec(zoneA, "lan.example.com", "A", "10.0.0.5", false),               // private
		rec(zoneA, "*.example.com", "A", "203.0.113.10", false),             // wildcard
		rec(zoneB, "shop.example.com", "AAAA", "2001:db8::10", false),       // web-02 (v6), exposed
		rec(zoneA, "loop.example.com", "CNAME", "loop2.example.com", false),
		rec(zoneA, "loop2.example.com", "CNAME", "loop.example.com", false),
	}
	hosts := []store.ReportAddr{
		{OrgID: 1, Org: "acme", Host: "web-01", Addr: netip.MustParseAddr("203.0.113.10")},
		{OrgID: 2, Org: "other", Host: "web-02", Addr: netip.MustParseAddr("2001:db8::10")},
	}
	sites := []store.SiteNames{
		{OrgID: 1, Org: "acme", Host: "web-01", Root: "/srv/example", Names: []string{"example.com", "WWW.example.com.", "_"}},
		{OrgID: 1, Org: "acme", Host: "web-01", Root: "/srv/api", Names: []string{"api.example.com"}},   // wildcard, grey
		{OrgID: 1, Org: "acme", Host: "web-01", Root: "/srv/blog", Names: []string{"blog.example.dev"}}, // no zone
		{OrgID: 2, Org: "other", Host: "web-02", Root: "/srv/shop", Names: []string{"shop.example.com", "localhost", "203.0.113.10"}},
		{OrgID: 2, Org: "other", Host: "web-02", Root: "/srv/none", Names: []string{"gone.shop.example.com"}}, // zone, no record
	}
	office := netip.MustParsePrefix("198.51.100.0/24")
	m := Build(zones, recs, hosts, sites, Known([]netip.Prefix{office}, NewEdge()))
	byName := map[string]Mapped{}
	for _, r := range m.Records {
		byName[r.Name] = r
	}
	for name, want := range map[string]struct {
		exposed, dangling bool
		hosts             int
	}{
		"example.com": {false, false, 1}, "origin.example.com": {true, false, 1}, "www.example.com": {true, false, 1},
		"cdn.example.com": {false, false, 1}, "old.example.com": {false, true, 0}, "office.example.com": {false, false, 0},
		"edge.example.com": {false, false, 0}, "lan.example.com": {false, false, 0}, "shop.example.com": {true, false, 1},
		"loop.example.com": {false, false, 0},
	} {
		got := byName[name]
		if got.Exposed != want.exposed || got.Dangling != want.dangling || len(got.Hosts) != want.hosts {
			t.Errorf("%s: exposed %v dangling %v hosts %d, want %+v", name, got.Exposed, got.Dangling, len(got.Hosts), want)
		}
	}
	if z := byName["shop.example.com"].Zone; z != "shop.example.com" {
		t.Errorf("zone name %q", z)
	}
	if s := byName["www.example.com"].Sites; len(s) != 1 || s[0].Root != "/srv/example" {
		t.Errorf("record → site: %+v", s)
	}
	status := map[string]string{}
	for _, s := range m.Sites {
		status[s.Name] = s.Status
	}
	want := map[string]string{
		"example.com": SiteProxied, "www.example.com": SiteUnproxied, "api.example.com": SiteUnproxied,
		"blog.example.dev": SiteNoZone, "shop.example.com": SiteUnproxied, "gone.shop.example.com": SiteNoRecord,
	}
	if len(status) != len(want) {
		t.Errorf("site names %v", status)
	}
	for n, w := range want {
		if status[n] != w {
			t.Errorf("site %s: %q, want %q", n, status[n], w)
		}
	}
}
