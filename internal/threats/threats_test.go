// SPDX-License-Identifier: AGPL-3.0-or-later

package threats

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/bans"
	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/logins"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

var testNow = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

type rig struct {
	t        *testing.T
	st       *store.Store
	hosts    map[string]store.IngestHost
	l        *Lister
	acme     int64
	globex   int64
	zoneOrgs map[string][]int64
}

func newRig(t *testing.T) *rig {
	t.Helper()
	st := storetest.New(t)
	ctx := t.Context()
	r := &rig{t: t, st: st, hosts: map[string]store.IngestHost{}, zoneOrgs: map[string][]int64{}}
	for _, org := range []string{"acme", "globex"} {
		st.CreateOrg(ctx, "test", org, "")
		st.CreateEnv(ctx, "test", org, "prod", "")
		for _, name := range []string{"web-01", "web-02", "web-03"} {
			if _, _, err := st.AddHost(ctx, "test", org, "prod", name, nil); err != nil {
				t.Fatal(err)
			}
			h, _ := st.HostByName(ctx, org, name)
			r.hosts[org+"/"+name] = h
		}
	}
	r.acme, r.globex = r.hosts["acme/web-01"].OrgID, r.hosts["globex/web-01"].OrgID
	ips := &ipinfo.Resolver{Store: st, Sources: []ipinfo.Source{ipinfo.Hosts{Store: st}, ipinfo.SignIns{Store: st}}}
	r.l = &Lister{Store: st, Ranker: &logins.Ranker{Store: st, IPs: ips}, Bans: config.BansDefaults,
		Now: func() time.Time { return testNow }}
	return r
}

// fail records failures from ip on a host, ago before now.
func (r *rig) fail(host, ip string, n, users int, succeeded bool, ago time.Duration) {
	r.t.Helper()
	at := testNow.Add(-ago)
	day := store.LoginDay{Day: at.Format(time.DateOnly), Failures: n, Addresses: 1,
		Rows: []store.LoginFailure{{IP: ip, Failures: n, Usernames: users, First: at.Add(-time.Minute), Last: at, Succeeded: succeeded}}}
	if err := r.st.RecordLogins(r.t.Context(), r.hosts[host].ID, store.LoginReport{Source: "journal", Days: []store.LoginDay{day}}, testNow); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) list(q Query) Result {
	r.t.Helper()
	res, err := r.l.Addresses(r.t.Context(), q)
	if err != nil {
		r.t.Fatal(err)
	}
	return res
}

func (r *rig) viewer(orgs ...int64) store.Scope {
	sc := store.Scope{Orgs: map[int64]store.Role{}}
	for _, o := range orgs {
		sc.Orgs[o] = store.RoleViewer
	}
	return sc
}

func ips(res Result) []string {
	var out []string
	for _, a := range res.Addresses {
		out = append(out, a.IP)
	}
	slices.Sort(out)
	return out
}

func find(res Result, ip string) *Address {
	for i := range res.Addresses {
		if res.Addresses[i].IP == ip {
			return &res.Addresses[i]
		}
	}
	return nil
}

func TestFriendlyExcluded(t *testing.T) {
	r := newRig(t)
	ctx := t.Context()
	for _, ip := range []string{
		"198.51.100.9", // nobody knows it: listed
		"10.0.0.5",     // private
		"100.64.1.2",   // the tailnet
		"173.245.48.5", // Cloudflare's edge
		"203.0.113.7",  // labelled, in another org than the one it hit
		"192.0.2.10",   // one of your hosts reports from it
		"192.0.2.20",   // someone signed in to Heimdall from it (weeks ago)
		"2001:db8:9::1",
	} {
		r.fail("acme/web-01", ip, 30, 4, false, time.Hour)
	}
	if _, err := r.st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: r.globex, Prefix: netip.MustParsePrefix("203.0.113.0/28"),
		Kind: store.IPKindStaff, Name: "Office"}); err != nil {
		t.Fatal(err)
	}
	r.st.RecordReportIP(ctx, r.hosts["globex/web-02"].ID, "192.0.2.10")
	uid, err := r.st.CreateLocalUser(ctx, "test", "admin@example.com", "", true, "$argon2id$x", []byte("secretsecretsecret12"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.st.CreateSession(ctx, [32]byte{1}, uid, testNow.Add(-20*24*time.Hour), testNow.Add(time.Hour), "192.0.2.20", "test"); err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.9", "2001:db8:9::1"}
	for name, sc := range map[string]store.Scope{"admin": store.AllScope, "acme viewer": r.viewer(r.acme)} {
		if got := ips(r.list(Query{Scope: sc})); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	// The web side is filtered the same way.
	r.l.Web = func(context.Context, []string, time.Time) ([]WebOffender, error) {
		return []WebOffender{{IP: "203.0.113.3", Events: 5}, {IP: "173.245.48.9", Events: 5}, {IP: "198.51.100.77", Events: 5}}, nil
	}
	if got := ips(r.list(Query{Scope: store.AllScope, Source: SourceWeb})); !slices.Equal(got, []string{"198.51.100.77"}) {
		t.Errorf("web: %v", got)
	}
}

func TestOrgScoping(t *testing.T) {
	r := newRig(t)
	r.fail("acme/web-01", "198.51.100.9", 20, 3, false, time.Hour)
	r.fail("globex/web-01", "198.51.100.9", 10, 2, true, 2*time.Hour)
	r.fail("globex/web-02", "198.51.100.20", 50, 9, false, time.Hour) // globex's only
	acme := r.viewer(r.acme)

	res := r.list(Query{Scope: acme})
	if got := ips(res); !slices.Equal(got, []string{"198.51.100.9"}) {
		t.Fatalf("acme sees %v", got)
	}
	if a := res.Addresses[0]; a.SSH.Hosts != 1 || a.SSH.Failures != 20 || a.SSH.Succeeded || a.SSH.Usernames != 3 {
		t.Errorf("acme's view counts another org's hosts: %+v", a.SSH)
	}
	if _, err := r.l.Addresses(t.Context(), Query{Scope: acme, Org: "globex"}); !errors.Is(err, ErrForbidden) {
		t.Errorf("another org: %v", err)
	}
	if _, err := r.l.Addresses(t.Context(), Query{Scope: acme, Org: "nope"}); !errors.Is(err, ErrForbidden) {
		t.Errorf("a missing org must look like another's: %v", err)
	}
	if _, err := r.l.Addresses(t.Context(), Query{Scope: store.Scope{}}); !errors.Is(err, ErrForbidden) {
		t.Errorf("no roles: %v", err)
	}
	var ve *store.ValidationError
	if _, err := r.l.Addresses(t.Context(), Query{Scope: store.AllScope, Org: "nope"}); !errors.As(err, &ve) {
		t.Errorf("admin, missing org: %v", err)
	}

	all := r.list(Query{Scope: store.AllScope})
	if a := find(all, "198.51.100.9"); a == nil || a.SSH.Hosts != 2 || a.SSH.Failures != 30 || !a.SSH.Succeeded {
		t.Errorf("hub-wide: %+v", a)
	}
	g := r.list(Query{Scope: store.AllScope, Org: "globex"})
	if a := find(g, "198.51.100.9"); a == nil || a.SSH.Hosts != 1 || a.SSH.Failures != 10 {
		t.Errorf("admin, org globex: %+v", a)
	}
	if find(g, "198.51.100.20") == nil {
		t.Error("admin, org globex: missing globex's offender")
	}

	// Filters and the limit.
	if got := r.list(Query{Scope: store.AllScope, MinHosts: 2}); len(got.Addresses) != 1 || got.Addresses[0].IP != "198.51.100.9" {
		t.Errorf("min_hosts: %v", ips(got))
	}
	if got := r.list(Query{Scope: store.AllScope, MinScore: 1000}); len(got.Addresses) != 0 {
		t.Errorf("min_score: %v", ips(got))
	}
	if got := r.list(Query{Scope: store.AllScope, Limit: 1}); len(got.Addresses) != 1 || !got.Truncated || got.Total != 2 {
		t.Errorf("limit: %+v", got)
	}
	if got := r.list(Query{Scope: store.AllScope, Window: 30 * time.Minute}); len(got.Addresses) != 0 {
		t.Errorf("since 30m: %v", ips(got))
	}
	// Times are UTC whatever the hub's zone.
	r.l.Now = func() time.Time { return testNow.In(time.FixedZone("UTC-5", -5*3600)) }
	if got := r.list(Query{Scope: store.AllScope}); got.Since.Location() != time.UTC || got.GeneratedAt.Location() != time.UTC ||
		got.Addresses[0].LastSeen.Location() != time.UTC {
		t.Errorf("not UTC: %v %v", got.Since, got.GeneratedAt)
	}
}

func TestScoresMatchBans(t *testing.T) {
	r := newRig(t)
	ctx := t.Context()
	r.fail("acme/web-01", "198.51.100.9", 40, 6, false, time.Hour)
	r.fail("acme/web-02", "198.51.100.9", 12, 2, false, 30*time.Hour)
	r.fail("globex/web-01", "198.51.100.9", 9, 1, false, time.Hour)
	r.fail("globex/web-03", "203.0.113.50", 200, 25, true, 2*time.Hour)
	r.fail("acme/web-03", "198.51.100.10", 3, 1, false, time.Hour)
	r.fail("acme/web-03", "2001:db8:5::7", 15, 3, false, 3*24*time.Hour)
	for _, ip := range []string{"198.51.100.9", "198.51.100.10", "203.0.113.50"} { // same ASN: peers count
		if err := r.st.PutCloudflareRadar(ctx, store.CloudflareRadar{IP: ip, ASN: 64500, Name: "Example ISP", Country: "US", FetchedAt: testNow}); err != nil {
			t.Fatal(err)
		}
	}
	e := &bans.Engine{Store: r.st, Ranker: r.l.Ranker, Cfg: config.BansDefaults, Now: func() time.Time { return testNow }}
	cands, err := e.Candidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	res := r.list(Query{Scope: store.AllScope, Window: config.BansDefaults.Window.Duration})
	if len(res.Addresses) != 4 {
		t.Fatalf("%d addresses", len(res.Addresses))
	}
	for _, a := range res.Addresses {
		addr := netip.MustParseAddr(a.IP)
		var want *bans.Candidate
		for i := range cands {
			if cands[i].Kind == bans.KindAddress && cands[i].Target == bans.AddressTarget(addr) {
				want = &cands[i]
			}
		}
		if want == nil || want.Score != a.Score {
			t.Errorf("%s: score %v, /bans %+v", a.IP, a.Score, want)
		}
		if a.Score == 0 {
			t.Errorf("%s scored 0", a.IP)
		}
	}
	if a := find(res, "198.51.100.9"); a.ASN != 64500 || a.ASName != "Example ISP" || a.Country != "US" || a.SSH.Days != 2 {
		t.Errorf("radar or days: %+v", a)
	}
	if res.Addresses[0].IP != "203.0.113.50" {
		t.Errorf("not highest score first: %v", res.Addresses[0].IP)
	}
}

func TestBanStatus(t *testing.T) {
	r := newRig(t)
	ctx := t.Context()
	r.fail("acme/web-01", "198.51.100.9", 20, 3, false, time.Hour)
	r.fail("acme/web-01", "203.0.113.50", 20, 3, false, time.Hour)
	if _, err := r.st.AddBan(ctx, store.Ban{Target: "198.51.100.0/24", Kind: bans.KindNetwork, Action: bans.Challenge,
		Status: store.BanActive, Mode: config.BansAuto, Duration: 7 * 24 * time.Hour, ExpiresAt: testNow.Add(24 * time.Hour)}, "test", testNow); err != nil {
		t.Fatal(err)
	}
	res := r.list(Query{Scope: store.AllScope})
	if b := find(res, "198.51.100.9").Ban; b == nil || b.Status != store.BanActive || b.Target != "198.51.100.0/24" || b.Kind != bans.KindNetwork {
		t.Errorf("ban: %+v", b)
	}
	if b := find(res, "203.0.113.50").Ban; b != nil {
		t.Errorf("no ban expected: %+v", b)
	}
	// Viewers don't see bans (/bans is for operators).
	if b := find(r.list(Query{Scope: r.viewer(r.acme)}), "198.51.100.9").Ban; b != nil {
		t.Errorf("viewer sees a ban: %+v", b)
	}
	op := store.Scope{Orgs: map[int64]store.Role{r.acme: store.RoleOperator}}
	if b := find(r.list(Query{Scope: op}), "198.51.100.9").Ban; b == nil {
		t.Error("operator doesn't see the ban")
	}
}

func TestNetworks(t *testing.T) {
	r := newRig(t)
	ctx := t.Context()
	r.fail("acme/web-01", "198.51.100.1", 50, 5, false, time.Hour)
	r.fail("acme/web-02", "198.51.100.2", 10, 2, false, time.Hour)
	r.fail("globex/web-01", "198.51.100.3", 5, 1, false, time.Hour)
	r.fail("acme/web-01", "203.0.113.9", 30, 3, false, time.Hour)
	r.fail("acme/web-01", "2001:db8:1:2::1", 7, 1, false, time.Hour)
	r.fail("acme/web-02", "2001:db8:1:3::1", 7, 1, false, time.Hour)
	for _, ip := range []string{"198.51.100.1", "203.0.113.9"} {
		r.st.PutCloudflareRadar(ctx, store.CloudflareRadar{IP: ip, ASN: 64500, Name: "Example ISP", Country: "US", FetchedAt: testNow})
	}
	res, err := r.l.Networks(ctx, Query{Scope: store.AllScope})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Network{}
	for _, n := range res.Networks {
		by[n.Network] = n
	}
	if n := by["198.51.100.0/24"]; n.Kind != KindPrefix || n.Addresses != 3 || n.Failures != 65 || n.Hosts != 3 ||
		len(n.Top) != 3 || n.Top[0] != "198.51.100.1" || n.ASN != 64500 {
		t.Errorf("/24: %+v", n)
	}
	if n := by["2001:db8:1::/48"]; n.Addresses != 2 || n.Hosts != 2 {
		t.Errorf("/48: %+v", n)
	}
	if n := by["AS64500"]; n.Kind != KindASN || n.Addresses != 2 || n.Failures != 80 || n.ASName != "Example ISP" {
		t.Errorf("ASN: %+v", n)
	}
	if res.Networks[0].Network != "198.51.100.0/24" {
		t.Errorf("not most addresses first: %+v", res.Networks[0])
	}
	// Kind, min_addresses and scope.
	res, _ = r.l.Networks(ctx, Query{Scope: store.AllScope, Kind: KindASN})
	if len(res.Networks) != 1 || res.Networks[0].Network != "AS64500" {
		t.Errorf("kind asn: %+v", res.Networks)
	}
	res, _ = r.l.Networks(ctx, Query{Scope: store.AllScope, Kind: KindPrefix, MinAddresses: 3})
	if len(res.Networks) != 1 || res.Networks[0].Network != "198.51.100.0/24" {
		t.Errorf("min_addresses: %+v", res.Networks)
	}
	res, _ = r.l.Networks(ctx, Query{Scope: r.viewer(r.globex), Kind: KindPrefix})
	if len(res.Networks) != 1 || res.Networks[0].Addresses != 1 || res.Networks[0].Top[0] != "198.51.100.3" {
		t.Errorf("globex viewer: %+v", res.Networks)
	}
}

func TestWebSeam(t *testing.T) {
	r := newRig(t)
	r.fail("acme/web-01", "198.51.100.9", 20, 3, false, time.Hour)
	// Unwired: no web rows, nothing breaks.
	if r.l.Web != nil {
		t.Fatal("the web source must start unwired")
	}
	if res := r.list(Query{Scope: store.AllScope, Source: SourceWeb}); len(res.Addresses) != 0 {
		t.Errorf("web rows without a source: %v", ips(res))
	}
	res := r.list(Query{Scope: store.AllScope})
	if a := find(res, "198.51.100.9"); a == nil || !slices.Equal(a.Sources, []string{"ssh"}) || a.Web.Events != 0 ||
		a.Web.Zones == nil || a.Web.Actions == nil {
		t.Errorf("ssh-only row: %+v", a)
	}

	// The seam asks for the caller's orgs, nil meaning every zone.
	var asked [][]string
	r.l.Web = func(_ context.Context, orgs []string, since time.Time) ([]WebOffender, error) {
		asked = append(asked, orgs)
		if !since.Equal(testNow.Add(-DefaultWindow)) {
			t.Errorf("since %v", since)
		}
		return nil, nil
	}
	r.list(Query{Scope: store.AllScope})
	r.list(Query{Scope: store.AllScope, Org: "globex"})
	r.list(Query{Scope: store.Scope{Orgs: map[int64]store.Role{r.acme: store.RoleViewer, r.globex: store.RoleViewer}}})
	r.list(Query{Scope: store.AllScope, Source: SourceSSH}) // not asked
	if len(asked) != 3 || asked[0] != nil || !slices.Equal(asked[1], []string{"globex"}) || !slices.Equal(asked[2], []string{"acme", "globex"}) {
		t.Errorf("asked for %q", asked)
	}
}

// web records a zone's offenders for today, mapped to orgs.
func (r *rig) web(zoneID, name string, orgs []int64, rows ...store.WebOffenderDay) {
	r.t.Helper()
	ctx := r.t.Context()
	zs, err := r.st.CloudflareZones(ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	zs = append(zs, store.CloudflareZone{ID: zoneID, Name: name, Plan: "Pro", Status: "active"})
	if err := r.st.ReplaceCloudflareZones(ctx, zs, nil, testNow); err != nil {
		r.t.Fatal(err)
	}
	r.zoneOrgs[zoneID] = orgs
	if err := r.st.SetCloudflareZoneOrgs(ctx, r.zoneOrgs); err != nil {
		r.t.Fatal(err)
	}
	day := store.WebDay{Day: testNow.Format(time.DateOnly), Final: false, Rows: rows}
	if err := r.st.RecordWebOffenders(ctx, zoneID, []store.WebDay{day}, testNow); err != nil {
		r.t.Fatal(err)
	}
}

func webRow(ip string, events int, action string, ago time.Duration) store.WebOffenderDay {
	at := testNow.Add(-ago)
	return store.WebOffenderDay{IP: ip, Events: events, Actions: map[string]int{action: events}, First: at.Add(-time.Hour), Last: at}
}

func TestWebSource(t *testing.T) {
	r := newRig(t)
	r.l.Web = StoreWeb(r.st)
	r.fail("acme/web-01", "198.51.100.9", 20, 3, false, time.Hour)
	const (
		zoneA = "0123456789abcdef0123456789abcd0a"
		zoneG = "0123456789abcdef0123456789abcd0b"
		zoneS = "0123456789abcdef0123456789abcd0c"
		zoneU = "0123456789abcdef0123456789abcd0d"
	)
	r.web(zoneA, "acme.example.com", []int64{r.acme}, webRow("198.51.100.9", 7, "block", time.Minute))
	g := webRow("203.0.113.60", 3, "managed_challenge", 4*time.Hour)
	g.ASN, g.ASName, g.Country = 64501, "Other ISP", "NL"
	r.web(zoneG, "globex.example.com", []int64{r.globex}, g)
	r.web(zoneS, "shared.example.com", []int64{r.acme, r.globex}, webRow("203.0.113.60", 5, "block", 2*time.Hour))
	r.web(zoneU, "unmapped.example.net", nil, webRow("203.0.113.61", 2, "block", time.Hour), webRow("173.245.48.9", 9, "block", time.Hour))

	// An admin: every zone, mapped or not.
	res := r.list(Query{Scope: store.AllScope})
	a := find(res, "198.51.100.9")
	if a == nil || !slices.Equal(a.Sources, []string{"ssh", "web"}) || a.Web.Events != 7 || a.Web.Actions["block"] != 7 ||
		!slices.Equal(a.Web.Zones, []string{"acme.example.com"}) || a.Web.Days != 1 || a.SSH.Hosts != 1 ||
		!a.LastSeen.Equal(testNow.Add(-time.Minute)) || !a.FirstSeen.Equal(testNow.Add(-time.Hour-time.Minute)) {
		t.Errorf("merged: %+v", a)
	}
	w := find(res, "203.0.113.60")
	if w == nil || !slices.Equal(w.Sources, []string{"web"}) || w.Web.Events != 8 || w.Web.Actions["block"] != 5 ||
		w.Web.Actions["managed_challenge"] != 3 || !slices.Equal(w.Web.Zones, []string{"globex.example.com", "shared.example.com"}) ||
		w.ASN != 64501 || w.ASName != "Other ISP" || w.Country != "NL" || w.Score != 0 || w.SSH.Hosts != 0 {
		t.Errorf("web only: %+v", w)
	}
	if find(res, "203.0.113.61") == nil {
		t.Error("admin misses an unmapped zone's offender")
	}
	if find(res, "173.245.48.9") != nil {
		t.Error("Cloudflare's edge listed")
	}

	// An acme viewer: acme's zones only, and the shared one.
	res = r.list(Query{Scope: r.viewer(r.acme)})
	if w := find(res, "203.0.113.60"); w == nil || w.Web.Events != 5 || !slices.Equal(w.Web.Zones, []string{"shared.example.com"}) || w.ASN != 0 {
		t.Errorf("acme's view: %+v", w)
	}
	if find(res, "203.0.113.61") != nil {
		t.Error("acme sees an unmapped zone")
	}
	// In both orgs: the shared zone counts once.
	res = r.list(Query{Scope: r.viewer(r.acme, r.globex)})
	if w := find(res, "203.0.113.60"); w == nil || w.Web.Events != 8 || len(w.Web.Zones) != 2 {
		t.Errorf("two orgs: %+v", w)
	}
	// Org filter, for an admin.
	res = r.list(Query{Scope: store.AllScope, Org: "globex"})
	if got := ips(res); !slices.Equal(got, []string{"203.0.113.60"}) {
		t.Errorf("org globex: %v", got)
	}

	// Source and min_hosts.
	res = r.list(Query{Scope: store.AllScope, Source: SourceWeb})
	if got := ips(res); !slices.Equal(got, []string{"198.51.100.9", "203.0.113.60", "203.0.113.61"}) {
		t.Errorf("source=web: %v", got)
	}
	res = r.list(Query{Scope: store.AllScope, Source: SourceSSH})
	if got := ips(res); !slices.Equal(got, []string{"198.51.100.9"}) || res.Addresses[0].Web.Events != 0 {
		t.Errorf("source=ssh: %v", res.Addresses)
	}
	if got := ips(r.list(Query{Scope: store.AllScope, MinHosts: 1})); !slices.Equal(got, []string{"198.51.100.9"}) {
		t.Errorf("min_hosts: %v", got)
	}

	// Rollups count web events.
	nets, err := r.l.Networks(t.Context(), Query{Scope: store.AllScope, Kind: KindPrefix})
	if err != nil {
		t.Fatal(err)
	}
	var n *Network
	for i := range nets.Networks {
		if nets.Networks[i].Network == "203.0.113.0/24" {
			n = &nets.Networks[i]
		}
	}
	if n == nil || n.Addresses != 2 || n.Events != 10 || n.Failures != 0 || n.Hosts != 0 || n.ASN != 64501 {
		t.Errorf("web /24: %+v", n)
	}
	nets, _ = r.l.Networks(t.Context(), Query{Scope: store.AllScope, Kind: KindASN})
	if len(nets.Networks) != 1 || nets.Networks[0].Network != "AS64501" || nets.Networks[0].Events != 8 {
		t.Errorf("web ASN: %+v", nets.Networks)
	}
}

func TestParse(t *testing.T) {
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	q, err := Parse(get(nil), RESTLimits)
	if err != nil || q.Window != DefaultWindow || q.Source != SourceAll || q.Limit != 1000 || q.MinAddresses != 1 {
		t.Errorf("defaults: %+v %v", q, err)
	}
	q, err = Parse(get(map[string]string{"since": "36h", "min_score": "12.5", "min_hosts": "2", "source": "SSH",
		"limit": "50", "org": "acme", "kind": "prefix", "min_addresses": "3"}), RESTLimits)
	if err != nil || q.Window != 36*time.Hour || q.MinScore != 12.5 || q.MinHosts != 2 || q.Source != SourceSSH ||
		q.Limit != 50 || q.Org != "acme" || q.Kind != KindPrefix || q.MinAddresses != 3 {
		t.Errorf("parsed: %+v %v", q, err)
	}
	if q, _ := Parse(get(map[string]string{"since": "30d"}), MCPLimits); q.Window != MaxWindow || q.Limit != 25 {
		t.Errorf("30d, mcp: %+v", q)
	}
	for k, v := range map[string]string{"since": "31d", "min_score": "-1", "source": "smtp", "limit": "10001",
		"min_hosts": "x", "kind": "city"} {
		if _, err := Parse(get(map[string]string{k: v}), RESTLimits); err == nil {
			t.Errorf("%s=%s accepted", k, v)
		}
	}
	if _, err := Parse(get(map[string]string{"limit": "101"}), MCPLimits); err == nil {
		t.Error("MCP limit over 100 accepted")
	}
	for in, want := range map[string]string{"": "json", "CSV": "csv", "plain": "plain"} {
		if got, err := ParseFormat(in); got != want || err != nil {
			t.Errorf("format %q: %q %v", in, got, err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("xml accepted")
	}
}

func TestFormats(t *testing.T) {
	first := testNow.Add(-2 * time.Hour)
	res := Result{GeneratedAt: testNow, Total: 2, Addresses: []Address{
		{IP: "198.51.100.9", Sources: []string{"ssh", "web"}, FirstSeen: first, LastSeen: testNow, Score: 14.2,
			SSH: SSH{Hosts: 2, Failures: 30, Usernames: 4, Days: 1}, Web: Web{Events: 3, Actions: map[string]int{"block": 3}, Zones: []string{"example.com"}},
			ASN: 64500, ASName: "=cmd|' /C calc'!A0", Country: "US", Ban: &Ban{Status: "active", Action: "block", Target: "198.51.100.9", Kind: "address"}},
		{IP: "2001:db8::1", Sources: []string{"ssh"}, Web: Web{Actions: map[string]int{}, Zones: []string{}}},
	}}
	var b bytes.Buffer
	if err := WriteAddresses(&b, FormatPlain, res); err != nil || b.String() != "198.51.100.9\n2001:db8::1\n" {
		t.Errorf("plain: %q %v", b.String(), err)
	}
	b.Reset()
	if err := WriteAddresses(&b, FormatCSV, res); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&b).ReadAll()
	if err != nil || len(rows) != 3 || rows[0][0] != "ip" || rows[1][0] != "198.51.100.9" || rows[1][4] != "14.2" {
		t.Fatalf("csv: %v %v", rows, err)
	}
	col := func(name string) int { return slices.Index(rows[0], name) }
	if v := rows[1][col("as_name")]; !strings.HasPrefix(v, "'=") {
		t.Errorf("formula not neutralized: %q", v)
	}
	if rows[1][col("web_actions")] != "block:3" || rows[1][col("ban_status")] != "active" || rows[1][col("sources")] != "ssh web" ||
		rows[1][col("first_seen")] != "2026-10-25T10:00:00Z" {
		t.Errorf("csv row: %v", rows[1])
	}
	b.Reset()
	if err := WriteAddresses(&b, FormatJSON, res); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(b.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	as := back["addresses"].([]any)
	a0, a1 := as[0].(map[string]any), as[1].(map[string]any)
	if a0["ssh"].(map[string]any)["usernames"] != float64(4) || a0["ban"].(map[string]any)["status"] != "active" || a1["ban"] != nil {
		t.Errorf("json: %s", b.String())
	}
	if _, ok := a1["web"].(map[string]any)["zones"].([]any); !ok {
		t.Errorf("empty zones must be [] not null: %s", b.String())
	}

	nr := NetworkResult{Networks: []Network{{Network: "198.51.100.0/24", Kind: KindPrefix, Addresses: 3, Top: []string{"198.51.100.1"}},
		{Network: "AS64500", Kind: KindASN, ASN: 64500, Addresses: 2, Top: []string{}}, {Network: "2001:db8::/48", Kind: KindPrefix, Top: []string{}}}}
	b.Reset()
	if err := WriteNetworks(&b, FormatPlain, nr); err != nil || b.String() != "198.51.100.0/24\n2001:db8::/48\n" {
		t.Errorf("networks plain: %q %v", b.String(), err)
	}
	b.Reset()
	WriteNetworks(&b, FormatCSV, nr)
	if rows, _ := csv.NewReader(&b).ReadAll(); len(rows) != 4 || rows[2][0] != "AS64500" || rows[2][1] != "asn" {
		t.Errorf("networks csv: %v", rows)
	}
	b.Reset()
	WriteNetworks(&b, FormatJSON, nr)
	if !strings.Contains(b.String(), `"network":"AS64500"`) {
		t.Errorf("networks json: %s", b.String())
	}
	for f, want := range map[string]string{FormatJSON: "application/json", FormatCSV: "text/csv; charset=utf-8", FormatPlain: "text/plain; charset=utf-8"} {
		if got := ContentType(f); got != want {
			t.Errorf("%s: %s", f, got)
		}
	}
}
