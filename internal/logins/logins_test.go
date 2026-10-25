// SPDX-License-Identifier: AGPL-3.0-or-later

package logins

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/cloudflare"
	"github.com/chrisreedio/heimdall/internal/ipinfo"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/store/storetest"
)

var now = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// radarSpy stands in for Cloudflare Radar: ranking must never ask it.
type radarSpy struct{ asked int }

func (*radarSpy) Name() string { return cloudflare.RadarSource }
func (r *radarSpy) Lookup(context.Context, int64, netip.Addr, time.Time) ([]ipinfo.Label, error) {
	r.asked++
	return nil, nil
}

type fleet struct {
	st    *store.Store
	hosts map[string]store.IngestHost // "org/name"
	rk    *Ranker
	radar *radarSpy
}

func newFleet(t *testing.T) *fleet {
	t.Helper()
	st := storetest.New(t)
	ctx := t.Context()
	f := &fleet{st: st, hosts: map[string]store.IngestHost{}, radar: &radarSpy{}}
	for _, org := range []string{"acme", "globex"} {
		st.CreateOrg(ctx, "test", org, "")
		st.CreateEnv(ctx, "test", org, "prod", "")
		for _, name := range []string{"web-01", "web-02", "db-01"} {
			if _, _, err := st.AddHost(ctx, "test", org, "prod", name, nil); err != nil {
				t.Fatal(err)
			}
			h, err := st.HostByName(ctx, org, name)
			if err != nil {
				t.Fatal(err)
			}
			f.hosts[org+"/"+name] = h
		}
	}
	f.rk = &Ranker{Store: st, IPs: &ipinfo.Resolver{Store: st, Sources: []ipinfo.Source{ipinfo.Hosts{Store: st}, f.radar}}}
	return f
}

// fail records failures from ip on a host today.
func (f *fleet) fail(t *testing.T, host, ip string, n int, succeeded bool) {
	t.Helper()
	at := now.Add(-time.Hour)
	day := store.LoginDay{Day: at.Format(time.DateOnly), Failures: n, Addresses: 1,
		Rows: []store.LoginFailure{{IP: ip, Failures: n, Usernames: 1, First: at, Last: at, Succeeded: succeeded}}}
	if err := f.st.RecordLogins(t.Context(), f.hosts[host].ID, store.LoginReport{Source: "journal", Days: []store.LoginDay{day}}, now); err != nil {
		t.Fatal(err)
	}
}

func ips(as []Address) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.IP)
	}
	return out
}

func TestRankExcludesVouched(t *testing.T) {
	f := newFleet(t)
	ctx := t.Context()
	acme := f.hosts["acme/web-01"].OrgID
	if _, err := f.st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: acme, Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		Kind: store.IPKindStaff, Name: "Office"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: acme, Prefix: netip.MustParsePrefix("192.0.2.80/32"),
		Kind: store.IPKindAutomation, Name: "Deploys"}); err != nil {
		t.Fatal(err)
	}
	// One of your own servers (the address its reports come from).
	if err := f.st.RecordReportIP(ctx, f.hosts["acme/db-01"].ID, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{
		"198.51.100.7", // staff
		"192.0.2.80",   // automation
		"192.0.2.50",   // infra: a host
		"100.101.2.3",  // the tailnet
		"10.0.0.5",     // private
		"104.16.0.9",   // Cloudflare's edge (built in, no label needed)
		"203.0.113.9",  // nobody knows it
	} {
		f.fail(t, "acme/web-01", ip, 3, false)
	}
	rep, err := f.rk.Rank(ctx, Query{Scope: store.AllScope, Since: now.Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if got := ips(rep.Offenders); !slices.Equal(got, []string{"203.0.113.9"}) {
		t.Errorf("offenders = %v, want only the unknown address", got)
	}
	if got := ips(rep.Known); len(got) != 6 {
		t.Errorf("known = %v, want the other six", got)
	}
	if rep.Failures != 21 {
		t.Errorf("failures = %d, want 21", rep.Failures)
	}
	if f.radar.asked != 0 {
		t.Errorf("Radar was asked %d times", f.radar.asked)
	}
	// The ban seam says the same.
	off, err := f.rk.Offenders(ctx, store.AllScope, "", now.Add(-24*time.Hour))
	if err != nil || !slices.Equal(ips(off), []string{"203.0.113.9"}) {
		t.Errorf("Offenders = %v, %v", ips(off), err)
	}

	// A label is per org: the office range is still unknown to globex.
	f.fail(t, "globex/web-01", "198.51.100.7", 2, false)
	rep, _ = f.rk.Rank(ctx, Query{Scope: store.AllScope, Since: now.Add(-24 * time.Hour)})
	i := slices.IndexFunc(rep.Offenders, func(a Address) bool { return a.IP == "198.51.100.7" })
	if i < 0 || len(rep.Offenders[i].Hosts) != 1 || rep.Offenders[i].Hosts[0].OrgSlug != "globex" {
		t.Errorf("offenders = %+v", rep.Offenders)
	}
	if !slices.Contains(ips(rep.Known), "198.51.100.7") {
		t.Errorf("acme's failures from its office should stay known: %v", ips(rep.Known))
	}
}

func TestVouched(t *testing.T) {
	v := func(addr string, ls ...ipinfo.Label) ipinfo.Verdict {
		return ipinfo.Verdict{Addr: netip.MustParseAddr(addr), Labels: ls}
	}
	a := netip.MustParseAddr("203.0.113.9")
	for name, c := range map[string]struct {
		v    ipinfo.Verdict
		want bool
	}{
		"nothing known":       {v("203.0.113.9"), false},
		"a user hint alone":   {v("203.0.113.9", ipinfo.Label{Kind: store.IPKindAutomation, Name: "Forge"}), false},
		"Radar's guess":       {v("203.0.113.9", ipinfo.Label{Kind: store.IPKindUnknown, Name: "AS64500", Prefix: netip.PrefixFrom(a, 32), Guess: true}), false},
		"a staff label":       {v("203.0.113.9", ipinfo.Label{Kind: store.IPKindStaff, Prefix: netip.MustParsePrefix("203.0.113.0/24")}), true},
		"a sign-in guess":     {v("203.0.113.9", ipinfo.Label{Kind: store.IPKindStaff, Prefix: netip.PrefixFrom(a, 32), Guess: true}), true},
		"Cloudflare built in": {v("2606:4700::1"), true},
		"not an address":      {ipinfo.Verdict{}, false},
	} {
		if got := Vouched(c.v, nil); got != c.want {
			t.Errorf("%s: Vouched = %v, want %v", name, got, c.want)
		}
	}
}

func TestRankOrder(t *testing.T) {
	f := newFleet(t)
	ctx := t.Context()
	// B: one host, many failures. A and C: three hosts; C more failures.
	f.fail(t, "acme/web-01", "203.0.113.2", 100, false)
	for _, h := range []string{"acme/web-01", "acme/web-02", "globex/db-01"} {
		f.fail(t, h, "203.0.113.1", 2, false)
		f.fail(t, h, "203.0.113.3", 4, h == "acme/web-02")
	}
	rep, err := f.rk.Rank(ctx, Query{Scope: store.AllScope, Since: now.Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if got := ips(rep.Offenders); !slices.Equal(got, []string{"203.0.113.3", "203.0.113.1", "203.0.113.2"}) {
		t.Fatalf("order = %v", got)
	}
	c := rep.Offenders[0]
	if c.Failures != 12 || len(c.Hosts) != 3 || len(c.Succeeded) != 1 || c.Succeeded[0].Name != "web-02" ||
		c.Hosts[0].OrgSlug != "acme" || c.Hosts[2].OrgSlug != "globex" {
		t.Errorf("top = %+v", c)
	}
	// A window that ended before: nothing.
	if rep, _ := f.rk.Rank(ctx, Query{Scope: store.AllScope, Since: now}); len(rep.Offenders) != 0 {
		t.Errorf("since now: %v", ips(rep.Offenders))
	}
	// Radar's cached network for the rows shown; nothing asked.
	if err := f.st.PutCloudflareRadar(ctx, store.CloudflareRadar{IP: "203.0.113.3", ASN: 64500, Name: "Example ISP", Country: "US", FetchedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := f.rk.Networks(ctx, rep.Offenders, 2); err != nil {
		t.Fatal(err)
	}
	if rep.Offenders[0].Network != "AS64500 Example ISP (US)" || rep.Offenders[1].Network != "" {
		t.Errorf("networks = %q, %q", rep.Offenders[0].Network, rep.Offenders[1].Network)
	}
}

func TestRankScope(t *testing.T) {
	f := newFleet(t)
	ctx := t.Context()
	for _, h := range []string{"acme/web-01", "globex/web-01", "globex/web-02"} {
		f.fail(t, h, "203.0.113.1", 5, h == "globex/web-02")
	}
	f.fail(t, "globex/db-01", "203.0.113.2", 9, false)
	acmeOnly := store.Scope{Orgs: map[int64]store.Role{f.hosts["acme/web-01"].OrgID: store.RoleViewer}}
	rep, err := f.rk.Rank(ctx, Query{Scope: acmeOnly, Since: now.Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	// Only acme's host counts: one host, its failures, no success seen elsewhere.
	if len(rep.Offenders) != 1 || rep.Offenders[0].IP != "203.0.113.1" || len(rep.Offenders[0].Hosts) != 1 ||
		rep.Offenders[0].Failures != 5 || len(rep.Offenders[0].Succeeded) != 0 || rep.Failures != 5 {
		t.Errorf("acme viewer sees %+v (failures %d)", rep.Offenders, rep.Failures)
	}
	// --org narrows an all-orgs scope the same way.
	rep, _ = f.rk.Rank(ctx, Query{Scope: store.AllScope, Org: "globex", Since: now.Add(-24 * time.Hour)})
	if got := ips(rep.Offenders); !slices.Equal(got, []string{"203.0.113.1", "203.0.113.2"}) || len(rep.Offenders[0].Hosts) != 2 || rep.Failures != 19 {
		t.Errorf("globex: %v, %+v, failures %d", got, rep.Offenders, rep.Failures)
	}
	if rep, _ := f.rk.Rank(ctx, Query{Scope: store.Scope{}, Since: now.Add(-24 * time.Hour)}); len(rep.Offenders) != 0 || rep.Failures != 0 {
		t.Errorf("empty scope sees %+v", rep)
	}
}
