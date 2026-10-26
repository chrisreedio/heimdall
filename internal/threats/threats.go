// SPDX-License-Identifier: AGPL-3.0-or-later

// Package threats is the threat list (docs/threats.md): the attacker
// addresses and networks the hub has seen, for other services to pull
// (firewalls, fail2ban, a SIEM) over REST, or for an assistant to ask about
// over MCP. Being on it never bans anything; bans are internal/bans.
//
// Sources are the login watch's failed SSH logins (internal/logins) and,
// once wired in, Cloudflare's web offenders (Lister.Web). Anything IP
// awareness knows in any org is never on it, exactly as bans drop it:
// labels, the tailnet, private ranges, Cloudflare's edge, your hosts'
// report addresses, recent Heimdall sign-ins. Scores are the ban scorer's
// (bans.AddressScores), so they match /bans. Network names come from the
// Radar cache or the web data, never a fresh lookup.
package threats

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/bans"
	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/logins"
	"github.com/realmwatch/heimdall/internal/store"
)

// Sources an address can come from.
const (
	SourceSSH = "ssh"
	SourceWeb = "web"
	SourceAll = "all"
)

// Windows.
const (
	DefaultWindow = 7 * 24 * time.Hour
	MaxWindow     = store.LoginRetention // nothing older is kept
)

// ErrForbidden: the caller asked for an org outside their scope.
var ErrForbidden = errors.New("forbidden")

// Query selects what a list covers.
type Query struct {
	Scope    store.Scope   // only what it can view counts
	Org      string        // one org's hosts and zones ("" every org in scope)
	Window   time.Duration // how far back (DefaultWindow when 0)
	MinScore float64
	MinHosts int    // SSH hosts an address failed on
	Source   string // ssh, web or all ("" all)
	Limit    int    // rows returned (0: no limit)
	// Networks only.
	Kind         string // prefix, asn or "" both
	MinAddresses int    // addresses a network needs (at least 1)
}

// SSH is what the login watch saw from an address, on the caller's hosts.
type SSH struct {
	Hosts     int  `json:"hosts"`
	Failures  int  `json:"failures"`
	Usernames int  `json:"usernames"` // the most distinct usernames tried on one host and day: a count, never names
	Days      int  `json:"days"`      // distinct UTC days with a failure
	Succeeded bool `json:"succeeded"` // a login from it then succeeded
}

// Web is what Cloudflare saw from an address on the caller's zones.
type Web struct {
	Events  int            `json:"events"`
	Actions map[string]int `json:"actions"` // Cloudflare's action: events
	Zones   []string       `json:"zones"`
	Days    int            `json:"days"`
}

// Ban is an address's ban, if it has one (shown to operators only).
type Ban struct {
	Status  string     `json:"status"` // shadow, proposed, pending, active, lifting
	Action  string     `json:"action"` // challenge, block
	Target  string     `json:"target"` // the address, its /64, or a network holding it
	Kind    string     `json:"kind"`   // address, network
	Expires *time.Time `json:"expires_at"`
}

// Address is one attacker address.
type Address struct {
	IP        string    `json:"ip"`
	Sources   []string  `json:"sources"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	SSH       SSH       `json:"ssh"`
	Web       Web       `json:"web"`
	ASN       int64     `json:"asn"`
	ASName    string    `json:"as_name"`
	Country   string    `json:"country"`
	Score     float64   `json:"score"`
	Ban       *Ban      `json:"ban"`

	hosts []int64 // SSH host IDs, for network rollups
}

// Network is a rollup of addresses: one /24 (IPv4) or /48 (IPv6), or one
// ASN.
type Network struct {
	Network   string    `json:"network"` // 203.0.113.0/24, or AS64500
	Kind      string    `json:"kind"`    // prefix, asn
	ASN       int64     `json:"asn"`
	ASName    string    `json:"as_name"`
	Country   string    `json:"country"`
	Addresses int       `json:"addresses"`
	Failures  int       `json:"failures"` // SSH
	Events    int       `json:"events"`   // web
	Hosts     int       `json:"hosts"`    // distinct SSH hosts hit
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Top       []string  `json:"top"` // up to TopAddresses, highest score first
}

// TopAddresses is how many addresses a network names.
const TopAddresses = 5

// Network kinds.
const (
	KindPrefix = "prefix"
	KindASN    = "asn"
)

// WebOffender is one address Cloudflare saw on an org's zones: the same
// fields as store.WebOffender, so a store row converts with
// threats.WebOffender(row).
type WebOffender struct {
	IP          string
	Events      int
	Actions     map[string]int
	Zones       []string
	Days        int
	First, Last time.Time
	ASN         int64
	ASName      string
	Country     string
}

// WebFunc returns web offenders since a time on one org's zones (org ""
// every org's).
type WebFunc func(ctx context.Context, org string, since time.Time) ([]WebOffender, error)

// Lister builds threat lists.
type Lister struct {
	Store  *store.Store
	Ranker *logins.Ranker // its IPs and Edge say what's friendly
	// Bans is the ban config, for its weights and min_failures (zero:
	// the defaults), so scores match /bans.
	Bans config.Bans
	Now  func() time.Time
	// Web is the web source: nil until Cloudflare's web offenders are wired
	// in, and then no web rows (docs/threats.md#web).
	Web WebFunc
}

func (l *Lister) now() time.Time {
	if l.Now == nil {
		return time.Now()
	}
	return l.Now()
}

func (l *Lister) bansCfg() config.Bans {
	if l.Bans.Weights == (config.BanWeights{}) {
		return config.BansDefaults
	}
	return l.Bans
}

// Result is a list of addresses, highest score first.
type Result struct {
	GeneratedAt time.Time `json:"generated_at"`
	Since       time.Time `json:"since"`
	Org         string    `json:"org"`
	Source      string    `json:"source"`
	Total       int       `json:"total"` // before the limit
	Truncated   bool      `json:"truncated"`
	Addresses   []Address `json:"addresses"`
}

// NetworkResult is a list of networks, most addresses first.
type NetworkResult struct {
	GeneratedAt time.Time `json:"generated_at"`
	Since       time.Time `json:"since"`
	Org         string    `json:"org"`
	Source      string    `json:"source"`
	Total       int       `json:"total"`
	Truncated   bool      `json:"truncated"`
	Networks    []Network `json:"networks"`
}

// Addresses lists attacker addresses.
func (l *Lister) Addresses(ctx context.Context, q Query) (Result, error) {
	as, since, err := l.addresses(ctx, &q)
	if err != nil {
		return Result{}, err
	}
	res := Result{GeneratedAt: l.now().UTC(), Since: since, Org: q.Org, Source: q.Source, Total: len(as)}
	if q.Limit > 0 && len(as) > q.Limit {
		as, res.Truncated = as[:q.Limit], true
	}
	res.Addresses = as
	return res, nil
}

// Networks rolls the addresses Addresses would list (before its limit)
// up by /24 or /48 and by ASN.
func (l *Lister) Networks(ctx context.Context, q Query) (NetworkResult, error) {
	as, since, err := l.addresses(ctx, &q)
	if err != nil {
		return NetworkResult{}, err
	}
	ns := rollup(as, q.Kind, max(q.MinAddresses, 1))
	res := NetworkResult{GeneratedAt: l.now().UTC(), Since: since, Org: q.Org, Source: q.Source, Total: len(ns)}
	if q.Limit > 0 && len(ns) > q.Limit {
		ns, res.Truncated = ns[:q.Limit], true
	}
	res.Networks = ns
	return res, nil
}

// addresses is every address the query matches, sorted, and the window's
// start. It normalizes q.
func (l *Lister) addresses(ctx context.Context, q *Query) ([]Address, time.Time, error) {
	if q.Window <= 0 {
		q.Window = DefaultWindow
	}
	q.Window = min(q.Window, MaxWindow)
	if q.Source == "" {
		q.Source = SourceAll
	}
	now := l.now()
	since := now.Add(-q.Window)
	if q.Scope.Empty() {
		return nil, since, ErrForbidden
	}
	visible, err := l.Store.VisibleOrgSlugs(ctx, q.Scope)
	if err != nil {
		return nil, since, err
	}
	if q.Org != "" && !visible[q.Org] {
		if q.Scope.Admin {
			return nil, since, &store.ValidationError{Field: "org", Msg: fmt.Sprintf("no org %q", q.Org)}
		}
		return nil, since, ErrForbidden // another org's, or none: the same answer
	}
	rk := l.Ranker
	if rk == nil {
		rk = &logins.Ranker{Store: l.Store}
	}

	// Friend or foe is hub-wide, as for bans: an address any org vouches
	// for is never listed, even where the caller's orgs don't know it.
	all, err := rk.Rank(ctx, logins.Query{Scope: store.AllScope, Since: since})
	if err != nil {
		return nil, since, err
	}
	known := map[string]bool{}
	var vouched []netip.Addr
	for _, k := range all.Known {
		known[k.IP] = true
		if a, err := netip.ParseAddr(k.IP); err == nil {
			vouched = append(vouched, a)
		}
	}
	guard, err := bans.LoadGuard(ctx, l.Store, rk.Edge, now, vouched)
	if err != nil {
		return nil, since, err
	}
	friendly := func(ip string) bool {
		a, err := netip.ParseAddr(ip)
		if err != nil || known[a.Unmap().String()] {
			return true
		}
		_, ok := guard.Friendly(bans.AddressTarget(a))
		return ok
	}

	byIP := map[string]*Address{}
	var order []string
	get := func(ip string) *Address {
		a := byIP[ip]
		if a == nil {
			a = &Address{IP: ip, Sources: []string{}, Web: Web{Actions: map[string]int{}, Zones: []string{}}}
			byIP[ip] = a
			order = append(order, ip)
		}
		return a
	}

	// SSH, on the caller's hosts (one org's when asked). Scored is what
	// the ban engine scores (everything but what IP awareness knows), so
	// the same-network factor counts the same peers and the numbers match
	// /bans; the guard then drops the rest of what's friendly.
	var scored, offenders []logins.Address
	if q.Source != SourceWeb {
		rep := all
		if !q.Scope.Admin || q.Org != "" {
			if rep, err = rk.Rank(ctx, logins.Query{Scope: q.Scope, Org: q.Org, Since: since}); err != nil {
				return nil, since, err
			}
		}
		for _, o := range rep.Offenders {
			if known[o.IP] {
				continue
			}
			scored = append(scored, o)
			if !friendly(o.IP) {
				offenders = append(offenders, o)
			}
		}
	}

	// Web, on the caller's zones.
	var web []WebOffender
	if q.Source != SourceSSH && l.Web != nil {
		orgs := []string{q.Org}
		if q.Org == "" && !q.Scope.Admin {
			orgs = slices.Sorted(maps.Keys(visible))
		}
		for _, org := range orgs {
			rows, err := l.Web(ctx, org, since)
			if err != nil {
				return nil, since, err
			}
			for _, r := range rows {
				if !friendly(r.IP) {
					web = append(web, r)
				}
			}
		}
	}

	ips := make([]string, 0, len(scored)+len(web))
	for _, o := range scored {
		ips = append(ips, o.IP)
	}
	for _, w := range web {
		ips = append(ips, w.IP)
	}
	radar, err := l.Store.RadarCached(ctx, ips)
	if err != nil {
		return nil, since, err
	}

	if len(offenders) > 0 {
		days, err := l.Store.LoginDaysFor(ctx, q.Scope, q.Org, since)
		if err != nil {
			return nil, since, err
		}
		scores := bans.AddressScores(l.bansCfg(), bans.Inputs{Offenders: scored, Days: days, Radar: radar,
			Guard: guard, Window: q.Window})
		for _, o := range offenders {
			a := get(o.IP)
			a.Sources = append(a.Sources, SourceSSH)
			a.FirstSeen, a.LastSeen = o.First, o.Last
			a.SSH = SSH{Hosts: len(o.Hosts), Failures: o.Failures, Usernames: o.Usernames, Days: max(days[o.IP], 1),
				Succeeded: len(o.Succeeded) > 0}
			for _, h := range o.Hosts {
				a.hosts = append(a.hosts, h.ID)
			}
			a.Score = scores[o.IP].Score
		}
	}
	for _, w := range web {
		ip := w.IP
		if p, err := netip.ParseAddr(ip); err == nil {
			ip = p.Unmap().String()
		}
		a := get(ip)
		if !slices.Contains(a.Sources, SourceWeb) {
			a.Sources = append(a.Sources, SourceWeb)
		}
		a.Web.Events += w.Events
		for k, n := range w.Actions {
			a.Web.Actions[k] += n
		}
		for _, z := range w.Zones {
			if !slices.Contains(a.Web.Zones, z) {
				a.Web.Zones = append(a.Web.Zones, z)
			}
		}
		a.Web.Days = max(a.Web.Days, w.Days) // one org's zones per row: the most on any
		if a.FirstSeen.IsZero() || (!w.First.IsZero() && w.First.Before(a.FirstSeen)) {
			a.FirstSeen = w.First
		}
		if w.Last.After(a.LastSeen) {
			a.LastSeen = w.Last
		}
		if a.ASN == 0 && w.ASN > 0 {
			a.ASN, a.ASName, a.Country = w.ASN, w.ASName, w.Country
		}
	}
	for _, ip := range order {
		a := byIP[ip]
		slices.Sort(a.Web.Zones)
		if r, ok := radar[ip]; ok && r.ASN > 0 { // the cache wins: it's what /bans shows
			a.ASN, a.ASName, a.Country = r.ASN, r.Name, r.Country
		}
		a.FirstSeen, a.LastSeen = a.FirstSeen.UTC(), a.LastSeen.UTC()
	}

	out := make([]Address, 0, len(order))
	for _, ip := range order {
		a := byIP[ip]
		if a.Score < q.MinScore || a.SSH.Hosts < q.MinHosts {
			continue
		}
		out = append(out, *a)
	}
	slices.SortFunc(out, func(x, y Address) int {
		return cmp.Or(cmp.Compare(y.Score, x.Score), cmp.Compare(y.SSH.Hosts, x.SSH.Hosts),
			cmp.Compare(y.SSH.Failures+y.Web.Events, x.SSH.Failures+x.Web.Events), y.LastSeen.Compare(x.LastSeen),
			compareIP(x.IP, y.IP))
	})
	if canOperateAny(q.Scope) {
		if err := l.addBans(ctx, out, now); err != nil {
			return nil, since, err
		}
	}
	return out, since, nil
}

// canOperateAny: bans are an operator's business (/bans is theirs).
func canOperateAny(sc store.Scope) bool {
	return sc.Admin || slices.ContainsFunc(slices.Collect(maps.Keys(sc.Orgs)), sc.CanOperate)
}

// addBans sets each address's ban: an open one covering it (the most
// specific), else a shadow record that hasn't run out.
func (l *Lister) addBans(ctx context.Context, as []Address, now time.Time) error {
	if len(as) == 0 {
		return nil
	}
	bs, err := l.Store.Bans(ctx, store.BanQuery{Statuses: append(slices.Clone(store.BanOpen), store.BanShadow), Limit: 100000})
	if err != nil {
		return err
	}
	type ban struct {
		p    netip.Prefix
		b    store.Ban
		open bool
	}
	var list []ban
	for _, b := range bs {
		if b.Status == store.BanShadow && !b.ExpiresAt.After(now) {
			continue
		}
		if p, ok := bans.ParseTarget(b.Target); ok {
			list = append(list, ban{p, b, b.Open()})
		}
	}
	for i := range as {
		a, err := netip.ParseAddr(as[i].IP)
		if err != nil {
			continue
		}
		var best *ban
		for j := range list {
			c := &list[j]
			if !c.p.Contains(a.Unmap()) {
				continue
			}
			if best == nil || (c.open && !best.open) || (c.open == best.open && c.p.Bits() > best.p.Bits()) {
				best = c
			}
		}
		if best != nil {
			b := &Ban{Status: best.b.Status, Action: best.b.Action, Target: best.b.Target, Kind: best.b.Kind}
			if !best.b.ExpiresAt.IsZero() {
				t := best.b.ExpiresAt.UTC()
				b.Expires = &t
			}
			as[i].Ban = b
		}
	}
	return nil
}

// rollup groups addresses by /24 or /48 and by ASN, most addresses first.
func rollup(as []Address, kind string, minAddrs int) []Network {
	type group struct {
		n     Network
		hosts map[int64]bool
	}
	groups := map[string]*group{}
	var keys []string
	add := func(key string, n Network, a Address) {
		g := groups[key]
		if g == nil {
			g = &group{n: n, hosts: map[int64]bool{}}
			g.n.Top = []string{}
			groups[key] = g
			keys = append(keys, key)
		}
		g.n.Addresses++
		g.n.Failures += a.SSH.Failures
		g.n.Events += a.Web.Events
		for _, h := range a.hosts {
			g.hosts[h] = true
		}
		if g.n.FirstSeen.IsZero() || a.FirstSeen.Before(g.n.FirstSeen) {
			g.n.FirstSeen = a.FirstSeen
		}
		if a.LastSeen.After(g.n.LastSeen) {
			g.n.LastSeen = a.LastSeen
		}
		if g.n.ASN == 0 && a.ASN > 0 {
			g.n.ASN, g.n.ASName, g.n.Country = a.ASN, a.ASName, a.Country
		}
		if len(g.n.Top) < TopAddresses { // as is highest score first
			g.n.Top = append(g.n.Top, a.IP)
		}
	}
	for _, a := range as {
		addr, err := netip.ParseAddr(a.IP)
		if err != nil {
			continue
		}
		if kind != KindASN {
			p := bans.NetworkOf(addr).String()
			add("p "+p, Network{Network: p, Kind: KindPrefix}, a)
		}
		if kind != KindPrefix && a.ASN > 0 {
			n := fmt.Sprintf("AS%d", a.ASN)
			add("a "+n, Network{Network: n, Kind: KindASN, ASN: a.ASN, ASName: a.ASName, Country: a.Country}, a)
		}
	}
	out := make([]Network, 0, len(keys))
	for _, k := range keys {
		g := groups[k]
		if g.n.Addresses < minAddrs {
			continue
		}
		g.n.Hosts = len(g.hosts)
		out = append(out, g.n)
	}
	slices.SortStableFunc(out, func(x, y Network) int {
		return cmp.Or(cmp.Compare(y.Addresses, x.Addresses), cmp.Compare(y.Failures+y.Events, x.Failures+x.Events),
			cmp.Compare(y.Hosts, x.Hosts), strings.Compare(x.Kind, y.Kind), strings.Compare(x.Network, y.Network))
	})
	return out
}

func compareIP(a, b string) int {
	x, err1 := netip.ParseAddr(a)
	y, err2 := netip.ParseAddr(b)
	if err1 != nil || err2 != nil {
		return strings.Compare(a, b)
	}
	return x.Compare(y)
}
