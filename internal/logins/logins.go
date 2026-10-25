// SPDX-License-Identifier: AGPL-3.0-or-later

// Package logins ranks the addresses behind failed SSH logins across the
// fleet (docs/failed-logins.md). Servers with the opt-in login watch report
// counts per address and day; this says which addresses are repeat
// offenders: failing on many hosts, many times, sometimes then getting in.
//
// Anything IP awareness vouches for (a label, the tailnet, a private
// network, your own hosts, a sign-in, Cloudflare's edge) is shown but
// never ranked as an offender, so a person who mistyped a password is
// never on the list a later "propose a ban" step reads (Offenders).
package logins

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/cloudflare"
	"github.com/chrisreedio/heimdall/internal/ipinfo"
	"github.com/chrisreedio/heimdall/internal/store"
)

// Address is failed logins from one address, summed over the hosts that
// reported them in a window.
type Address struct {
	IP      string
	Verdict ipinfo.Verdict // what IP awareness knows (in the first host's org)
	Hosts   []store.IngestHost
	// Failures are summed over the hosts; Usernames is the most tried on
	// any one host and day.
	Failures, Usernames int
	First, Last         time.Time
	// Succeeded: a login from it succeeded after failing, on these hosts.
	Succeeded []store.IngestHost
	Network   string // Radar's name for its network, when cached: "AS64500 Example ISP (US)"
}

// Report is a window's failed logins, split by whether IP awareness
// vouches for the address.
type Report struct {
	Offenders []Address // nothing vouches for them; ranked (see Rank)
	Known     []Address // vouched for: shown, never counted as offenders
	// Failures is every failure the hosts counted in the window's days,
	// including addresses a push didn't list.
	Failures int
}

// Ranker builds reports.
type Ranker struct {
	Store *store.Store
	IPs   *ipinfo.Resolver // nil knows only the built-in ranges
	Edge  *cloudflare.Edge // Cloudflare's edge ranges; nil: the built-in list
}

// Query selects what a report covers.
type Query struct {
	Scope  store.Scope // only hosts it can view count, everywhere
	Org    string      // one org's hosts ("" all the scope's)
	HostID int64       // one host (0 all)
	IP     string      // one address ("" all)
	Since  time.Time
}

// Vouched reports whether IP awareness knows the address well enough that
// its failures aren't an attack: any label about the address itself
// (staff, automation, infra, tailnet, private, your hosts, a sign-in) or
// Cloudflare's edge. Account-name hints don't count (Verdict.UnknownAddress),
// and none are asked for: usernames are never reported.
func Vouched(v ipinfo.Verdict, edge *cloudflare.Edge) bool {
	if !v.Addr.IsValid() {
		return false
	}
	if edge == nil {
		edge = defaultEdge
	}
	return !v.UnknownAddress() || edge.Contains(v.Addr)
}

var defaultEdge = cloudflare.NewEdge()

// resolver is r without Radar: classifying hundreds of attackers'
// addresses must not queue them all for lookups (and use up the day's
// budget). Radar's cache is read separately for the rows shown.
func (rk *Ranker) resolver() *ipinfo.Resolver {
	if rk.IPs == nil {
		return &ipinfo.Resolver{Store: rk.Store}
	}
	c := *rk.IPs
	c.Sources = slices.DeleteFunc(slices.Clone(c.Sources), func(s ipinfo.Source) bool { return s.Name() == cloudflare.RadarSource })
	return &c
}

// Rank reports failed logins since q.Since. Offenders are ranked by how
// many hosts they failed on, then by failures, then the most recent;
// known addresses by failures.
func (rk *Ranker) Rank(ctx context.Context, q Query) (Report, error) {
	var rep Report
	rows, err := rk.Store.LoginFailuresSince(ctx, q.Scope, q.HostID, q.IP, q.Since)
	if err != nil {
		return rep, err
	}
	res := rk.resolver()
	type key struct {
		ip    string
		known bool
	}
	batches := map[int64]func(ip, user string, at time.Time) ipinfo.Verdict{}
	byKey := map[key]*Address{}
	var keys []key
	for _, r := range rows {
		if q.Org != "" && r.Host.OrgSlug != q.Org {
			continue
		}
		resolve := batches[r.Host.OrgID]
		if resolve == nil {
			resolve = res.Batch(ctx, r.Host.OrgID)
			batches[r.Host.OrgID] = resolve
		}
		v := resolve(r.IP, "", r.Last)
		if !v.Addr.IsValid() {
			continue
		}
		k := key{ip: v.Addr.String(), known: Vouched(v, rk.Edge)}
		a := byKey[k]
		if a == nil {
			a = &Address{IP: k.ip, Verdict: v, First: r.First, Last: r.Last}
			byKey[k] = a
			keys = append(keys, k)
		}
		if !slices.ContainsFunc(a.Hosts, func(h store.IngestHost) bool { return h.ID == r.Host.ID }) {
			a.Hosts = append(a.Hosts, r.Host)
		}
		a.Failures += r.Failures
		a.Usernames = max(a.Usernames, r.Usernames)
		if r.First.Before(a.First) {
			a.First = r.First
		}
		if r.Last.After(a.Last) {
			a.Last = r.Last
		}
		if r.Succeeded {
			a.Succeeded = append(a.Succeeded, r.Host)
		}
	}
	for _, k := range keys {
		a := byKey[k]
		byName := func(x, y store.IngestHost) int {
			return cmp.Or(strings.Compare(x.OrgSlug, y.OrgSlug), strings.Compare(x.Name, y.Name))
		}
		slices.SortFunc(a.Hosts, byName)
		slices.SortFunc(a.Succeeded, byName)
		if k.known {
			rep.Known = append(rep.Known, *a)
		} else {
			rep.Offenders = append(rep.Offenders, *a)
		}
	}
	slices.SortFunc(rep.Offenders, func(x, y Address) int {
		return cmp.Or(cmp.Compare(len(y.Hosts), len(x.Hosts)), cmp.Compare(y.Failures, x.Failures),
			y.Last.Compare(x.Last), compareIP(x.IP, y.IP))
	})
	slices.SortFunc(rep.Known, func(x, y Address) int {
		return cmp.Or(cmp.Compare(y.Failures, x.Failures), compareIP(x.IP, y.IP))
	})
	if q.IP == "" {
		if rep.Failures, err = rk.Store.LoginDayTotals(ctx, q.Scope, q.Org, q.HostID, q.Since.UTC().Format(time.DateOnly)); err != nil {
			return rep, err
		}
	}
	listed := 0
	for _, a := range append(slices.Clip(rep.Offenders), rep.Known...) {
		listed += a.Failures
	}
	rep.Failures = max(rep.Failures, listed)
	return rep, nil
}

// Networks fills in Radar's cached network name for the first n
// offenders (all when n <= 0). It never asks Radar.
func (rk *Ranker) Networks(ctx context.Context, as []Address, n int) error {
	if n <= 0 || n > len(as) {
		n = len(as)
	}
	ips := make([]string, n)
	for i := range n {
		ips[i] = as[i].IP
	}
	cached, err := rk.Store.RadarCached(ctx, ips)
	if err != nil {
		return err
	}
	for i := range n {
		if c, ok := cached[as[i].IP]; ok {
			as[i].Network = NetworkName(c)
		}
	}
	return nil
}

// NetworkName names a Radar answer: "AS64500 Example ISP (US)".
func NetworkName(c store.CloudflareRadar) string {
	s := "AS" + strconv.FormatInt(c.ASN, 10)
	if c.Name != "" {
		s += " " + c.Name
	}
	if c.Country != "" {
		s += " (" + c.Country + ")"
	}
	return s
}

// Offenders is the ranked list of addresses nothing vouches for that
// failed to log in since a time, on hosts the scope can view (one org's
// when org isn't ""). It's what a later "propose a ban" step reads: every
// address on it is unknown to IP awareness and outside Cloudflare's edge.
func (rk *Ranker) Offenders(ctx context.Context, sc store.Scope, org string, since time.Time) ([]Address, error) {
	rep, err := rk.Rank(ctx, Query{Scope: sc, Org: org, Since: since})
	return rep.Offenders, err
}

func compareIP(a, b string) int {
	x, err1 := netip.ParseAddr(a)
	y, err2 := netip.ParseAddr(b)
	if err1 != nil || err2 != nil {
		return strings.Compare(a, b)
	}
	return x.Compare(y)
}
