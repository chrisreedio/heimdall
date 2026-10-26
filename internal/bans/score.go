// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bans turns repeat offenders (failed SSH logins across the fleet,
// internal/logins) into Cloudflare bans, the way an air defence network
// works: the collectors and Cloudflare are the sensors, the hub decides,
// IP awareness is identify-friend-or-foe (staff, automation, your
// infrastructure, the tailnet, private networks and Cloudflare's edge are
// never fired on), and Cloudflare's edge enforces.
//
// Candidates are scored, not counted (Score): hosts hit, failures,
// distinct usernames, "then succeeded", coming back day after day, and
// company in the same network. Many addresses in one /24 or /48 that each
// stay under the threshold add up to a network ban. In shadow mode the
// hub only records what it would have done; in propose mode an operator
// approves each ban; in auto mode it bans within the caps. Writes go to an
// account-level IP list per action (challenge, block) that one custom
// rule in each opted-in zone matches (Enforcer). See docs/bans.md.
package bans

import (
	"cmp"
	"context"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/logins"
	"github.com/realmwatch/heimdall/internal/store"
)

// Ban actions, and the Cloudflare rule action each one means.
const (
	Challenge = "challenge"
	Block     = "block"
)

// RuleAction maps a ban action to a Cloudflare custom rule action.
var RuleAction = map[string]string{Challenge: "managed_challenge", Block: "block"}

// Kinds of target.
const (
	KindAddress = "address"
	KindNetwork = "network"
)

// Factor is one part of a score: what it measured and the points it gave.
type Factor struct {
	Name   string  `json:"name"`  // hosts, failures, usernames, succeeded, days, asn, network
	Value  float64 `json:"value"` // the measurement (3 hosts, 120 failures)
	Points float64 `json:"points"`
}

// Host is a host a candidate failed on.
type Host struct {
	OrgID int64  `json:"org_id"`
	Org   string `json:"org"`
	Name  string `json:"name"`
}

// Evidence is what a ban is based on, as shown on /bans and in the
// notification card.
type Evidence struct {
	Hosts     []Host    `json:"hosts"`
	Succeeded []Host    `json:"succeeded,omitempty"` // a login then succeeded on these
	Failures  int       `json:"failures"`
	Usernames int       `json:"usernames"` // most tried on one host and day
	Days      int       `json:"days"`      // distinct UTC days with failures
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	Network   string    `json:"network,omitempty"` // Radar's name, when cached: "AS64500 Example ISP (US)"
	ASN       int64     `json:"asn,omitempty"`
	Prefix    string    `json:"prefix"`            // the address's /24 or /48
	Members   []string  `json:"members,omitempty"` // network bans: the addresses in it
	Known     string    `json:"known"`             // what IP awareness says
	Reason    string    `json:"reason,omitempty"`  // why this action
	Window    string    `json:"window"`            // "7 days"
}

// Candidate is a scored offender or network.
type Candidate struct {
	Target   netip.Prefix // what the list gets: /32 or /64 for an address, /24 or /48 for a network
	Kind     string
	Action   string
	Score    float64
	Factors  []Factor
	Evidence Evidence
	Orgs     []int64 // whose hosts it hit
	Over     bool    // at or over propose_at
	// Skip says why a candidate over the threshold isn't acted on: IP
	// awareness vouches for something in it, or it's already decided.
	Skip string
}

// TargetString is the target as stored and sent: an address alone, or a
// prefix.
func TargetString(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// ParseTarget reads a stored target.
func ParseTarget(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// addressTarget is what an address's ban covers: the address for IPv4, its
// /64 for IPv6 (one machine usually holds a whole /64, and rotates within
// it).
func addressTarget(a netip.Addr) netip.Prefix {
	if a.Is4() {
		return netip.PrefixFrom(a, 32)
	}
	p, _ := a.Prefix(64)
	return p
}

// networkOf is the grouping prefix: /24 for IPv4, /48 for IPv6.
func networkOf(a netip.Addr) netip.Prefix {
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, _ := a.Prefix(bits)
	return p
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// scoreAddress scores one offender. asnPeers is how many other offenders
// share its ASN.
func scoreAddress(w config.BanWeights, a logins.Address, days, asnPeers int) []Factor {
	fs := []Factor{
		{Name: "hosts", Value: float64(len(a.Hosts)), Points: w.Hosts * float64(min(len(a.Hosts), 10))},
		{Name: "failures", Value: float64(a.Failures), Points: w.Failures * math.Log2(1+float64(a.Failures))},
		{Name: "usernames", Value: float64(a.Usernames), Points: w.Usernames * float64(min(a.Usernames, 20))},
	}
	if len(a.Succeeded) > 0 {
		fs = append(fs, Factor{Name: "succeeded", Value: float64(len(a.Succeeded)), Points: w.Succeeded})
	}
	if days > 1 {
		fs = append(fs, Factor{Name: "days", Value: float64(days), Points: w.Days * float64(min(days-1, 7))})
	}
	if asnPeers > 0 {
		fs = append(fs, Factor{Name: "asn", Value: float64(asnPeers), Points: w.ASN * float64(min(asnPeers, 10))})
	}
	for i := range fs {
		fs[i].Points = round1(fs[i].Points)
	}
	return fs
}

func total(fs []Factor) float64 {
	t := 0.0
	for _, f := range fs {
		t += f.Points
	}
	return round1(t)
}

// Inputs are what Score reads besides the offenders.
type Inputs struct {
	Offenders []logins.Address
	Days      map[string]int                   // distinct failure days per address
	Radar     map[string]store.CloudflareRadar // cached, never asked for
	Guard     *Guard
	Window    time.Duration
}

// Score scores every offender and the networks they cluster in, highest
// first. Candidates under the threshold are kept, so shadow mode can show
// how close they came.
func Score(cfg config.Bans, in Inputs) []Candidate {
	asnCount := asnCounts(in)
	window := windowText(in.Window)
	var out []Candidate
	type net struct {
		under []Candidate
	}
	nets := map[netip.Prefix]*net{}
	var netOrder []netip.Prefix
	for _, a := range in.Offenders {
		c, addr, eligible, ok := addressCandidate(cfg, in, a, asnCount, window)
		if !ok {
			continue
		}
		if !c.Over && (eligible || a.Failures > 0) {
			n := networkOf(addr)
			if nets[n] == nil {
				nets[n] = &net{}
				netOrder = append(netOrder, n)
			}
			nets[n].under = append(nets[n].under, c)
		}
		out = append(out, c)
	}
	if cfg.Networks {
		for _, p := range netOrder {
			n := nets[p]
			if len(n.under) < cfg.NetworkAddresses {
				continue
			}
			out = append(out, networkCandidate(cfg, p, n.under, in.Guard, window))
		}
	}
	slices.SortStableFunc(out, func(x, y Candidate) int {
		return cmp.Or(cmp.Compare(y.Score, x.Score), x.Target.Addr().Compare(y.Target.Addr()), cmp.Compare(x.Target.Bits(), y.Target.Bits()))
	})
	return out
}

// AddressScores scores each offender alone, by address, with the points
// Score gives it (no networks): what the threat list shows
// (internal/threats), so its numbers match /bans.
func AddressScores(cfg config.Bans, in Inputs) map[string]Candidate {
	asnCount := asnCounts(in)
	window := windowText(in.Window)
	out := make(map[string]Candidate, len(in.Offenders))
	for _, a := range in.Offenders {
		if c, _, _, ok := addressCandidate(cfg, in, a, asnCount, window); ok {
			out[a.IP] = c
		}
	}
	return out
}

// asnCounts is how many offenders each cached ASN holds.
func asnCounts(in Inputs) map[int64]int {
	n := map[int64]int{}
	for _, a := range in.Offenders {
		if r, ok := in.Radar[a.IP]; ok && r.ASN > 0 {
			n[r.ASN]++
		}
	}
	return n
}

// addressCandidate scores one offender. ok is false for an address that
// doesn't parse; eligible is whether it has enough failures to count.
func addressCandidate(cfg config.Bans, in Inputs, a logins.Address, asnCount map[int64]int, window string) (c Candidate, addr netip.Addr, eligible, ok bool) {
	addr, err := netip.ParseAddr(a.IP)
	if err != nil {
		return c, addr, false, false
	}
	addr = addr.Unmap()
	r := in.Radar[a.IP]
	peers := 0
	if r.ASN > 0 {
		peers = asnCount[r.ASN] - 1
	}
	fs := scoreAddress(cfg.Weights, a, in.Days[a.IP], peers)
	c = Candidate{Target: addressTarget(addr), Kind: KindAddress, Factors: fs, Score: total(fs),
		Evidence: evidence(a, in.Days[a.IP], r, window)}
	c.Evidence.Prefix = networkOf(addr).String()
	c.Orgs = orgsOf(c.Evidence.Hosts)
	eligible = a.Failures >= cfg.MinFailures || len(a.Succeeded) > 0
	c.Over = eligible && c.Score >= cfg.ProposeAt
	c.Action, c.Evidence.Reason = actionFor(cfg, len(a.Hosts), len(a.Succeeded) > 0)
	if c.Over {
		if why, ok := in.Guard.Friendly(c.Target); ok {
			c.Skip = why
		}
	}
	return c, addr, eligible, true
}

// AddressTarget is what a ban on an address covers: the address for IPv4,
// its /64 for IPv6.
func AddressTarget(a netip.Addr) netip.Prefix { return addressTarget(a.Unmap()) }

// NetworkOf is the grouping prefix: /24 for IPv4, /48 for IPv6.
func NetworkOf(a netip.Addr) netip.Prefix { return networkOf(a.Unmap()) }

func networkCandidate(cfg config.Bans, p netip.Prefix, under []Candidate, g *Guard, window string) Candidate {
	sum := 0.0
	ev := Evidence{Prefix: p.String(), Window: window, Known: "nothing known about any address in it"}
	succeeded := false
	for i, m := range under {
		sum += m.Score
		ev.Members = append(ev.Members, TargetString(m.Target))
		for _, h := range m.Evidence.Hosts {
			if !slices.Contains(ev.Hosts, h) {
				ev.Hosts = append(ev.Hosts, h)
			}
		}
		for _, h := range m.Evidence.Succeeded {
			if !slices.Contains(ev.Succeeded, h) {
				ev.Succeeded = append(ev.Succeeded, h)
			}
		}
		succeeded = succeeded || len(m.Evidence.Succeeded) > 0
		ev.Failures += m.Evidence.Failures
		ev.Usernames = max(ev.Usernames, m.Evidence.Usernames)
		ev.Days = max(ev.Days, m.Evidence.Days)
		if i == 0 || m.Evidence.First.Before(ev.First) {
			ev.First = m.Evidence.First
		}
		if m.Evidence.Last.After(ev.Last) {
			ev.Last = m.Evidence.Last
		}
		if ev.Network == "" {
			ev.Network, ev.ASN = m.Evidence.Network, m.Evidence.ASN
		}
	}
	fs := []Factor{
		{Name: "addresses", Value: float64(len(under)), Points: 0},
		{Name: "network", Value: round1(sum), Points: round1(cfg.Weights.Network * sum)},
	}
	c := Candidate{Target: p, Kind: KindNetwork, Factors: fs, Score: total(fs), Evidence: ev, Orgs: orgsOf(ev.Hosts)}
	c.Over = c.Score >= cfg.ProposeAt
	// A network is challenged, never blocked, unless one of its addresses
	// got in: a challenge lets the people who share it through.
	c.Action, c.Evidence.Reason = Challenge, "a network: challenged, so others behind it can still pass"
	if succeeded && cfg.BlockSucceeded {
		c.Action, c.Evidence.Reason = Block, "an address in it failed and then logged in"
	}
	if c.Over {
		if why, ok := g.Friendly(p); ok {
			c.Skip = why
		}
	}
	return c
}

// actionFor is challenge by default; block for an address that hit
// block_hosts hosts or (block_succeeded) failed and then got in.
func actionFor(cfg config.Bans, hosts int, succeeded bool) (string, string) {
	switch {
	case succeeded && cfg.BlockSucceeded:
		return Block, "failed, then logged in"
	case hosts >= cfg.BlockHosts:
		return Block, "failed on " + strconv.Itoa(hosts) + " hosts"
	}
	return Challenge, "challenge by default"
}

func evidence(a logins.Address, days int, r store.CloudflareRadar, window string) Evidence {
	ev := Evidence{Failures: a.Failures, Usernames: a.Usernames, Days: max(days, 1), First: a.First, Last: a.Last,
		Window: window, Known: "nothing known: not staff, automation, infra, the tailnet, private or Cloudflare"}
	for _, h := range a.Hosts {
		ev.Hosts = append(ev.Hosts, Host{OrgID: h.OrgID, Org: h.OrgSlug, Name: h.Name})
	}
	for _, h := range a.Succeeded {
		ev.Succeeded = append(ev.Succeeded, Host{OrgID: h.OrgID, Org: h.OrgSlug, Name: h.Name})
	}
	if r.ASN > 0 {
		ev.ASN, ev.Network = r.ASN, logins.NetworkName(r)
	}
	return ev
}

func orgsOf(hs []Host) []int64 {
	var out []int64
	for _, h := range hs {
		if !slices.Contains(out, h.OrgID) {
			out = append(out, h.OrgID)
		}
	}
	slices.Sort(out)
	return out
}

func windowText(d time.Duration) string {
	if d >= 48*time.Hour {
		return strconv.Itoa(int(d.Hours()/24)) + " days"
	}
	return strconv.Itoa(int(d.Hours())) + " hours"
}

// BanDuration is a ban's length: the base doubled for each earlier
// offense, capped.
func BanDuration(cfg config.Bans, earlier int) time.Duration {
	d := cfg.Duration.Duration
	for range min(earlier, 20) {
		d *= 2
		if d >= cfg.MaxDuration.Duration {
			return cfg.MaxDuration.Duration
		}
	}
	return min(d, cfg.MaxDuration.Duration)
}

// candidatesInput gathers Score's inputs from the store.
func (e *Engine) candidatesInput(ctx context.Context) (Inputs, error) {
	now := e.now()
	since := now.Add(-e.Cfg.Window.Duration)
	in := Inputs{Window: e.Cfg.Window.Duration}
	rep, err := e.Ranker.Rank(ctx, logins.Query{Scope: store.AllScope, Since: since})
	if err != nil {
		return in, err
	}
	// An address one org vouches for is never banned, even where another
	// org doesn't know it: the ban is hub-wide.
	known := map[string]bool{}
	var vouched []netip.Addr
	for _, k := range rep.Known {
		known[k.IP] = true
		if a, err := netip.ParseAddr(k.IP); err == nil {
			vouched = append(vouched, a)
		}
	}
	for _, o := range rep.Offenders {
		if !known[o.IP] {
			in.Offenders = append(in.Offenders, o)
		}
	}
	if in.Days, err = e.Store.LoginDays(ctx, since); err != nil {
		return in, err
	}
	ips := make([]string, len(in.Offenders))
	for i, o := range in.Offenders {
		ips[i] = o.IP
	}
	if in.Radar, err = e.Store.RadarCached(ctx, ips); err != nil {
		return in, err
	}
	if in.Guard, err = LoadGuard(ctx, e.Store, e.Ranker.Edge, now, vouched); err != nil {
		return in, err
	}
	return in, nil
}

// Candidates scores the current offenders (for /bans and the CLI).
func (e *Engine) Candidates(ctx context.Context) ([]Candidate, error) {
	in, err := e.candidatesInput(ctx)
	if err != nil {
		return nil, err
	}
	return Score(e.Cfg, in), nil
}
