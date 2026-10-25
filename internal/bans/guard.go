// SPDX-License-Identifier: AGPL-3.0-or-later

package bans

import (
	"context"
	"net/netip"
	"time"

	"github.com/chrisreedio/heimdall/internal/cloudflare"
	"github.com/chrisreedio/heimdall/internal/ipinfo"
	"github.com/chrisreedio/heimdall/internal/store"
)

// Guard is identify-friend-or-foe for a ban target. A ban is hub-wide at
// Cloudflare, so it checks everything any org knows: a target is friendly
// when it overlaps a label of any org (staff, automation, infra, tailnet,
// private, synced or manual), a built-in internal range, Cloudflare's
// edge, one of your hosts' report addresses, an address someone signed in
// to Heimdall from, or an address whose failures IP awareness vouched for.
// It's checked when a ban is proposed and again right before it's written.
type Guard struct {
	labels   []netip.Prefix
	edge     []netip.Prefix
	hosts    []netip.Addr
	signIns  []netip.Addr
	vouched  []netip.Addr
	internal []netip.Prefix
}

// signInLookback is how far back a Heimdall sign-in vouches for an address.
const signInLookback = 30 * 24 * time.Hour

// internalRanges are never banned: the tailnet, private networks,
// loopback, link-local, and the unspecified and multicast space.
var internalRanges = []netip.Prefix{
	ipinfo.Tailnet, ipinfo.Tailnet6,
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("::/128"), netip.MustParsePrefix("ff00::/8"),
}

// LoadGuard reads what the guard checks. edge nil is the built-in list;
// vouched are addresses IP awareness knew among the failures.
func LoadGuard(ctx context.Context, st *store.Store, edge *cloudflare.Edge, now time.Time, vouched []netip.Addr) (*Guard, error) {
	g := &Guard{internal: internalRanges, vouched: vouched}
	var err error
	if g.labels, err = st.KnownIPPrefixes(ctx); err != nil {
		return nil, err
	}
	if edge == nil {
		edge = cloudflare.NewEdge()
	}
	g.edge = edge.Prefixes()
	addrs, err := st.ReportAddrs(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		g.hosts = append(g.hosts, a.Addr)
	}
	ins, err := st.SignInIPs(ctx, now.Add(-signInLookback))
	if err != nil {
		return nil, err
	}
	for _, s := range ins {
		if ip, err := netip.ParseAddr(s); err == nil {
			g.signIns = append(g.signIns, ip.Unmap())
		}
	}
	return g, nil
}

// Friendly says whether the target holds anything known, and what.
func (g *Guard) Friendly(p netip.Prefix) (string, bool) {
	if g == nil {
		return "no guard data", true // never fire blind
	}
	for _, q := range g.internal {
		if q.Overlaps(p) {
			return "internal range " + q.String(), true
		}
	}
	for _, q := range g.edge {
		if q.Overlaps(p) {
			return "Cloudflare's edge " + q.String(), true
		}
	}
	for _, q := range g.labels {
		if q.Overlaps(p) {
			return "labelled range " + q.String(), true
		}
	}
	for _, a := range g.hosts {
		if p.Contains(a) {
			return "one of your hosts (" + a.String() + ")", true
		}
	}
	for _, a := range g.signIns {
		if p.Contains(a) {
			return "a Heimdall sign-in came from " + a.String(), true
		}
	}
	for _, a := range g.vouched {
		if p.Contains(a) {
			return "IP awareness knows " + a.String(), true
		}
	}
	return "", false
}
