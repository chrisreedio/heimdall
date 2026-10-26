// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ipinfo says what Heimdall knows about an IP address: whose it is
// (a person on the team, a deploy service, your own infrastructure, the
// tailnet) or that nobody knows it. It's used wherever an address shows up,
// above all a privilege watch session's source.
//
// Knowledge comes from labels (store.IPLabel): added by hand, or kept in
// sync by a Syncer (a deploy service's published ranges, the Tailscale API,
// Cloudflare). Some ranges are known without any (private, loopback, the
// tailnet's 100.64.0.0/10). Sources that work per lookup (e.g. "this person
// signed in to Heimdall from this address an hour before") are Sources.
package ipinfo

import (
	"cmp"
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// Label is one thing known about an address.
type Label struct {
	Kind   string // store.IPKind*
	Name   string // "Office VPN", "Laravel Forge", "laptop-01"
	Person string // who, when known
	Note   string // anything else (a Cloudflare list item's comment, for kinds without a person)
	Source string // "manual", "service:forge", "tailscale", "cloudflare:list:<id>", "builtin", ...
	Prefix netip.Prefix
	// Guess marks a label inferred rather than known (e.g. matched by a
	// sign-in from the same address). Ranked below known labels.
	Guess bool
}

// Verdict is everything known about one address, the most telling first.
type Verdict struct {
	Addr   netip.Addr // invalid if the input wasn't an address
	Labels []Label
}

// Kind is the verdict's overall kind: its first label's, or unknown.
func (v Verdict) Kind() string {
	if len(v.Labels) == 0 {
		return store.IPKindUnknown
	}
	return v.Labels[0].Kind
}

// Best is the most telling label (zero if none).
func (v Verdict) Best() Label {
	if len(v.Labels) == 0 {
		return Label{Kind: store.IPKindUnknown}
	}
	return v.Labels[0]
}

// Source answers per lookup, for knowledge that isn't a fixed range.
type Source interface {
	Name() string
	Lookup(ctx context.Context, orgID int64, ip netip.Addr, at time.Time) ([]Label, error)
}

// UserHint recognizes an account name that belongs to a deploy service or
// tool (e.g. "forge" for Laravel Forge), for privilege events.
type UserHint func(user string) (Label, bool)

// Resolver combines labels, sources and user hints.
type Resolver struct {
	Store     *store.Store
	Sources   []Source
	UserHints []UserHint
	Log       *slog.Logger
}

// Resolve says what's known about ip (an address as text, as stored on
// privilege events) in an org. user, if not empty, is the account the
// session used, for user hints; at is when the address was seen.
func (r *Resolver) Resolve(ctx context.Context, orgID int64, ip, user string, at time.Time) Verdict {
	labels, _ := r.labels(ctx, orgID)
	return r.resolve(ctx, labels, orgID, ip, user, at)
}

// Batch resolves many addresses in an org with one label query.
func (r *Resolver) Batch(ctx context.Context, orgID int64) func(ip, user string, at time.Time) Verdict {
	labels, _ := r.labels(ctx, orgID)
	return func(ip, user string, at time.Time) Verdict { return r.resolve(ctx, labels, orgID, ip, user, at) }
}

func (r *Resolver) labels(ctx context.Context, orgID int64) ([]store.IPLabel, error) {
	if r == nil || r.Store == nil {
		return nil, nil
	}
	ls, err := r.Store.IPLabels(ctx, orgID)
	if err != nil && r.Log != nil {
		r.Log.Warn("IP labels unavailable", "err", err)
	}
	return ls, err
}

func (r *Resolver) resolve(ctx context.Context, stored []store.IPLabel, orgID int64, ip, user string, at time.Time) Verdict {
	var v Verdict
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return v
	}
	v.Addr = addr.Unmap()
	for _, l := range stored {
		if l.Prefix.Contains(v.Addr) {
			v.Labels = append(v.Labels, Label{Kind: l.Kind, Name: l.Name, Person: l.Person, Note: l.Note, Source: l.Source, Prefix: l.Prefix})
		}
	}
	v.Labels = append(v.Labels, builtin(v.Addr)...)
	if r != nil {
		for _, s := range r.Sources {
			ls, err := s.Lookup(ctx, orgID, v.Addr, at)
			if err != nil {
				if r.Log != nil {
					r.Log.Warn("IP source failed", "source", s.Name(), "err", err)
				}
				continue
			}
			v.Labels = append(v.Labels, ls...)
		}
		if user != "" {
			for _, h := range r.UserHints {
				if l, ok := h(user); ok {
					v.Labels = append(v.Labels, l)
				}
			}
		}
	}
	rank(v.Labels)
	return v
}

// kindRank orders kinds from most to least telling.
var kindRank = map[string]int{
	store.IPKindStaff: 0, store.IPKindOffice: 1, store.IPKindAutomation: 2, store.IPKindInfra: 3,
	store.IPKindTailnet: 4, store.IPKindPrivate: 5, store.IPKindUnknown: 6,
}

// sourceRank puts a Cloudflare IP list's labels ahead of the rest (manual
// labels above all) for the same range size: the team keeps the list
// current, while a manual label may be stale.
func sourceRank(src string) int {
	if store.IsIPListSource(src) {
		return 0
	}
	return 1
}

// rank sorts labels: known before guessed, then the most specific range,
// then a Cloudflare IP list's before any other source's, then the most
// telling kind. So a manual /32 still beats a list's /24, but a list's
// /32 beats a manual /32.
func rank(ls []Label) {
	slices.SortStableFunc(ls, func(a, b Label) int {
		if a.Guess != b.Guess {
			if a.Guess {
				return 1
			}
			return -1
		}
		if c := cmp.Compare(b.Prefix.Bits(), a.Prefix.Bits()); c != 0 {
			return c
		}
		if c := cmp.Compare(sourceRank(a.Source), sourceRank(b.Source)); c != 0 {
			return c
		}
		return cmp.Compare(kindRank[a.Kind], kindRank[b.Kind])
	})
}

// Tailnet is Tailscale's address range (CGNAT space; on a server it's the
// tailnet unless you also use carrier-grade NAT).
var (
	Tailnet   = netip.MustParsePrefix("100.64.0.0/10")
	Tailnet6  = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	privateV4 = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16")}
)

// builtin is what's known about an address without any labels.
func builtin(a netip.Addr) []Label {
	l := func(kind, name string, p netip.Prefix) []Label {
		return []Label{{Kind: kind, Name: name, Source: "builtin", Prefix: p}}
	}
	switch {
	case Tailnet.Contains(a):
		return l(store.IPKindTailnet, "Tailnet", Tailnet)
	case Tailnet6.Contains(a):
		return l(store.IPKindTailnet, "Tailnet", Tailnet6)
	case a.IsLoopback():
		return l(store.IPKindPrivate, "This server", netip.PrefixFrom(a, a.BitLen()))
	case a.IsLinkLocalUnicast():
		return l(store.IPKindPrivate, "Link-local", netip.PrefixFrom(a, a.BitLen()))
	case a.IsPrivate():
		for _, p := range privateV4 {
			if p.Contains(a) {
				return l(store.IPKindPrivate, "Private network", p)
			}
		}
		return l(store.IPKindPrivate, "Private network", netip.MustParsePrefix("fc00::/7"))
	}
	return nil
}
