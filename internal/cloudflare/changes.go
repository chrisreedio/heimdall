// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"slices"
	"strings"

	"github.com/chrisreedio/heimdall/internal/store"
)

// nameState is a public name's records, reduced to what a change is
// about: whether any is proxied, and where they point.
type nameState struct {
	proxied bool
	targets []string // "A 203.0.113.10", sorted
}

func states(recs []store.CloudflareRecord) map[string]*nameState {
	out := map[string]*nameState{}
	for _, r := range recs {
		name := strings.TrimSuffix(strings.ToLower(r.Name), ".")
		s := out[name]
		if s == nil {
			s = &nameState{}
			out[name] = s
		}
		s.proxied = s.proxied || r.Proxied
		s.targets = append(s.targets, r.Type+" "+strings.TrimSuffix(strings.ToLower(r.Content), "."))
	}
	for _, s := range out {
		slices.Sort(s.targets)
		s.targets = slices.Compact(s.targets)
	}
	return out
}

func (s *nameState) String() string {
	p := "not proxied"
	if s.proxied {
		p = "proxied"
	}
	return strings.Join(s.targets, ", ") + " (" + p + ")"
}

// Diff compares one zone's records before and after a sync: names added
// or removed, the proxy turned on or off, and targets changed. Changes
// carry no time, zone or orgs; the caller fills those in.
func Diff(before, after []store.CloudflareRecord) []store.SurfaceChange {
	old, cur := states(before), states(after)
	var out []store.SurfaceChange
	for name, n := range cur {
		o := old[name]
		if o == nil {
			out = append(out, store.SurfaceChange{Name: name, Kind: store.SurfaceAdded, New: n.String()})
			continue
		}
		if o.proxied && !n.proxied {
			out = append(out, store.SurfaceChange{Name: name, Kind: store.SurfaceUnproxied, Old: "proxied", New: "not proxied"})
		} else if !o.proxied && n.proxied {
			out = append(out, store.SurfaceChange{Name: name, Kind: store.SurfaceProxied, Old: "not proxied", New: "proxied"})
		}
		if !slices.Equal(o.targets, n.targets) {
			out = append(out, store.SurfaceChange{Name: name, Kind: store.SurfaceTarget,
				Old: strings.Join(o.targets, ", "), New: strings.Join(n.targets, ", ")})
		}
	}
	for name, o := range old {
		if cur[name] == nil {
			out = append(out, store.SurfaceChange{Name: name, Kind: store.SurfaceRemoved, Old: o.String()})
		}
	}
	slices.SortFunc(out, func(a, b store.SurfaceChange) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Kind, b.Kind)
	})
	return out
}
