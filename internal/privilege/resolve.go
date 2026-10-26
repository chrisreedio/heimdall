// SPDX-License-Identifier: AGPL-3.0-or-later

package privilege

import (
	"context"
	"time"

	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/store"
)

// ResolveKnown closes open privilege_unknown_source anomalies whose
// address has since become known: labeled, in a synced range, one of your
// hosts, or someone signed in to Heimdall from it near the time. It uses
// the rule's own test (ipinfo.UnknownAddress, at the time the anomaly was
// detected), so a deploy service's account name alone still doesn't count.
// Each is closed as Heimdall with a note saying who the address is.
//
// privilege_off_tailnet is left alone: a label says whose an address is,
// not that it's allowed. So is privileged_access.
//
// Run when a label is added, after a synced source's sync, and hourly
// (for sign-ins). ips nil: labels, your hosts and sign-ins.
func ResolveKnown(ctx context.Context, st *store.Store, ips *ipinfo.Resolver, now time.Time) (int, error) {
	if ips == nil {
		ips = &ipinfo.Resolver{Store: st, Sources: []ipinfo.Source{ipinfo.Hosts{Store: st}, ipinfo.SignIns{Store: st}}}
	}
	open, err := st.OpenSourceAnomalies(ctx, ruleUnknownSource)
	if err != nil || len(open) == 0 {
		return 0, err
	}
	batches := map[int64]func(ip, user string, at time.Time) ipinfo.Verdict{}
	n := 0
	for _, a := range open {
		resolve := batches[a.Host.OrgID]
		if resolve == nil {
			resolve = ips.Batch(ctx, a.Host.OrgID)
			batches[a.Host.OrgID] = resolve
		}
		v := resolve(a.Source, "", a.DetectedAt)
		l, ok := v.AddressLabel()
		if !ok {
			continue
		}
		closed, err := st.ResolveAnomaly(ctx, a.ID, KnownNote(v.Addr.String(), l), now)
		if err != nil {
			return n, err
		}
		if closed {
			n++
		}
	}
	return n, nil
}

// KnownNote says why an address is known now, for the anomaly it closes:
// "resolved: 203.0.113.4 is now known (staff: alice@example.com, label
// 'Alice home')".
func KnownNote(addr string, l ipinfo.Label) string {
	what := l.Kind
	if l.Person != "" {
		what += ": " + l.Person
	}
	if l.Guess {
		what = "probably " + what
	}
	switch l.Source {
	case store.IPSourceManual:
		what += ", label '" + l.Name + "'"
	case "signin":
		what += ", signed in to Heimdall from it"
	default:
		if store.IsIPListSource(l.Source) {
			what += ", Cloudflare IP list '" + l.Name + "'"
			break
		}
		what += ", '" + l.Name + "' from " + l.Source
	}
	return "resolved: " + addr + " is now known (" + what + ")"
}
