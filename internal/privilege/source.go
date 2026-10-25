// SPDX-License-Identifier: AGPL-3.0-or-later

package privilege

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/ipinfo"
	"github.com/chrisreedio/heimdall/internal/store"
)

// The rules on where privileged sessions came from (docs/ip-awareness.md):
//
//   - privilege_unknown_source: a session from an address nothing is known
//     about (no label, not the tailnet or a private network, no sign-in
//     from it), outside a maintenance window. A deploy service's account
//     name alone doesn't make an address known (ipinfo.UnknownAddress).
//   - privilege_off_tailnet: the org's tailnet-only policy is on and a
//     session came from anywhere but the tailnet, a private network or
//     loopback, labeled or not, window or not. A deploy service's synced
//     range is exempt while the org allows deploy services.
//
// Each is one anomaly per host, source and (UTC) day, its count growing as
// more sessions arrive. An event that breaks the policy raises only that.
const (
	ruleUnknownSource = "privilege_unknown_source"
	ruleOffTailnet    = "privilege_off_tailnet"
)

func (e *Rules) sourceRules(ctx context.Context, host store.IngestHost, snapshotID int64,
	fresh []store.PrivilegeEvent, windows []store.Window, now time.Time) ([]store.Anomaly, error) {
	ips := e.IPs
	if ips == nil {
		ips = &ipinfo.Resolver{Store: e.Store}
	}
	policy, err := e.Store.IPPolicy(ctx, host.OrgID)
	if err != nil {
		return nil, err
	}
	type key struct{ rule, day, source string }
	type group struct {
		counts map[string]int
		users  []string
		label  string
	}
	groups := map[key]*group{}
	var resolve func(ip, user string, at time.Time) ipinfo.Verdict
	for _, ev := range fresh {
		if ev.Source == "" || ev.Source == "?" {
			continue
		}
		if resolve == nil {
			resolve = ips.Batch(ctx, host.OrgID)
		}
		v := resolve(ev.Source, ev.User, ev.At)
		k := key{day: ev.At.UTC().Format(time.DateOnly), source: ev.Source}
		switch {
		case policy.TailnetOnly && !ipinfo.Internal(v.Addr) && !(policy.AllowServices && v.SyncedAutomation()):
			k.rule = ruleOffTailnet
		case v.UnknownAddress() && !slices.ContainsFunc(windows, func(w store.Window) bool { return w.Overlaps(ev.At, ev.At) }):
			k.rule = ruleUnknownSource
		default:
			continue
		}
		g := groups[k]
		if g == nil {
			g = &group{counts: map[string]int{}, label: LabelText(v)}
			groups[k] = g
		}
		g.counts[ev.Kind]++
		if ev.User != "" && !slices.Contains(g.users, ev.User) {
			g.users = append(g.users, ev.User)
		}
	}
	var raised []store.Anomaly
	for _, k := range slices.SortedFunc(maps.Keys(groups), func(a, b key) int {
		return strings.Compare(a.rule+a.day+a.source, b.rule+b.day+b.source)
	}) {
		g := groups[k]
		date, _ := time.Parse(time.DateOnly, k.day)
		on := date.Format("Jan 2, 2006")
		from := k.source
		if g.label != "" {
			from += " (" + g.label + ")"
		}
		summarize := func(counts map[string]int, users []string) string {
			var s string
			if k.rule == ruleOffTailnet {
				s = fmt.Sprintf("Privileged access from outside the tailnet, %s, on %s (UTC): %s", from, on, Counts(counts))
			} else {
				s = fmt.Sprintf("Privileged access from an unknown address, %s, on %s (UTC): %s", k.source, on, Counts(counts))
			}
			if len(users) > 0 {
				s += " by " + strings.Join(users, ", ")
			}
			return s
		}
		a := store.Anomaly{Rule: k.rule, Severity: "high",
			Detail: map[string]any{"key": k.day + " " + k.source, "day": k.day, "source": k.source}}
		ok, err := e.Store.CountAnomaly(ctx, host.ID, snapshotID, a, g.counts, g.users, summarize, now)
		if err != nil {
			return raised, err
		}
		if ok {
			a.Summary = summarize(g.counts, g.users)
			raised = append(raised, a)
		}
	}
	return raised, nil
}

// LabelText says briefly who an address is, from its verdict: "alice",
// "probably alice", "Laravel Forge", "web-01", or "" when nothing's known.
func LabelText(v ipinfo.Verdict) string {
	if v.Unknown() {
		return ""
	}
	b := v.Best()
	who := b.Name
	switch {
	case b.Person != "" && b.Kind == store.IPKindStaff:
		who = b.Person
	case b.Person != "" && b.Name != "":
		who = b.Name + ", " + b.Person
	}
	if b.Guess {
		return "probably " + who
	}
	return who
}
