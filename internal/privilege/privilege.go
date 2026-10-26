// SPDX-License-Identifier: AGPL-3.0-or-later

// Package privilege holds the hub side of the opt-in privilege watch
// (install.sh --watch-privilege): turning what servers report into
// anomalies. It's apart from package anomaly so ingest can use it without
// importing the findings engine. See docs/anomaly-signals.md.
package privilege

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/store"
)

// KindLabel names a privilege event kind for people.
func KindLabel(kind string) string {
	if kind == "root-ssh" {
		return "root SSH"
	}
	return kind
}

// Counts writes counts like "3 sudo, 1 root SSH" (sudo, su, root
// SSH order).
func Counts(counts map[string]int) string {
	var parts []string
	for _, k := range []string{"sudo", "su", "root-ssh"} {
		if n := counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, KindLabel(k)))
		}
	}
	return strings.Join(parts, ", ")
}

// Who describes who an event was, as far as the server recorded it:
// "chris from 203.0.113.7", "chris", "from 203.0.113.7" or "".
func Who(ev store.PrivilegeEvent) string {
	src := ev.Source
	if src == "?" {
		src = ""
	}
	switch {
	case ev.User != "" && src != "":
		return ev.User + " from " + src
	case src != "":
		return "from " + src
	}
	return ev.User
}

// Rules raises privilege watch anomalies.
type Rules struct {
	Store *store.Store
	Now   func() time.Time
	IPs   *ipinfo.Resolver // what's known about sessions' sources; nil: labels and built-ins only
}

// OnReport runs the privilege watch rules on what a push reported:
// fresh holds the events not seen before, prev and cur the watch state
// before and now ("" when not reported).
//
//   - privileged_access: events outside a maintenance window, one anomaly
//     per host per (UTC) day, its count growing as more arrive.
//   - privilege_watch_disabled: the host reported "on" before and now
//     reports "off" or "partial". Hosts that never enabled it never alert.
//   - privilege_unknown_source, privilege_off_tailnet: where sessions came
//     from (source.go).
func (e *Rules) OnReport(ctx context.Context, host store.IngestHost, snapshotID int64,
	fresh []store.PrivilegeEvent, prev, cur string) ([]store.Anomaly, error) {
	var raised []store.Anomaly
	now := e.Now()
	if prev == "on" && (cur == "off" || cur == "partial") {
		what := "was removed"
		if cur == "partial" {
			what = "is only partly installed (a PAM line or the hook is missing)"
		}
		a := store.Anomaly{Rule: "privilege_watch_disabled", Severity: "high",
			Summary: "Privilege watch " + what + ", while the host still reports",
			Detail:  map[string]any{"key": now.UTC().Format(time.RFC3339Nano), "from": prev, "to": cur}}
		ok, err := e.Store.AddAnomaly(ctx, host.ID, snapshotID, a, now)
		if err != nil {
			return raised, err
		}
		if ok {
			raised = append(raised, a)
		}
	}
	if len(fresh) == 0 {
		return raised, nil
	}

	windows, err := e.Store.WindowsFor(ctx, host.ID)
	if err != nil {
		return raised, err
	}
	type day struct {
		counts map[string]int
		users  []string
	}
	days := map[string]*day{}
	for _, ev := range fresh {
		if slices.ContainsFunc(windows, func(w store.Window) bool { return w.Overlaps(ev.At, ev.At) }) {
			continue
		}
		k := ev.At.UTC().Format(time.DateOnly)
		d := days[k]
		if d == nil {
			d = &day{counts: map[string]int{}}
			days[k] = d
		}
		d.counts[ev.Kind]++
		if who := Who(ev); who != "" && !slices.Contains(d.users, who) {
			d.users = append(d.users, who)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(days)) {
		d := days[k]
		date, _ := time.Parse(time.DateOnly, k)
		on := date.Format("Jan 2, 2006")
		summarize := func(counts map[string]int, users []string) string {
			total := 0
			for _, n := range counts {
				total += n
			}
			s := fmt.Sprintf("%d privileged access%s outside a maintenance window on %s (UTC): %s",
				total, map[bool]string{true: "", false: "es"}[total == 1], on, Counts(counts))
			if len(users) > 0 {
				s += " by " + strings.Join(users, ", ")
			}
			return s
		}
		a := store.Anomaly{Rule: "privileged_access", Severity: "medium",
			Detail: map[string]any{"key": k, "day": k}}
		ok, err := e.Store.CountAnomaly(ctx, host.ID, snapshotID, a, d.counts, d.users, summarize, now)
		if err != nil {
			return raised, err
		}
		if ok {
			a.Summary = summarize(d.counts, d.users)
			raised = append(raised, a)
		}
	}
	more, err := e.sourceRules(ctx, host, snapshotID, fresh, windows, now) // source.go
	return append(raised, more...), err
}
