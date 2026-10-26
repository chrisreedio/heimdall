// SPDX-License-Identifier: AGPL-3.0-or-later

// Package anomaly raises tripwire alerts by comparing a host's snapshots
// over time and against its peers. See docs/anomaly-signals.md: these are
// tripwires, not intrusion detection.
package anomaly

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/findings"
	"github.com/realmwatch/heimdall/internal/history"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/version"
)

// LearningSnapshots: a host's first snapshots only set its baseline.
const LearningSnapshots = 3

type Engine struct {
	Store *store.Store
	Now   func() time.Time
	Log   *slog.Logger
}

// OnSnapshot runs the change rules on a host's newest snapshot.
func (e *Engine) OnSnapshot(ctx context.Context, host store.IngestHost) ([]store.Anomaly, error) {
	facts, err := e.Store.RecentSnapshotFacts(ctx, host.ID, 2)
	if err != nil || len(facts) == 0 {
		return nil, err
	}
	cur := facts[0]
	var raised []store.Anomaly
	raiseOK := func(a store.Anomaly) (bool, error) {
		ok, err := e.Store.AddAnomaly(ctx, host.ID, cur.ID, a, e.Now())
		if ok {
			raised = append(raised, a)
		}
		return ok, err
	}
	raise := func(a store.Anomaly) error {
		_, err := raiseOK(a)
		return err
	}

	// Collector integrity applies from the first snapshot.
	anyTrusted, trusted, err := e.Store.CollectorTrust(ctx, cur.CollectorSHA256)
	if err != nil {
		return nil, err
	}
	if cur.CollectorSHA256 != "" {
		if anyTrusted && !trusted {
			if err := raise(store.Anomaly{Rule: "collector_changed", Severity: "high",
				Summary: fmt.Sprintf("Collector %s reported an untrusted checksum %s…", cur.CollectorVer, cur.CollectorSHA256[:12]),
				Detail:  map[string]any{"key": cur.CollectorSHA256, "version": cur.CollectorVer}}); err != nil {
				return nil, err
			}
		}
	}

	n, err := e.Store.SnapshotCount(ctx, host.ID)
	if err != nil || n <= LearningSnapshots || len(facts) < 2 {
		return raised, err // still learning this host's baseline
	}
	prev := facts[1]

	windows, err := e.Store.WindowsFor(ctx, host.ID)
	if err != nil {
		return nil, err
	}
	inWindow := slices.ContainsFunc(windows, func(w store.Window) bool { return w.Overlaps(prev.ReceivedAt, cur.ReceivedAt) })
	inPlan, err := e.Store.InOpenPlan(ctx, host.ID)
	if err != nil {
		return nil, err
	}
	expected := inWindow || inPlan

	// Reboots and kernels.
	elapsed := int64(cur.ReceivedAt.Sub(prev.ReceivedAt).Seconds())
	if cur.UptimeSeconds >= 0 && prev.UptimeSeconds >= 0 {
		// Uptime never goes backwards without a reboot, however close
		// together the reports are (a report minutes before a reboot, and
		// the one 3 minutes after boot).
		rebooted := cur.UptimeSeconds < elapsed-300 && cur.UptimeSeconds < prev.UptimeSeconds+elapsed-300 ||
			cur.UptimeSeconds > 0 && cur.UptimeSeconds < prev.UptimeSeconds
		switch {
		case rebooted && !expected:
			if err := raise(store.Anomaly{Rule: "unexpected_reboot", Severity: "low",
				Summary: "Rebooted outside a maintenance window",
				Detail:  map[string]any{"key": cur.Key(), "uptime_seconds": cur.UptimeSeconds}}); err != nil {
				return nil, err
			}
		case !rebooted && cur.Kernel != prev.Kernel && cur.Kernel != "" && prev.Kernel != "":
			if err := raise(store.Anomaly{Rule: "kernel_no_reboot", Severity: "medium",
				Summary: fmt.Sprintf("Kernel changed from %s to %s without a reboot", prev.Kernel, cur.Kernel),
				Detail:  map[string]any{"key": prev.Kernel + "→" + cur.Kernel}}); err != nil {
				return nil, err
			}
		}
	}

	// Reports that don't add up (consistency.go). Uptime is in heartbeats
	// too. No maintenance makes uptime outrun the clock, so windows and
	// plans don't apply to it.
	if a, ok := uptimeInconsistent(prev, cur); ok {
		if err := raise(a); err != nil {
			return nil, err
		}
	}

	// Snapshot-to-snapshot rules. An unchanged report (heartbeat) shares its
	// snapshot's inventory, so there is nothing to compare.
	if prev.ID == cur.ID {
		return raised, nil
	}
	if a, ok := osChanged(prev, cur); ok && !expected {
		if err := raise(a); err != nil {
			return nil, err
		}
	}
	if a, ok := collectorDowngrade(prev, cur, anyTrusted, trusted); ok && !expected {
		if err := raise(a); err != nil {
			return nil, err
		}
	}
	a, err := e.Store.SnapshotPackages(ctx, host.ID, prev.ID)
	if err != nil {
		return nil, err
	}
	b, err := e.Store.SnapshotPackages(ctx, host.ID, cur.ID)
	if err != nil {
		return nil, err
	}
	inv, err := e.Store.Inventory(ctx, host)
	if err != nil {
		return nil, err
	}
	scheme := version.Scheme("")
	if info, ok := findings.HostEcosystem(inv); ok {
		scheme = info.Scheme
	}
	d := history.Compare(scheme, a, b)

	if len(d.Downgraded) > 0 && !expected {
		if err := raise(store.Anomaly{Rule: "package_downgrade", Severity: "high",
			Summary: fmt.Sprintf("%d package(s) downgraded: %s", len(d.Downgraded), changeNames(d.Downgraded, 5)),
			Detail:  map[string]any{"key": fmt.Sprint(cur.ID), "packages": changeList(d.Downgraded)}}); err != nil {
			return nil, err
		}
	}
	// A big drop is one summarising anomaly in place of package_change
	// (unless package_drop is suppressed for the host).
	dropped := false
	if an, ok := packageDrop(len(a), len(b), d, cur.ID); ok && !expected {
		if dropped, err = raiseOK(an); err != nil {
			return nil, err
		}
	}
	// Upgrades are routine (unattended-upgrades); installs and removals aren't.
	if n := len(d.Added) + len(d.Removed); n > 0 && !expected && !dropped {
		if err := raise(store.Anomaly{Rule: "package_change", Severity: "medium",
			Summary: fmt.Sprintf("%d package(s) installed or removed outside a window or plan: %s", n,
				changeNames(append(slices.Clone(d.Added), d.Removed...), 5)),
			Detail: map[string]any{"key": fmt.Sprint(cur.ID), "added": changeList(d.Added), "removed": changeList(d.Removed)}}); err != nil {
			return nil, err
		}
	}
	// Back to an older inventory, with packages changed since the last one.
	if !d.Empty() && !expected {
		matchID, matchedAt, found, err := e.Store.InventoryMatch(ctx, host.ID, cur.ID, prev.ID)
		if err != nil {
			return nil, err
		}
		if found {
			if err := raise(inventoryReverted(matchID, matchedAt, d, cur.ID)); err != nil {
				return nil, err
			}
		}
	}
	// Odd one out: new packages that none of the host's tag peers have.
	if len(d.Added) > 0 {
		names := make([]string, len(d.Added))
		for i, c := range d.Added {
			names[i] = c.Name
		}
		have, peers, err := e.Store.PeerPackages(ctx, host.ID, names)
		if err != nil {
			return nil, err
		}
		if peers >= 2 {
			var odd []string
			for _, nm := range names {
				if have[nm] == 0 {
					odd = append(odd, nm)
				}
			}
			if len(odd) > 0 {
				if err := raise(store.Anomaly{Rule: "peer_outlier", Severity: "medium",
					Summary: fmt.Sprintf("New package(s) none of its %d tag peers have: %s", peers, strings.Join(first(odd, 5), ", ")),
					Detail:  map[string]any{"key": fmt.Sprint(cur.ID), "packages": odd}}); err != nil {
					return nil, err
				}
			}
		}
	}
	return raised, nil
}

// CheckSilence flags hosts that have stopped reporting (once per silence).
func (e *Engine) CheckSilence(ctx context.Context, staleAfter time.Duration) (int, error) {
	if staleAfter <= 0 {
		return 0, nil
	}
	hosts, err := e.Store.SilentHosts(ctx, e.Now().Add(-staleAfter))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, h := range hosts {
		ok, err := e.raiseSilence(ctx, h)
		if err != nil {
			return n, err
		}
		if ok {
			n++
		}
	}
	return n, nil
}

// raiseSilence records a host's silence. It's keyed by the last report's
// time, so each silence episode is raised once, whether the fast check
// (hosts.alert_after) or the stale check (hosts.stale_after) sees it first.
func (e *Engine) raiseSilence(ctx context.Context, h store.SilentHost) (bool, error) {
	return e.Store.AddAnomaly(ctx, h.ID, 0, store.Anomaly{Rule: "silence", Severity: "medium",
		Summary: fmt.Sprintf("No check-in since %s", h.LastSeenAt.UTC().Format(time.RFC3339)),
		Detail:  map[string]any{"key": store.SilenceKey(h.LastSeenAt)}}, e.Now())
}

// SilenceAlerts is what the fast silence check found: hosts to alert on
// now, and hosts that reported again after an alert.
type SilenceAlerts struct {
	Silent []store.SilentHost
	Back   []store.SilentHost
}

// CheckFastSilence is the dead man's switch: hosts that reported before
// and have been quiet for longer than alertAfter get a silence anomaly and
// are returned for an immediate notification, once per silence episode.
// Hosts in a maintenance window, or with the silence rule suppressed, are
// skipped. The caller sends the notices, then calls MarkSilenceAlerts.
func (e *Engine) CheckFastSilence(ctx context.Context, alertAfter time.Duration) (SilenceAlerts, error) {
	var out SilenceAlerts
	if alertAfter <= 0 {
		return out, nil
	}
	now := e.Now()
	back, err := e.Store.SilenceAlertsOutstanding(ctx)
	if err != nil {
		return out, err
	}
	for _, h := range back {
		if h.LastSeenAt.After(h.AlertedFor) {
			if err := e.Store.NoteSilenceEnded(ctx, h.ID, h.AlertedFor, h.LastSeenAt); err != nil {
				return out, err
			}
			out.Back = append(out.Back, h)
		}
	}
	silent, err := e.Store.SilentHosts(ctx, now.Add(-alertAfter))
	if err != nil {
		return out, err
	}
	for _, h := range silent {
		if h.AlertedFor.Equal(h.LastSeenAt) {
			continue // already alerted for this episode
		}
		// Only hosts that report more often than alertAfter: a collector
		// still on a daily timer would otherwise alert every day (the stale
		// check covers it). Going quiet always leaves the last gap short, so
		// this can't be gamed without first raising this alert.
		facts, err := e.Store.RecentSnapshotFacts(ctx, h.ID, 2)
		if err != nil {
			return out, err
		}
		if len(facts) < 2 || facts[0].ReceivedAt.Sub(facts[1].ReceivedAt) > alertAfter {
			continue
		}
		if muted, err := e.Store.Suppressed(ctx, h.ID, "silence", now); err != nil || muted {
			if err != nil {
				return out, err
			}
			continue
		}
		windows, err := e.Store.WindowsFor(ctx, h.ID)
		if err != nil {
			return out, err
		}
		if slices.ContainsFunc(windows, func(w store.Window) bool { return w.Overlaps(now, now) }) {
			continue // planned downtime; alerts once the window is over if still quiet
		}
		if _, err := e.raiseSilence(ctx, h); err != nil {
			return out, err
		}
		out.Silent = append(out.Silent, h)
	}
	return out, nil
}

// MarkSilenceAlerts records that the notices for a check went out, so the
// same episode isn't alerted again and a "back" notice is sent only once.
func (e *Engine) MarkSilenceAlerts(ctx context.Context, a SilenceAlerts) error {
	for _, h := range a.Back {
		if err := e.Store.ClearSilenceAlerted(ctx, h.ID); err != nil {
			return err
		}
	}
	for _, h := range a.Silent {
		if err := e.Store.SetSilenceAlerted(ctx, h.ID, h.LastSeenAt); err != nil {
			return err
		}
	}
	return nil
}

func changeNames(cs []history.Change, max int) string {
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		names = append(names, c.Name)
	}
	return strings.Join(first(names, max), ", ")
}

func changeList(cs []history.Change) []string {
	out := make([]string, 0, len(cs))
	for _, c := range first(cs, 50) {
		out = append(out, strings.TrimSpace(c.Name+" "+c.From+"→"+c.To))
	}
	return out
}

func first[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}
