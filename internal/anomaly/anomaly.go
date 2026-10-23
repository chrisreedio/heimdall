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

	"github.com/chrisreedio/heimdall/internal/findings"
	"github.com/chrisreedio/heimdall/internal/history"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/version"
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
	raise := func(a store.Anomaly) error {
		ok, err := e.Store.AddAnomaly(ctx, host.ID, cur.ID, a, e.Now())
		if ok {
			raised = append(raised, a)
		}
		return err
	}

	// Collector integrity applies from the first snapshot.
	if cur.CollectorSHA256 != "" {
		anyTrusted, trusted, err := e.Store.CollectorTrust(ctx, cur.CollectorSHA256)
		if err != nil {
			return nil, err
		}
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
		rebooted := cur.UptimeSeconds < elapsed-300 && cur.UptimeSeconds < prev.UptimeSeconds+elapsed-300
		switch {
		case rebooted && !expected:
			if err := raise(store.Anomaly{Rule: "unexpected_reboot", Severity: "low",
				Summary: "Rebooted outside a maintenance window",
				Detail:  map[string]any{"key": fmt.Sprint(cur.ID), "uptime_seconds": cur.UptimeSeconds}}); err != nil {
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

	// Package changes.
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
	// Upgrades are routine (unattended-upgrades); installs and removals aren't.
	if n := len(d.Added) + len(d.Removed); n > 0 && !expected {
		if err := raise(store.Anomaly{Rule: "package_change", Severity: "medium",
			Summary: fmt.Sprintf("%d package(s) installed or removed outside a window or plan: %s", n,
				changeNames(append(slices.Clone(d.Added), d.Removed...), 5)),
			Detail: map[string]any{"key": fmt.Sprint(cur.ID), "added": changeList(d.Added), "removed": changeList(d.Removed)}}); err != nil {
			return nil, err
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
		facts, err := e.Store.RecentSnapshotFacts(ctx, h.ID, 1)
		if err != nil || len(facts) == 0 {
			continue
		}
		ok, err := e.Store.AddAnomaly(ctx, h.ID, 0, store.Anomaly{Rule: "silence", Severity: "medium",
			Summary: fmt.Sprintf("No check-in since %s", facts[0].ReceivedAt.UTC().Format(time.RFC3339)),
			// Keyed by the last snapshot, so each silence is raised once.
			Detail: map[string]any{"key": fmt.Sprint(facts[0].ID)}}, e.Now())
		if err != nil {
			return n, err
		}
		if ok {
			n++
		}
	}
	return n, nil
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
