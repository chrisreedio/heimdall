// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/tailscale"
)

// tailnetFresh is how recent the Tailscale sync must be for its devices'
// state to count.
const tailnetFresh = time.Hour

// CheckSilentOnline raises silent_online for hosts that stopped reporting
// while their tailnet device stayed up: seen by Tailscale at least quiet
// after the host's last report, so the machine is running but its
// collector isn't sending. That's what a collector someone switched off
// looks like (a powered-off or unplugged server drops off the tailnet too).
// It needs a recent Tailscale sync, and skips hosts in a maintenance window
// or with the rule suppressed. Once per silence episode.
func (e *Engine) CheckSilentOnline(ctx context.Context, quiet time.Duration) (int, error) {
	if quiet <= 0 {
		return 0, nil
	}
	now := e.Now()
	sync, err := e.Store.TailnetSyncState(ctx)
	if err != nil || sync.SyncedAt.IsZero() || now.Sub(sync.SyncedAt) > tailnetFresh {
		return 0, err // Tailscale off, never synced or stale: nothing to compare
	}
	silent, err := e.Store.SilentHosts(ctx, now.Add(-quiet))
	if err != nil || len(silent) == 0 {
		return 0, err
	}
	devs, err := e.Store.TailnetDevices(ctx)
	if err != nil {
		return 0, err
	}
	hosts, err := e.Store.TailnetHosts(ctx)
	if err != nil {
		return 0, err
	}
	matched := tailscale.MatchHosts(hosts, devs)
	n := 0
	for _, h := range silent {
		d, ok := matched[h.ID]
		if !ok {
			continue
		}
		seen := d.LastSeen
		if d.Online {
			seen = sync.SyncedAt
		}
		if seen.Sub(h.LastSeenAt) < quiet {
			continue // it went quiet on the tailnet too, or not for long enough
		}
		windows, err := e.Store.WindowsFor(ctx, h.ID)
		if err != nil {
			return n, err
		}
		if slices.ContainsFunc(windows, func(w store.Window) bool { return w.Overlaps(now, now) }) {
			continue
		}
		state := "online"
		if !d.Online {
			state = "last seen " + seen.UTC().Format(time.RFC3339)
		}
		ok, err = e.Store.AddAnomaly(ctx, h.ID, 0, store.Anomaly{Rule: "silent_online", Severity: "high",
			Summary: fmt.Sprintf("No check-in since %s, but its tailnet device %s is %s: the server is up and its collector isn't reporting",
				h.LastSeenAt.UTC().Format(time.RFC3339), tailscale.DeviceName(d), state),
			Detail: map[string]any{"key": store.SilenceKey(h.LastSeenAt), "device": d.ID}}, now)
		if err != nil {
			return n, err
		}
		if ok {
			n++
		}
	}
	return n, nil
}
