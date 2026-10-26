// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/privilege"
	"github.com/realmwatch/heimdall/internal/store"
)

// newIPResolver builds what the hub knows about IP addresses, and the
// syncers that keep synced sources' labels current (run by serve). Each
// source adds itself here, one block each.
func newIPResolver(cfg config.Config, s *store.Store, log *slog.Logger) (*ipinfo.Resolver, []ipinfo.Syncer) {
	log = log.With("component", "ipinfo")
	r := &ipinfo.Resolver{Store: s, Log: log, Sources: []ipinfo.Source{ipinfo.Hosts{Store: s}}}
	var syncers []ipinfo.Syncer
	r.Sources = append(r.Sources, ipinfo.SignIns{Store: s}) // Heimdall sign-ins from the same address (signin.go)
	_ = cfg

	// ── sources: keep one block per source, in this order ──
	// (deploy services)
	hints, dsSyncers := deployServices(cfg, s, log) // ipservices.go
	r.UserHints = append(r.UserHints, hints...)
	syncers = append(syncers, dsSyncers...)
	// (Tailscale)
	if ts, err := newTailscaleSyncer(cfg, s, log, false); err != nil { // tailscale.go; nil when [tailscale] is off
		log.Error("Tailscale sync is enabled but has no credential", "err", err)
	} else if ts != nil {
		syncers = append(syncers, ts)
	}
	// (Cloudflare)
	if cfg.Cloudflare.Enabled { // edge ranges, zones, DNS, security events, Radar (cloudflare.go)
		syncers = append(syncers, newCloudflare(cfg, s, log, r)...)
	}

	return r, syncers
}

// resolveKnownFunc closes privilege_unknown_source anomalies whose address
// is known now (privilege.ResolveKnown), logging what it did.
func resolveKnownFunc(s *store.Store, ips *ipinfo.Resolver, log *slog.Logger) func(context.Context) {
	return func(ctx context.Context) {
		if n, err := privilege.ResolveKnown(ctx, s, ips, time.Now()); err != nil {
			log.Warn("closing unknown-address anomalies failed", "err", err)
		} else if n > 0 {
			log.Info("unknown-address anomalies resolved: the address is known now", "count", n)
		}
	}
}

// everyHour runs f shortly after start and then hourly, until ctx ends.
func everyHour(ctx context.Context, f func(context.Context)) {
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f(ctx)
			t.Reset(time.Hour)
		}
	}
}

// resolveKnownCLI is resolveKnownFunc for commands that add labels: it
// says on stderr what it closed.
func resolveKnownCLI(a *app, s *store.Store) {
	n, err := privilege.ResolveKnown(a.ctx, s, nil, time.Now())
	switch {
	case err != nil:
		fmt.Fprintf(a.stderr, "closing unknown-address anomalies failed: %v\n", err)
	case n == 1:
		fmt.Fprintln(a.stderr, "1 unknown-address anomaly resolved: its address is known now")
	case n > 1:
		fmt.Fprintf(a.stderr, "%d unknown-address anomalies resolved: their addresses are known now\n", n)
	}
}
