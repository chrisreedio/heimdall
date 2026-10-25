// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log/slog"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/ipinfo"
	"github.com/chrisreedio/heimdall/internal/store"
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
