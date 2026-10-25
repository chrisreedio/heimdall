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
	_ = cfg

	// ── sources: keep one block per source, in this order ──
	// (deploy services)
	// (Tailscale)
	// (Cloudflare)

	return r, syncers
}
