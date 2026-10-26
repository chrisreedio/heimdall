// SPDX-License-Identifier: AGPL-3.0-or-later

package surface

import (
	"context"
	"slices"
	"time"

	"github.com/realmwatch/heimdall/internal/cloudflare"
	"github.com/realmwatch/heimdall/internal/store"
)

// Load reads the map's inputs from the store and builds it. With
// cloudflareOn false the stored zones are ignored, so every site name
// shows as not on Cloudflare.
func Load(ctx context.Context, st *store.Store, cloudflareOn bool, now time.Time) (Map, error) {
	in := Input{Now: now}
	var err error
	if cloudflareOn {
		if in.Zones, err = st.CloudflareZones(ctx); err != nil {
			return Map{}, err
		}
	}
	if len(in.Zones) > 0 {
		if in.Records, err = st.CloudflareRecords(ctx); err != nil {
			return Map{}, err
		}
		if in.Settings, err = st.SurfaceSettingsAll(ctx); err != nil {
			return Map{}, err
		}
		if in.CNAMEs, err = st.CNAMEChecks(ctx); err != nil {
			return Map{}, err
		}
		if in.Addrs, err = st.ReportAddrs(ctx); err != nil {
			return Map{}, err
		}
		known, err := st.KnownIPPrefixes(ctx)
		if err != nil {
			return Map{}, err
		}
		in.Known = cloudflare.Known(known, cloudflare.NewEdge())
	}
	if in.Sites, err = st.AllSiteNames(ctx); err != nil {
		return Map{}, err
	}
	if in.Hosts, err = st.SurfaceHosts(ctx); err != nil {
		return Map{}, err
	}
	if in.Stacks, err = st.SurfaceSites(ctx); err != nil {
		return Map{}, err
	}
	if in.Counts, err = st.OpenFindingCounts(ctx); err != nil {
		return Map{}, err
	}
	return Build(in), nil
}

// ChangesFor keeps the changes a viewer may see: those about a name that
// led to one of their orgs' hosts or sites (admins: all).
func ChangesFor(cs []store.SurfaceChange, admin bool, can func(int64) bool) []store.SurfaceChange {
	if admin {
		return cs
	}
	var out []store.SurfaceChange
	for _, c := range cs {
		if slices.ContainsFunc(c.Orgs, can) {
			out = append(out, c)
		}
	}
	return out
}
