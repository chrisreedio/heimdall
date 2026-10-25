// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/chrisreedio/heimdall/internal/store"
)

// The surface map's part of a zone sync (Syncer.Surface, docs/surface.md):
// each zone's settings and edge certificates, a DNS check of CNAME targets
// outside our zones, and the changes to public names since the last sync.

// surfaceBefore is the stored state a sync is compared against.
type surfaceBefore struct {
	zones map[string]bool
	recs  map[string][]store.CloudflareRecord // by zone ID
}

func (s *Syncer) surfaceBefore(ctx context.Context) (*surfaceBefore, error) {
	zs, err := s.Store.CloudflareZones(ctx)
	if err != nil {
		return nil, err
	}
	recs, err := s.Store.CloudflareRecords(ctx)
	if err != nil {
		return nil, err
	}
	b := &surfaceBefore{zones: map[string]bool{}, recs: map[string][]store.CloudflareRecord{}}
	for _, z := range zs {
		b.zones[z.ID] = true
	}
	for _, r := range recs {
		b.recs[r.ZoneID] = append(b.recs[r.ZoneID], r)
	}
	return b, nil
}

// surface runs after the records are stored. Like the rest of the sync it
// keeps the last good data when a call fails; a missing permission is a
// state, not an error.
func (s *Syncer) surface(ctx context.Context, zones []store.CloudflareZone, read map[string][]store.CloudflareRecord, before *surfaceBefore) []error {
	var errs []error
	now := s.Now()
	if before != nil {
		if err := s.recordChanges(ctx, zones, read, before); err != nil {
			errs = append(errs, fmt.Errorf("surface changes: %w", err))
		}
	}
	for _, z := range zones {
		state, note, zs, err := s.Client.Settings(ctx, z.ID)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s zone settings: %w", z.Name, err))
		}
		if err := s.Store.SetSurfaceSettings(ctx, z.ID, state, note, zs.SSL, zs.AlwaysHTTPS, zs.MinTLS, now); err != nil {
			return append(errs, err)
		}
		// Certificates are a nice-to-have: a failure is stored, not
		// reported as a sync error.
		state, note, exp, _ := s.Client.CertExpiry(ctx, z.ID)
		if err := s.Store.SetSurfaceCert(ctx, z.ID, state, note, exp, now); err != nil {
			return append(errs, err)
		}
	}
	recs, err := s.Store.CloudflareRecords(ctx)
	if err != nil {
		return append(errs, err)
	}
	checks := CheckCNAMEs(ctx, s.Resolver, ForeignTargets(zones, recs))
	if err := s.Store.PutCNAMEChecks(ctx, checks, now); err != nil {
		errs = append(errs, err)
	}
	return errs
}

// recordChanges diffs each zone whose records were read against what was
// stored before. A zone seen for the first time has no "before", so its
// records aren't all logged as added.
func (s *Syncer) recordChanges(ctx context.Context, zones []store.CloudflareZone, read map[string][]store.CloudflareRecord, before *surfaceBefore) error {
	hosts, err := s.Store.ReportAddrs(ctx)
	if err != nil {
		return err
	}
	sites, err := s.Store.AllSiteNames(ctx)
	if err != nil {
		return err
	}
	var all []store.SurfaceChange
	for _, z := range zones {
		after, ok := read[z.ID]
		if !ok || !before.zones[z.ID] {
			continue
		}
		after = normalized(z.ID, after)
		cs := Diff(before.recs[z.ID], after)
		if len(cs) == 0 {
			continue
		}
		orgs := orgsByName(zones, before.recs[z.ID], hosts, sites)
		for name, os := range orgsByName(zones, after, hosts, sites) {
			for _, o := range os {
				if !slices.Contains(orgs[name], o) {
					orgs[name] = append(orgs[name], o)
				}
			}
		}
		for _, c := range cs {
			c.ZoneID, c.Zone, c.Orgs = z.ID, z.Name, orgs[c.Name]
			all = append(all, c)
		}
	}
	return s.Store.AddSurfaceChanges(ctx, all, s.Now())
}

// orgsByName maps each record name to the orgs whose hosts or sites it
// leads to.
func orgsByName(zones []store.CloudflareZone, recs []store.CloudflareRecord, hosts []store.ReportAddr, sites []store.SiteNames) map[string][]int64 {
	out := map[string][]int64{}
	for _, r := range Build(zones, recs, hosts, sites, nil).Records {
		for _, h := range r.Hosts {
			if !slices.Contains(out[r.Name], h.OrgID) {
				out[r.Name] = append(out[r.Name], h.OrgID)
			}
		}
		for _, x := range r.Sites {
			if !slices.Contains(out[r.Name], x.OrgID) {
				out[r.Name] = append(out[r.Name], x.OrgID)
			}
		}
	}
	return out
}

// normalized copies records as the store keeps them: in the zone, with
// lowercase names and no trailing dot.
func normalized(zoneID string, recs []store.CloudflareRecord) []store.CloudflareRecord {
	out := make([]store.CloudflareRecord, len(recs))
	for i, r := range recs {
		r.ZoneID, r.Name = zoneID, strings.TrimSuffix(strings.ToLower(r.Name), ".")
		out[i] = r
	}
	return out
}
