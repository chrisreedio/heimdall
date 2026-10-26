// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// Syncer reads the token's zones, their A/AAAA/CNAME records and (if
// Security) their security event counts and web offenders (web.go) into
// the store. On an API failure
// the last good data stays: a failed zone list changes nothing, a zone
// whose records fail keeps its old ones.
type Syncer struct {
	Client   *Client
	Store    *store.Store
	Zones    []string // names or IDs to sync; empty = all
	Security bool
	Interval time.Duration
	Now      func() time.Time
	Log      *slog.Logger
	// Surface: also read zone settings and certificates, check CNAME
	// targets outside the zones and log changes (surfacesync.go).
	Surface  bool
	Resolver Resolver // for the CNAME checks; nil = net.DefaultResolver
	Edge     *Edge    // Cloudflare's edge, never a web offender; nil = the built-in list
}

func (s *Syncer) Name() string         { return "cloudflare:zones" }
func (s *Syncer) Every() time.Duration { return s.Interval }

// Wanted keeps the zones the config asks for (all if it names none).
func Wanted(zs []Zone, want []string) []Zone {
	if len(want) == 0 {
		return zs
	}
	var out []Zone
	for _, z := range zs {
		if slices.Contains(want, z.ID) || slices.Contains(want, strings.ToLower(z.Name)) {
			out = append(out, z)
		}
	}
	return out
}

func (s *Syncer) Sync(ctx context.Context) error {
	err := s.sync(ctx)
	if rerr := s.Store.RecordCloudflareSync(ctx, "zones", err, s.Now()); err == nil {
		err = rerr
	}
	return err
}

func (s *Syncer) sync(ctx context.Context) error {
	all, err := s.Client.Zones(ctx)
	if err != nil {
		return fmt.Errorf("listing zones: %w", err)
	}
	zs := Wanted(all, s.Zones)
	var errs []error
	stored := make([]store.CloudflareZone, 0, len(zs))
	records := map[string][]store.CloudflareRecord{}
	for _, z := range zs {
		if !zoneIDRe(z.ID) {
			continue
		}
		stored = append(stored, store.CloudflareZone{ID: z.ID, Name: z.Name, Plan: z.Plan.Name, Status: z.Status})
		rs, err := s.Client.DNSRecords(ctx, z.ID)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s DNS records: %w", z.Name, err))
			continue
		}
		out := make([]store.CloudflareRecord, 0, len(rs))
		for _, r := range rs {
			out = append(out, store.CloudflareRecord{Name: r.Name, Type: r.Type, Content: r.Content, Proxied: r.Proxied, TTL: r.TTL})
		}
		records[z.ID] = out
	}
	var before *surfaceBefore
	if s.Surface {
		if before, err = s.surfaceBefore(ctx); err != nil {
			return err
		}
	}
	if err := s.Store.ReplaceCloudflareZones(ctx, stored, records, s.Now()); err != nil {
		return err
	}
	if s.Surface {
		errs = append(errs, s.surface(ctx, stored, records, before)...)
	}
	if s.Security {
		var web []webZone
		for _, z := range stored {
			state, note, sum, days, err := s.Client.Security(ctx, z.ID, s.Now())
			if err != nil && state != store.CloudflareSecurityPermission {
				errs = append(errs, fmt.Errorf("%s security events: %w", z.Name, err))
			}
			last24, _ := json.Marshal(sum)
			if err := s.Store.SetCloudflareSecurity(ctx, z.ID, state, note, last24, days, s.Now()); err != nil {
				return err
			}
			web = append(web, webZone{z, state})
		}
		errs = append(errs, s.syncWeb(ctx, web)...)
	}
	if s.Log != nil {
		s.Log.Debug("Cloudflare synced", "zones", len(stored), "visible", len(all))
	}
	return errors.Join(errs...)
}
