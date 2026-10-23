// SPDX-License-Identifier: AGPL-3.0-or-later

package findings

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/ecosystem"
	"github.com/chrisreedio/heimdall/internal/feeds/eol"
	"github.com/chrisreedio/heimdall/internal/feeds/epss"
	"github.com/chrisreedio/heimdall/internal/feeds/kev"
	"github.com/chrisreedio/heimdall/internal/netx"
	"github.com/chrisreedio/heimdall/internal/snapshot"
	"github.com/chrisreedio/heimdall/internal/store"
)

// Syncer refreshes every enabled feed and recomputes findings.
type Syncer struct {
	Store  *store.Store
	HTTP   *netx.Client
	Engine *Engine
	EOL    *eol.Client
	EPSS   *epss.Client
	KEVURL string // kev.DefaultURL if empty
	Feeds  config.Feeds
	Now    func() time.Time
	Log    *slog.Logger
	// Retention is applied by serve after each scheduled sync.
	Retention struct {
		For time.Duration
		Min int
	}
}

// Run syncs KEV, endoflife.date and OSV in turn. A failing feed doesn't
// stop the others; all errors are returned together.
func (s *Syncer) Run(ctx context.Context) error {
	var errs []error
	run := func(feed string, enabled bool, fn func(context.Context) error) {
		if !enabled {
			return
		}
		start := s.Now()
		err := fn(ctx)
		if recErr := s.Store.RecordFeedRun(ctx, feed, start, err); recErr != nil {
			err = errors.Join(err, recErr)
		}
		if err != nil {
			s.Log.Warn("feed sync failed", "feed", feed, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", feed, err))
			return
		}
		s.Log.Info("feed synced", "feed", feed, "took", s.Now().Sub(start).Round(time.Millisecond))
	}
	run("kev", s.Feeds.KEV, s.syncKEV)
	run("endoflife", s.Feeds.EndOfLife, s.syncEOL)
	run("osv", s.Feeds.OSV, s.syncOSV)
	// EPSS scores the CVEs behind open findings, so it runs after OSV.
	run("epss", s.Feeds.EPSS && s.EPSS != nil, s.syncEPSS)
	return errors.Join(errs...)
}

func (s *Syncer) syncKEV(ctx context.Context) error {
	cat, err := kev.Fetch(ctx, s.HTTP, s.KEVURL)
	if err != nil {
		return err
	}
	entries := make([]store.KEVEntry, len(cat.Entries))
	for i, e := range cat.Entries {
		entries[i] = store.KEVEntry{CVE: e.CVE, Vendor: e.Vendor, Product: e.Product,
			DateAdded: e.DateAdded, DueDate: e.DueDate, KnownRansomware: e.KnownRansomware}
	}
	return s.Store.ReplaceKEV(ctx, entries)
}

// syncEOL fetches only the products the fleet actually runs.
func (s *Syncer) syncEOL(ctx context.Context) error {
	products, err := s.neededEOLProducts(ctx)
	if err != nil {
		return err
	}
	return s.fetchEOL(ctx, products)
}

// SyncMissingEOL fetches lifecycle data for products hosts run that have
// none yet, so a host's first report shows lifecycles without waiting for
// the next scheduled sync.
func (s *Syncer) SyncMissingEOL(ctx context.Context) error {
	products, err := s.neededEOLProducts(ctx)
	if err != nil {
		return err
	}
	var missing []string
	for _, p := range products {
		cycles, err := s.Store.EOLCycles(ctx, p)
		if err != nil {
			return err
		}
		if len(cycles) == 0 {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return s.fetchEOL(ctx, missing)
}

func (s *Syncer) fetchEOL(ctx context.Context, products []string) error {
	var errs []error
	for _, p := range products {
		cycles, err := s.EOL.Product(ctx, p)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			continue
		}
		rows := make([]store.EOLCycle, len(cycles))
		for i, c := range cycles {
			rows[i] = store.EOLCycle{Product: p, Cycle: c.Cycle, ReleaseDate: c.ReleaseDate,
				SupportUntil: c.SupportUntil, EOL: c.EOL, EOLReached: c.EOLReached, Latest: c.Latest}
		}
		if err := s.Store.ReplaceEOL(ctx, p, rows); err != nil {
			return err
		}
	}
	return errors.Join(errs...)
}

func (s *Syncer) neededEOLProducts(ctx context.Context) ([]string, error) {
	hosts, err := s.Store.HostsWithSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	need := map[string]bool{}
	for _, h := range hosts {
		inv, err := s.Store.Inventory(ctx, h)
		if err != nil {
			return nil, err
		}
		if p, _, ok := eol.OSCycle(inv.OSID, inv.OSVersion, inv.OSIDLike); ok {
			need[p] = true
		}
		for _, rt := range HostRuntimes(inv) {
			need[rt.Name] = true
		}
		for _, site := range inv.Sites {
			if site.PHPFPMVersion != "" {
				need[eol.ProductPHP] = true
			}
			if site.Framework == "laravel" {
				need[eol.ProductLaravel] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(need)), nil
}

func (s *Syncer) syncEPSS(ctx context.Context) error {
	cves, err := s.Store.OpenFindingCVEs(ctx)
	if err != nil || len(cves) == 0 {
		return err
	}
	scores, err := s.EPSS.Scores(ctx, cves)
	if err != nil {
		return err
	}
	rows := make([]store.EPSSScore, 0, len(scores))
	for _, sc := range scores {
		rows = append(rows, store.EPSSScore{CVE: sc.CVE, Score: sc.EPSS, Percentile: sc.Percentile, Date: sc.Date})
	}
	return s.Store.PutEPSS(ctx, rows)
}

func (s *Syncer) syncOSV(ctx context.Context) error {
	results, err := s.Engine.EvaluateAll(ctx)
	added, resolved := 0, 0
	for _, r := range results {
		added += r.Added
		resolved += r.Resolved
	}
	s.Log.Info("findings updated", "hosts", len(results), "new", added, "resolved", resolved)
	return err
}

// HostRuntimes derives language runtimes from a host's packages. The
// runtime names match endoflife.date product slugs (php, nodejs, python).
func HostRuntimes(inv store.HostInventory) []ecosystem.Runtime {
	pm := inv.PackageManager
	if pm == "" {
		pm = inferPackageManager(inv.OSID, inv.OSIDLike)
	}
	pkgs := make([]snapshot.Package, len(inv.Packages))
	for i, p := range inv.Packages {
		pkgs[i] = snapshot.Package{Name: p.Name, Version: p.Version, Arch: p.Arch,
			SourceName: p.SourceName, SourceVersion: p.SourceVersion}
	}
	return ecosystem.Runtimes(pm, pkgs)
}
