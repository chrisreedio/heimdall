// SPDX-License-Identifier: AGPL-3.0-or-later

// Package findings turns host inventories into vulnerability findings using
// OSV, and runs feed sync (OSV, KEV, endoflife.date).
package findings

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/realmwatch/heimdall/internal/cvss"
	"github.com/realmwatch/heimdall/internal/ecosystem"
	"github.com/realmwatch/heimdall/internal/feeds/osv"
	"github.com/realmwatch/heimdall/internal/snapshot"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/version"
)

// Bounds on what one advisory may contribute, since records are remote input.
const (
	maxAliases = 50
	maxRanges  = 2000
)

type Engine struct {
	Store  *store.Store
	OSV    *osv.Client
	Now    func() time.Time
	Log    *slog.Logger
	MaxAge time.Duration // how long cached OSV query results stay fresh
	// Concurrency for advisory fetches.
	Concurrency int
}

type HostResult struct {
	Host      store.IngestHost
	Ecosystem string // "" if the OS isn't supported
	Findings  int
	Added     int
	Resolved  int
}

// EvaluateHost recomputes a host's findings from its latest snapshot: OS
// packages against the distro's OSV ecosystem, each site's Composer
// packages against Packagist and its npm packages against npm, and
// allowlisted lockfiles against theirs.
func (e *Engine) EvaluateHost(ctx context.Context, host store.IngestHost) (HostResult, error) {
	res := HostResult{Host: host}
	inv, err := e.Store.Inventory(ctx, host)
	if errors.Is(err, store.ErrNotFound) {
		return res, nil
	}
	if err != nil {
		return res, err
	}

	targets := map[target]*targetInfo{}
	if info, ok := HostEcosystem(inv); ok {
		res.Ecosystem = info.OSV
		addOSTargets(targets, info, inv.Packages)
	} else {
		e.Log.Info("findings: OS packages not supported, skipping them", "host", host.Name, "os", inv.OSID, "version", inv.OSVersion)
	}
	addSiteTargets(targets, inv.Sites)
	addLockfileTargets(targets, inv.Lockfiles)
	if len(targets) == 0 {
		return res, nil
	}

	order := slices.SortedFunc(maps.Keys(targets), func(a, b target) int {
		return strings.Compare(a.site+"\x00"+a.key.Ecosystem+"\x00"+a.key.Name+"\x00"+a.key.Version,
			b.site+"\x00"+b.key.Ecosystem+"\x00"+b.key.Name+"\x00"+b.key.Version)
	})
	keySet := map[store.OSVKey]bool{}
	for _, t := range order {
		keySet[t.key] = true
	}
	ids, err := e.lookup(ctx, slices.SortedFunc(maps.Keys(keySet), func(a, b store.OSVKey) int {
		return strings.Compare(a.Ecosystem+"\x00"+a.Name+"\x00"+a.Version, b.Ecosystem+"\x00"+b.Name+"\x00"+b.Version)
	}))
	if err != nil {
		return res, err
	}

	var fs []store.Finding
	// One finding per site, advisory and package (the store's key), though
	// npm can install a package at several versions: the oldest version
	// stands for them all, and it's dev only if every copy is.
	seen := map[[3]string]int{}
	for _, t := range order {
		ti := targets[t]
		for _, id := range ids[t.key] {
			fixedList, err := e.Store.FixedVersions(ctx, id, t.key.Ecosystem, t.key.Name)
			if err != nil {
				return res, err
			}
			fixed := pickFixed(ti.scheme, t.key.Version, fixedList)
			pending := false
			if fixed != "" {
				for _, pv := range ti.pending {
					if compare(ti.scheme, pv, fixed) >= 0 {
						pending = true
					}
				}
			}
			f := store.Finding{
				AdvisoryID: id, Ecosystem: t.key.Ecosystem, Package: t.key.Name, Version: t.key.Version,
				Binaries: ti.binaries, FixedVersion: fixed, FixPending: pending, SiteRoot: t.site, Dev: ti.dev,
			}
			k := [3]string{t.site, id, t.key.Name}
			i, dup := seen[k]
			if !dup {
				seen[k] = len(fs)
				fs = append(fs, f)
				continue
			}
			f.Dev = f.Dev && fs[i].Dev
			if compare(ti.scheme, f.Version, fs[i].Version) < 0 {
				fs[i] = f
			}
			fs[i].Dev = f.Dev
		}
	}
	res.Findings = len(fs)
	res.Added, res.Resolved, err = e.Store.SetFindings(ctx, host.ID, fs, e.Now())
	return res, err
}

// target is one OSV query owned by the OS (site == "") or by a site.
type target struct {
	site string
	key  store.OSVKey
}

type targetInfo struct {
	scheme   version.Scheme
	binaries []string // installed packages the target covers (OS: binaries of a source package)
	pending  []string // versions pending updates would install
	dev      bool     // npm: a dev dependency, needed only to build or test the site
}

// addOSTargets adds one target per source package and version.
func addOSTargets(targets map[target]*targetInfo, info ecosystem.Info, pkgs []store.InventoryPackage) {
	for _, p := range pkgs {
		name, ver := ecosystem.QueryFor(info, snapshot.Package{
			Name: p.Name, Version: p.Version, Arch: p.Arch, SourceName: p.SourceName, SourceVersion: p.SourceVersion,
		})
		if name == "" || ver == "" {
			continue
		}
		t := target{key: store.OSVKey{Ecosystem: info.OSV, Name: name, Version: ver}}
		ti := targets[t]
		if ti == nil {
			ti = &targetInfo{scheme: info.Scheme}
			targets[t] = ti
		}
		if !slices.Contains(ti.binaries, p.Name) {
			ti.binaries = append(ti.binaries, p.Name)
		}
		if p.PendingVersion != "" {
			ti.pending = append(ti.pending, p.PendingVersion)
		}
	}
}

// addLockfileTargets adds npm and PyPI packages from allowlisted lockfiles;
// their findings are keyed by the lockfile path. Fix-version selection uses
// the semver-style Composer comparison, which is close enough for picking
// the lowest fix (OSV itself decides what's affected).
func addLockfileTargets(targets map[target]*targetInfo, files []store.InventoryLockfile) {
	for _, f := range files {
		for _, p := range f.Packages {
			t := target{site: f.Path, key: store.OSVKey{Ecosystem: f.Ecosystem, Name: p.Name, Version: p.Version}}
			if targets[t] == nil {
				targets[t] = &targetInfo{scheme: version.Composer, binaries: []string{p.Name}}
			}
		}
	}
}

// OSV's ecosystems for Composer and npm packages.
const (
	PackagistEcosystem = "Packagist"
	NpmEcosystem       = "npm"
)

// addSiteTargets adds each site's Composer packages (dev branches can't be
// matched against version ranges, so they're skipped) and npm packages,
// keyed by the site's root so their findings belong to the site. Fix
// selection for npm uses the Composer comparison, as for lockfiles.
func addSiteTargets(targets map[target]*targetInfo, sites []store.InventorySite) {
	for _, site := range sites {
		for _, p := range site.Packages {
			if strings.HasPrefix(p.Version, "dev-") {
				continue
			}
			t := target{site: site.Root, key: store.OSVKey{Ecosystem: PackagistEcosystem, Name: p.Name, Version: p.Version}}
			if targets[t] == nil {
				targets[t] = &targetInfo{scheme: version.Composer, binaries: []string{p.Name}}
			}
		}
		for _, p := range site.NpmPackages {
			t := target{site: site.Root, key: store.OSVKey{Ecosystem: NpmEcosystem, Name: p.Name, Version: p.Version}}
			if targets[t] == nil {
				targets[t] = &targetInfo{scheme: version.Composer, binaries: []string{p.Name}, dev: p.Dev}
			}
		}
	}
}

// EvaluateAll recomputes findings for every host that has reported.
func (e *Engine) EvaluateAll(ctx context.Context) ([]HostResult, error) {
	hosts, err := e.Store.HostsWithSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	var out []HostResult
	var errs []error
	for _, h := range hosts {
		r, err := e.EvaluateHost(ctx, h)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s/%s: %w", h.OrgSlug, h.Name, err))
			continue
		}
		out = append(out, r)
	}
	return out, errors.Join(errs...)
}

// lookup returns advisory IDs per query, using the cache where fresh and
// querying OSV for the rest, then makes sure every advisory is stored.
func (e *Engine) lookup(ctx context.Context, keys []store.OSVKey) (map[store.OSVKey][]string, error) {
	now := e.Now()
	ids, err := e.Store.OSVCached(ctx, keys, now.Add(-e.MaxAge))
	if err != nil {
		return nil, err
	}
	var stale []store.OSVKey
	for _, k := range keys {
		if _, ok := ids[k]; !ok {
			stale = append(stale, k)
		}
	}

	modified := map[string]time.Time{} // OSV's modified time, for refetching
	if len(stale) > 0 {
		qs := make([]osv.Query, len(stale))
		for i, k := range stale {
			qs[i] = osv.Query{Ecosystem: k.Ecosystem, Name: k.Name, Version: k.Version}
		}
		refs, err := e.OSV.QueryBatch(ctx, qs)
		if err != nil {
			return nil, fmt.Errorf("osv query: %w", err)
		}
		fresh := make(map[store.OSVKey][]string, len(stale))
		for i, k := range stale {
			list := []string{}
			for _, r := range refs[i] {
				list = append(list, r.ID)
				if r.Modified.After(modified[r.ID]) {
					modified[r.ID] = r.Modified
				}
			}
			fresh[k], ids[k] = list, list
		}
		if err := e.Store.PutOSVResults(ctx, fresh, now); err != nil {
			return nil, err
		}
	}

	all := map[string]bool{}
	for _, list := range ids {
		for _, id := range list {
			all[id] = true
		}
	}
	if err := e.ensureAdvisories(ctx, slices.Sorted(maps.Keys(all)), modified); err != nil {
		return nil, err
	}
	return ids, nil
}

// ensureAdvisories fetches advisories that are missing or have changed.
func (e *Engine) ensureAdvisories(ctx context.Context, ids []string, modified map[string]time.Time) error {
	known, err := e.Store.AdvisoryModified(ctx, ids)
	if err != nil {
		return err
	}
	var need []string
	for _, id := range ids {
		have, ok := known[id]
		if !ok || modified[id].After(have) {
			need = append(need, id)
		}
	}
	if len(need) == 0 {
		return nil
	}
	e.Log.Info("findings: fetching advisories", "count", len(need))

	workers := max(1, e.Concurrency)
	jobs := make(chan string)
	var mu sync.Mutex
	var errs []error
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				if err := e.fetchAdvisory(ctx, id); err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("%s: %w", id, err))
					mu.Unlock()
				}
			}
		}()
	}
	// A first run can be thousands of advisories: report progress.
	for i, id := range need {
		select {
		case jobs <- id:
		case <-ctx.Done():
		}
		if n := i + 1; n%1000 == 0 && n < len(need) {
			e.Log.Info("findings: fetching advisories", "done", n, "of", len(need))
		}
	}
	close(jobs)
	wg.Wait()
	if len(errs) > 0 {
		return fmt.Errorf("fetching %d of %d advisories failed: %w", len(errs), len(need), errors.Join(errs[:min(len(errs), 5)]...))
	}
	return ctx.Err()
}

func (e *Engine) fetchAdvisory(ctx context.Context, id string) error {
	v, raw, err := e.OSV.Vuln(ctx, id)
	if err != nil {
		return err
	}
	// Ranges and ratings come from the full record; only the stored copy
	// is slimmed. Vuln has parsed raw, so Slim can't fail on it.
	if slim, err := osv.Slim(raw); err == nil {
		raw = slim
	}
	return e.Store.PutAdvisory(ctx, toAdvisory(v, raw))
}

func toAdvisory(v *osv.Vuln, raw []byte) store.Advisory {
	a := store.Advisory{
		ID: v.ID, Modified: v.Modified, Published: v.Published, Withdrawn: v.Withdrawn,
		Summary: summarize(v), Raw: raw,
	}
	// Distro records keep their CVE under upstream/related rather than
	// aliases; store both so KEV and CVE lookups work for every source.
	for _, alias := range slices.Concat(v.CVEs(), v.Aliases) {
		if len(a.Aliases) < maxAliases && alias != v.ID && !slices.Contains(a.Aliases, alias) {
			a.Aliases = append(a.Aliases, alias)
		}
	}

	var best float64
	for _, s := range v.Severity {
		if !strings.HasPrefix(s.Type, "CVSS_V3") {
			continue
		}
		if score, err := cvss.Score(s.Score); err == nil && score > best {
			best = score
		}
	}
	a.CVSS = best
	a.Severity = v.DistroRating()
	if a.Severity == "" && best > 0 {
		if r := cvss.Rating(best); r != "none" {
			a.Severity = r
		}
	}

	for _, aff := range v.Affected {
		for _, rg := range aff.Ranges {
			introduced := ""
			for _, ev := range rg.Events {
				if len(a.Ranges) >= maxRanges {
					return a
				}
				switch {
				case ev.Introduced != "":
					introduced = ev.Introduced
				case ev.Fixed != "":
					a.Ranges = append(a.Ranges, store.AffectedRange{Ecosystem: aff.Package.Ecosystem,
						Package: aff.Package.Name, Introduced: introduced, Fixed: ev.Fixed})
				case ev.LastAffected != "":
					a.Ranges = append(a.Ranges, store.AffectedRange{Ecosystem: aff.Package.Ecosystem,
						Package: aff.Package.Name, Introduced: introduced, LastAffected: ev.LastAffected})
				}
			}
		}
	}
	return a
}

func summarize(v *osv.Vuln) string {
	s := v.Summary
	if s == "" {
		s = v.Details
	}
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "…"
	}
	return s
}

// pickFixed returns the lowest fixed version newer than installed, or "".
func pickFixed(s version.Scheme, installed string, fixed []string) string {
	best := ""
	for _, f := range fixed {
		if compare(s, installed, f) >= 0 {
			continue
		}
		if best == "" || compare(s, f, best) < 0 {
			best = f
		}
	}
	return best
}

// compare handles rpm advisories that omit the epoch the installed package
// carries ("3.0.7-27.el9" vs "1:3.0.7-24.el9"): an epoch-less fixed version
// is compared against the installed version without its epoch.
func compare(s version.Scheme, a, b string) int {
	if s == version.RPM && strings.Contains(a, ":") != strings.Contains(b, ":") {
		a, b = stripEpoch(a), stripEpoch(b)
	}
	c, _ := version.Compare(s, a, b)
	return c
}

func stripEpoch(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		return v[i+1:]
	}
	return v
}

// HostEcosystem resolves the OSV ecosystem for a host's latest snapshot.
func HostEcosystem(inv store.HostInventory) (ecosystem.Info, bool) {
	pm := inv.PackageManager
	if pm == "" {
		pm = inferPackageManager(inv.OSID, inv.OSIDLike)
	}
	return ecosystem.Resolve(inv.OSID, inv.OSVersion, inv.OSIDLike, pm)
}

// inferPackageManager covers snapshots stored before M2 recorded it.
func inferPackageManager(osID, idLike string) string {
	for _, id := range append([]string{osID}, strings.Fields(idLike)...) {
		switch id {
		case "debian", "ubuntu":
			return "dpkg"
		case "rhel", "centos", "fedora", "rocky", "almalinux":
			return "rpm"
		case "alpine":
			return "apk"
		}
	}
	return ""
}
