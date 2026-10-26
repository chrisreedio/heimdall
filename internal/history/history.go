// SPDX-License-Identifier: AGPL-3.0-or-later

// Package history compares snapshots over time (what changed on a host)
// and across hosts (drift between hosts that should match).
package history

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/realmwatch/heimdall/internal/findings"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/version"
)

// Change is one package difference between two snapshots.
type Change struct {
	Name, Arch string
	From, To   string // "" when added (From) or removed (To)
}

// Diff is what changed on a host between two snapshots.
type Diff struct {
	Added, Removed, Upgraded, Downgraded []Change
}

func (d Diff) Empty() bool {
	return len(d.Added)+len(d.Removed)+len(d.Upgraded)+len(d.Downgraded) == 0
}

// Compare diffs two package lists. Versions compare with the host's scheme;
// with an unknown scheme any version change counts as an upgrade.
func Compare(scheme version.Scheme, from, to []store.InventoryPackage) Diff {
	type key struct{ name, arch string }
	index := func(ps []store.InventoryPackage) map[key][]string {
		m := map[key][]string{}
		for _, p := range ps {
			k := key{p.Name, p.Arch}
			m[k] = append(m[k], p.Version)
		}
		return m
	}
	a, b := index(from), index(to)
	var d Diff
	for k, olds := range a {
		news, ok := b[k]
		if !ok {
			for _, v := range olds {
				d.Removed = append(d.Removed, Change{Name: k.name, Arch: k.arch, From: v})
			}
			continue
		}
		// Multi-version packages (e.g. kernels): compare the newest of each.
		oldV, newV := newest(scheme, olds), newest(scheme, news)
		if oldV == newV {
			continue
		}
		c := Change{Name: k.name, Arch: k.arch, From: oldV, To: newV}
		if cmpVersions(scheme, newV, oldV) < 0 {
			d.Downgraded = append(d.Downgraded, c)
		} else {
			d.Upgraded = append(d.Upgraded, c)
		}
	}
	for k, news := range b {
		if _, ok := a[k]; !ok {
			for _, v := range news {
				d.Added = append(d.Added, Change{Name: k.name, Arch: k.arch, To: v})
			}
		}
	}
	for _, l := range []*[]Change{&d.Added, &d.Removed, &d.Upgraded, &d.Downgraded} {
		slices.SortFunc(*l, func(x, y Change) int { return cmp.Or(strings.Compare(x.Name, y.Name), strings.Compare(x.Arch, y.Arch)) })
	}
	return d
}

func newest(s version.Scheme, vs []string) string {
	best := vs[0]
	for _, v := range vs[1:] {
		if cmpVersions(s, v, best) > 0 {
			best = v
		}
	}
	return best
}

func cmpVersions(s version.Scheme, a, b string) int {
	if c, err := version.Compare(s, a, b); err == nil {
		return c
	}
	return strings.Compare(a, b)
}

// HostDiff diffs two of a host's snapshots (or, with fromID/toID 0, its
// two newest).
func HostDiff(ctx context.Context, st *store.Store, host store.IngestHost, fromID, toID int64) (from, to store.SnapshotInfo, d Diff, err error) {
	snaps, err := st.Snapshots(ctx, host.ID, 500)
	if err != nil {
		return
	}
	find := func(id int64) (store.SnapshotInfo, bool) {
		for _, s := range snaps {
			if s.ID == id {
				return s, true
			}
		}
		return store.SnapshotInfo{}, false
	}
	switch {
	case fromID == 0 && toID == 0:
		if len(snaps) < 2 {
			err = store.ErrNotFound
			return
		}
		to, from = snaps[0], snaps[1]
	default:
		var ok1, ok2 bool
		from, ok1 = find(fromID)
		to, ok2 = find(toID)
		if !ok1 || !ok2 {
			err = store.ErrNotFound
			return
		}
	}
	a, err := st.SnapshotPackages(ctx, host.ID, from.ID)
	if err != nil {
		return
	}
	b, err := st.SnapshotPackages(ctx, host.ID, to.ID)
	if err != nil {
		return
	}
	inv, err := st.Inventory(ctx, host)
	if err != nil {
		return
	}
	scheme := version.Scheme("")
	if info, ok := findings.HostEcosystem(inv); ok {
		scheme = info.Scheme
	}
	return from, to, Compare(scheme, a, b), nil
}

// DriftRow is one package whose presence or version differs across hosts.
type DriftRow struct {
	Name     string
	Versions map[string]string // host label ("org/host") → version; missing = not installed
	Missing  int               // hosts without it
}

// Drift compares the latest packages of hosts sharing a tag (within scope).
// Only packages that differ are returned, most-divergent first.
func Drift(ctx context.Context, st *store.Store, tag string, sc store.Scope) (hosts []string, rows []DriftRow, err error) {
	all, err := st.HostsTagged(ctx, tag)
	if err != nil {
		return nil, nil, err
	}
	pkgs := map[string]map[string]string{} // package → host → version
	for _, h := range all {
		if !sc.CanView(h.OrgID) {
			continue
		}
		inv, err := st.Inventory(ctx, h)
		if err != nil {
			return nil, nil, err
		}
		label := h.OrgSlug + "/" + h.Name
		hosts = append(hosts, label)
		for _, p := range inv.Packages {
			if pkgs[p.Name] == nil {
				pkgs[p.Name] = map[string]string{}
			}
			pkgs[p.Name][label] = p.Version
		}
	}
	for _, name := range slices.Sorted(maps.Keys(pkgs)) {
		vs := pkgs[name]
		distinct := map[string]bool{}
		for _, v := range vs {
			distinct[v] = true
		}
		if len(vs) == len(hosts) && len(distinct) == 1 {
			continue // identical everywhere
		}
		rows = append(rows, DriftRow{Name: name, Versions: vs, Missing: len(hosts) - len(vs)})
	}
	slices.SortStableFunc(rows, func(a, b DriftRow) int { return b.Missing - a.Missing })
	return hosts, rows, nil
}
