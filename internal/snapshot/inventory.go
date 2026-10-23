// SPDX-License-Identifier: AGPL-3.0-or-later

package snapshot

import (
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// inventoryScheme versions InventoryHash. Changing what the hash covers
// means a new scheme, so old and new hashes never compare equal by accident.
const inventoryScheme = "heimdall.inventory/v1\n"

// InventoryHash is a canonical hash of what the host has, ignoring the
// fields that change on every run even when nothing else does:
//
//   - collected_at: a timestamp, different on every run by definition.
//   - uptime_seconds: grows on every run. Reboots are still detected from
//     the uptime kept with each heartbeat.
//
// Everything else counts as inventory, including reboot_required (it only
// flips around upgrades and reboots, and the UI, findings and reports read
// it from the snapshot), the unavailable list (a check that starts failing
// is a change worth keeping), the collector's version and checksum (so a
// swapped collector is always a new snapshot for the "collector changed"
// rule), the format, and container state.
//
// Lists are sorted first, so the order a package manager happens to print
// in doesn't matter.
func (s *Snapshot) InventoryHash() [32]byte {
	c := *s
	c.CollectedAt = time.Time{}
	c.UptimeSeconds = 0

	c.Packages = sortedBy(s.Packages, func(a, b Package) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Arch, b.Arch),
			strings.Compare(a.Version, b.Version), strings.Compare(a.SourceName, b.SourceName),
			strings.Compare(a.SourceVersion, b.SourceVersion))
	})
	c.Updates = sortedBy(s.Updates, func(a, b Update) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Arch, b.Arch), strings.Compare(a.Version, b.Version))
	})
	c.Unavailable = sortedBy(s.Unavailable, strings.Compare)
	c.Containers = sortedBy(s.Containers, func(a, b Container) int { return strings.Compare(a.Name, b.Name) })

	c.Sites = sortedBy(s.Sites, func(a, b Site) int { return strings.Compare(a.Root, b.Root) })
	for i := range c.Sites {
		c.Sites[i].ServerNames = sortedBy(c.Sites[i].ServerNames, strings.Compare)
		c.Sites[i].ComposerPackages = sortedBy(c.Sites[i].ComposerPackages, comparePackage)
		if t := c.Sites[i].DeployedAt; t != nil {
			u := t.UTC()
			c.Sites[i].DeployedAt = &u
		}
	}
	c.Lockfiles = sortedBy(s.Lockfiles, func(a, b Lockfile) int {
		return cmp.Or(strings.Compare(a.Path, b.Path), strings.Compare(a.Ecosystem, b.Ecosystem))
	})
	for i := range c.Lockfiles {
		c.Lockfiles[i].Packages = sortedBy(c.Lockfiles[i].Packages, comparePackage)
	}

	b, err := json.Marshal(&c)
	if err != nil { // can't happen for this type; never let it compare equal
		return sha256.Sum256([]byte(err.Error()))
	}
	return sha256.Sum256(append([]byte(inventoryScheme), b...))
}

func comparePackage(a, b ComposerPackage) int {
	return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Version, b.Version))
}

// sortedBy returns a sorted copy (nil stays nil, so v1/v2 documents hash
// the same as before they were sorted).
func sortedBy[T any](s []T, f func(a, b T) int) []T {
	if s == nil {
		return nil
	}
	out := slices.Clone(s)
	slices.SortStableFunc(out, f)
	return out
}
