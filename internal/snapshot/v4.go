// SPDX-License-Identifier: AGPL-3.0-or-later

package snapshot

import "fmt"

// FormatV4 adds each site's npm packages (sites[].npm_packages), read
// from the app root's package-lock.json, with npm's dev flag.
const FormatV4 = "heimdall.snapshot/v4"

// MaxNpmPackages caps one site's npm packages, like a lockfile's.
const MaxNpmPackages = MaxLockfilePackages

// NpmPackage is one entry from a site's package-lock.json (v4). The same
// name can appear at several versions (nested node_modules), so name and
// version together are unique.
type NpmPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Dev: every copy of this name and version is marked "dev": true, so
	// it's only needed to build or test the app, not to run it.
	Dev bool `json:"dev"`
}

// atLeastV3 reports whether the (accepted) format carries the v3 lists.
func atLeastV3(format string) bool { return format == FormatV3 || format == FormatV4 }

// validateNpm checks one site's npm packages: only v4 may carry them.
func validateNpm(s *Snapshot, f string, site Site, bad func(field, format string, a ...any)) {
	if s.Format != FormatV4 {
		if site.NpmPackages != nil {
			bad(f+".npm_packages", "not allowed in %s", s.Format)
		}
		return
	}
	if len(site.NpmPackages) > 0 && !site.Readable {
		bad(f, "npm data present but readable is false")
	}
	if len(site.NpmPackages) > MaxNpmPackages {
		bad(f+".npm_packages", "too many (%d > %d)", len(site.NpmPackages), MaxNpmPackages)
		return
	}
	seen := make(map[[2]string]bool, len(site.NpmPackages))
	for j, p := range site.NpmPackages {
		pf := fmt.Sprintf("%s.npm_packages[%d]", f, j)
		if !npmNameRe.MatchString(p.Name) || !appVersionRe.MatchString(p.Version) {
			bad(pf, "invalid package %s %s", quote(p.Name), quote(p.Version))
			continue
		}
		if k := [2]string{p.Name, p.Version}; seen[k] {
			bad(pf, "duplicate package %s %s", quote(p.Name), quote(p.Version))
		} else {
			seen[k] = true
		}
	}
}
