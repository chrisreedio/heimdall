// SPDX-License-Identifier: AGPL-3.0-or-later

package snapshot

import (
	"fmt"
	"regexp"
)

// FormatV3 adds containers and allowlisted application lockfiles.
const FormatV3 = "heimdall.snapshot/v3"

const (
	MaxContainers       = 500
	MaxLockfiles        = 50
	MaxLockfilePackages = 5000
)

// Container is a Docker/Podman container on the host (v3).
type Container struct {
	Name   string `json:"name"`
	Image  string `json:"image"`  // repository, e.g. "nginx" or "ghcr.io/acme/app"
	Tag    string `json:"tag"`    // e.g. "1.27", "" if unknown
	Digest string `json:"digest"` // sha256:…, "" if unknown
	State  string `json:"state"`  // running, exited, …
}

// Lockfile is an allowlisted application manifest (v3): npm or PyPI.
type Lockfile struct {
	Path      string            `json:"path"`
	Ecosystem string            `json:"ecosystem"` // "npm" or "PyPI" (OSV names)
	Packages  []ComposerPackage `json:"packages"`  // name + version
}

var (
	LockfileEcosystems = []string{"npm", "PyPI"}
	containerNameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	imageRe            = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}$`)
	tagRe              = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	digestRe           = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	stateRe            = regexp.MustCompile(`^[a-z]{0,20}$`)
	npmNameRe          = regexp.MustCompile(`^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]{0,213}$`)
	pypiNameRe         = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$`)
	appVersionRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+!-]{0,99}$`)
)

// validateV3 checks containers and lockfiles, which only v3 may carry.
func validateV3(s *Snapshot, unavailable map[string]bool, bad func(field, format string, a ...any)) {
	if s.Format != FormatV3 {
		if s.Containers != nil {
			bad("containers", "not allowed in %s", s.Format)
		}
		if s.Lockfiles != nil {
			bad("lockfiles", "not allowed in %s", s.Format)
		}
		for _, c := range []string{"containers", "lockfiles"} {
			if unavailable[c] {
				bad("unavailable", "%q is not a %s check", c, s.Format)
			}
		}
		return
	}
	switch {
	case unavailable["containers"] && len(s.Containers) > 0:
		bad("containers", "must be empty when listed in unavailable")
	case !unavailable["containers"] && s.Containers == nil:
		bad("containers", "required in %s (use [] for none, or list \"containers\" as unavailable)", FormatV3)
	case len(s.Containers) > MaxContainers:
		bad("containers", "too many (%d > %d)", len(s.Containers), MaxContainers)
	default:
		names := map[string]bool{}
		for i, c := range s.Containers {
			f := fmt.Sprintf("containers[%d]", i)
			if !containerNameRe.MatchString(c.Name) || names[c.Name] {
				bad(f+".name", "invalid or duplicate %s", quote(c.Name))
			}
			names[c.Name] = true
			if !imageRe.MatchString(c.Image) {
				bad(f+".image", "invalid value %s", quote(c.Image))
			}
			if c.Tag != "" && !tagRe.MatchString(c.Tag) {
				bad(f+".tag", "invalid value %s", quote(c.Tag))
			}
			if c.Digest != "" && !digestRe.MatchString(c.Digest) {
				bad(f+".digest", "invalid value %s", quote(c.Digest))
			}
			if !stateRe.MatchString(c.State) {
				bad(f+".state", "invalid value %s", quote(c.State))
			}
		}
	}

	switch {
	case unavailable["lockfiles"] && len(s.Lockfiles) > 0:
		bad("lockfiles", "must be empty when listed in unavailable")
	case !unavailable["lockfiles"] && s.Lockfiles == nil:
		bad("lockfiles", "required in %s (use [] for none)", FormatV3)
	case len(s.Lockfiles) > MaxLockfiles:
		bad("lockfiles", "too many (%d > %d)", len(s.Lockfiles), MaxLockfiles)
	default:
		paths := map[string]bool{}
		for i, l := range s.Lockfiles {
			f := fmt.Sprintf("lockfiles[%d]", i)
			if !validSitePath(l.Path) || paths[l.Path] {
				bad(f+".path", "invalid or duplicate path %s", quote(l.Path))
			}
			paths[l.Path] = true
			nameRe := npmNameRe
			switch l.Ecosystem {
			case "npm":
			case "PyPI":
				nameRe = pypiNameRe
			default:
				bad(f+".ecosystem", "must be npm or PyPI, got %s", quote(l.Ecosystem))
				continue
			}
			if len(l.Packages) > MaxLockfilePackages {
				bad(f+".packages", "too many (%d > %d)", len(l.Packages), MaxLockfilePackages)
				continue
			}
			for j, p := range l.Packages {
				if !nameRe.MatchString(p.Name) || !appVersionRe.MatchString(p.Version) {
					bad(fmt.Sprintf("%s.packages[%d]", f, j), "invalid package %s %s", quote(p.Name), quote(p.Version))
				}
			}
		}
	}
}
