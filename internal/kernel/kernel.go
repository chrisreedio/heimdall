// SPDX-License-Identifier: AGPL-3.0-or-later

// Package kernel knows how each package manager ships Linux kernels, so
// patch commands can upgrade a kernel the way that actually installs the
// fix.
//
// Debian and Ubuntu ship each kernel ABI as new packages
// (linux-image-6.8.0-45-generic, then linux-image-6.8.0-47-generic), so
// upgrading the installed ABI-named packages does nothing: the fix arrives
// through a metapackage (linux-generic, linux-aws, linux-image-amd64…)
// that depends on the newest ABI. RPM kernels (kernel, kernel-core…) and
// Alpine's (linux-lts, linux-virt…) keep stable names, so upgrading them
// by name works. Every kernel fix needs a reboot to take effect.
package kernel

import (
	"regexp"
	"slices"
	"strings"

	"github.com/chrisreedio/heimdall/internal/version"
)

var (
	// abiName is a Debian/Ubuntu package named for one kernel ABI:
	// linux-image-6.8.0-45-generic, linux-aws-6.17-headers-6.17.0-1009,
	// linux-headers-6.1.0-18-common, linux-modules-nvidia-550-6.8.0-45-generic.
	abiName = regexp.MustCompile(`^linux-.*\d+\.\d+(\.\d+)?-\d+`)

	// metaName is a Debian/Ubuntu kernel metapackage: a flavour, optionally
	// with an image/headers/tools prefix and an hwe, lts, edge or series
	// suffix (linux-aws, linux-image-generic-hwe-24.04, linux-oem-24.04b,
	// linux-image-amd64, linux-headers-cloud-amd64).
	metaName = regexp.MustCompile(`^linux-(?:(?:image|headers|tools|cloud-tools|modules-extra|image-unsigned)-)?` +
		`(?:generic|virtual|lowlatency|aws|azure|azure-fde|gcp|gke|gkeop|oracle|kvm|ibm|nvidia|nvidia-lowlatency|raspi|oem|` +
		`amd64|arm64|i386|686|686-pae|armmp|armmp-lpae|cloud-amd64|cloud-arm64|rt-amd64|rt-arm64|powerpc64le|s390x)` +
		`(?:-(?:hwe|lts|edge|\d+\.\d+[a-z]?))*$`)

	// dpkgSource is a kernel source package (linux, linux-aws-6.17,
	// linux-hwe-6.8, linux-signed-generic…), for findings that carry no
	// binary package names.
	dpkgSource = regexp.MustCompile(`^linux(-[a-z0-9.+-]+)?$`)

	// apkKernel is one of Alpine's kernel flavours.
	apkKernel = regexp.MustCompile(`^linux-(lts|virt|edge|rpi|rpi2|rpi4|stable)$`)
)

// notKernelSources share the linux- prefix but aren't kernels.
var notKernelSources = []string{"linux-firmware", "linux-base", "linux-atm", "linux-ftpd", "linux-libc-dev", "linux-tools-common", "linux-cloud-tools-common", "linux-doc", "linux-sound-base"}

// userland are Debian/Ubuntu packages built from a kernel source that
// aren't a kernel: perf and its wrappers, the kernel headers libc builds
// against, docs and the source tarball. Advisories for the kernel source
// list them, but a kernel bug isn't live through them.
var userland = []string{"linux-tools-common", "linux-cloud-tools-common", "linux-libc-dev", "linux-doc", "linux-source", "linux-tools-host"}

// UserlandNames are Userland's exact names (it also takes linux-source-*).
func UserlandNames() []string { return slices.Clone(userland) }

// Userland reports whether name is one of those packages
// (linux-source-6.8.0 included).
func Userland(pm, name string) bool {
	return pm == "dpkg" && (slices.Contains(userland, name) || strings.HasPrefix(name, "linux-source-"))
}

// DpkgFullUpgrade is the fallback for a Debian/Ubuntu kernel fix on a host
// with no kernel metapackage to upgrade.
const DpkgFullUpgrade = "sudo apt-get update && sudo apt-get upgrade"

// ABIPackage reports whether name is a Debian/Ubuntu package named for
// one kernel ABI, which a newer kernel never upgrades in place.
func ABIPackage(pm, name string) bool {
	return pm == "dpkg" && abiName.MatchString(name)
}

// Package reports whether name (a binary package, or for dpkg a source
// package) is part of a kernel.
func Package(pm, name string) bool {
	switch pm {
	case "dpkg":
		if abiName.MatchString(name) || metaName.MatchString(name) {
			return true
		}
		return dpkgSource.MatchString(name) && !slices.Contains(notKernelSources, name) && !strings.HasPrefix(name, "linux-firmware")
	case "rpm":
		if name == "kernel" {
			return true
		}
		rest, ok := strings.CutPrefix(name, "kernel-")
		// Headers, tools, devel and docs don't change the running kernel.
		return ok && rest != "headers" && rest != "doc" && !strings.HasPrefix(rest, "tools") && !strings.HasPrefix(rest, "devel")
	case "apk":
		return apkKernel.MatchString(name)
	}
	return false
}

// Split sorts one finding's packages for an upgrade command: the names
// that upgrade by name, and whether the fix is a kernel update. Findings
// with no binary package names fall back to the source name, which for a
// Debian/Ubuntu kernel (linux-aws-6.17) is never installable itself.
func Split(pm string, binaries []string, source string, installed func(string) bool) (names []string, isKernel bool) {
	bins := binaries
	if len(bins) == 0 {
		if pm == "dpkg" && Package(pm, source) && !installed(source) {
			return nil, true
		}
		bins = []string{source}
	}
	for _, b := range bins {
		if ABIPackage(pm, b) {
			isKernel = true
			continue
		}
		if Package(pm, b) {
			isKernel = true
		}
		names = append(names, b)
	}
	return names, isKernel
}

// Metapackages returns the installed Debian/Ubuntu kernel metapackages,
// sorted: upgrading them pulls in the newest kernel ABI.
func Metapackages(pm string, installed []string) []string {
	if pm != "dpkg" {
		return nil
	}
	var out []string
	for _, n := range installed {
		if metaName.MatchString(n) && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// Installed is one installed package, as the inventory has it.
type Installed struct{ Name, Version, Arch string }

// Newest returns the release (as uname -r prints it) of the newest kernel
// installed, or "" if it can't be told from the package list.
func Newest(pm string, pkgs []Installed) string {
	var best, bestVer string
	var scheme version.Scheme
	consider := func(release, ver string) {
		if release == "" {
			return
		}
		if c, err := version.Compare(scheme, ver, bestVer); best == "" || (err == nil && c > 0) {
			best, bestVer = release, ver
		}
	}
	for _, p := range pkgs {
		switch pm {
		case "dpkg":
			scheme = version.Dpkg
			rel, ok := strings.CutPrefix(p.Name, "linux-image-")
			rel = strings.TrimPrefix(rel, "unsigned-")
			rel = strings.TrimSuffix(rel, "-unsigned")
			if ok && abiName.MatchString("linux-"+rel) && !strings.HasSuffix(rel, "-dbg") && !strings.HasSuffix(rel, "-dbgsym") {
				consider(rel, p.Version)
			}
		case "rpm":
			scheme = version.RPM
			// kernel-core on EL8+ and Fedora, kernel on EL7, kernel-uek on Oracle.
			if p.Name == "kernel-core" || p.Name == "kernel" || p.Name == "kernel-uek-core" || p.Name == "kernel-uek" {
				v := p.Version
				if i := strings.IndexByte(v, ':'); i >= 0 {
					v = v[i+1:]
				}
				rel := v
				if p.Arch != "" {
					rel += "." + p.Arch
				}
				consider(rel, p.Version)
			}
		case "apk":
			scheme = version.APK
			// linux-lts 6.6.52-r0 runs as 6.6.52-0-lts.
			if m := apkKernel.FindStringSubmatch(p.Name); m != nil {
				up, r, ok := strings.Cut(p.Version, "-r")
				if ok && up != "" && r != "" {
					consider(up+"-"+r+"-"+m[1], p.Version)
				}
			}
		}
	}
	return best
}

// releaseRe finds a kernel release in a package name or uname -r:
// "6.17.0-1009" in linux-aws-6.17-headers-6.17.0-1009 or 7.0.0-1014-aws.
var releaseRe = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?-\d+`)

// PurgePrefix is the command that removes kernels that aren't running.
const PurgePrefix = "sudo apt-get purge"

// Release is the kernel release a Debian/Ubuntu ABI-named package belongs
// to ("6.17.0-1009"), or "".
func Release(pm, name string) string {
	if !ABIPackage(pm, name) {
		return ""
	}
	return releaseRe.FindString(name)
}

// runningRelease is uname -r without its flavour: 7.0.0-1014-aws is
// "7.0.0-1014".
func runningRelease(running string) string {
	if m := releaseRe.FindStringIndex(running); m != nil && m[0] == 0 {
		return running[:m[1]]
	}
	return ""
}

// older reports whether release is older than the running kernel's.
func older(release, running string) bool {
	r := runningRelease(running)
	return release != "" && r != "" && version.CompareDpkg(release, r) < 0
}

// NotRunning reports whether a finding's packages all belong to a
// Debian/Ubuntu kernel older than the one running: it's on disk (often
// apt's previous kernel, kept as a boot fallback) but not in use, and
// upgrading never removes it. A newer, not yet booted kernel isn't
// counted: it runs after the next reboot.
func NotRunning(pm, running string, binaries []string) bool {
	if pm != "dpkg" || len(binaries) == 0 {
		return false
	}
	for _, b := range binaries {
		if !older(Release(pm, b), running) {
			return false
		}
	}
	return true
}

// Older returns the installed Debian/Ubuntu kernel packages for releases
// older than the running kernel, sorted: what PurgePrefix removes. It
// never includes the running kernel or a newer one waiting for a reboot.
func Older(pm, running string, installed []string) []string {
	if pm != "dpkg" {
		return nil
	}
	var out []string
	for _, n := range installed {
		if older(Release(pm, n), running) && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// Per-finding kernel statuses (State.Status). A finding that isn't on a
// Debian/Ubuntu kernel ABI package has none ("").
const (
	// StatusRunning: on the running kernel, and no newer one is installed
	// (or the packages span kernels).
	StatusRunning = "running"
	// StatusNotRunning: on an older kernel that's installed but not
	// running. Removing that kernel clears it; upgrading never does.
	StatusNotRunning = "not_running"
	// StatusRebootPending: on the running kernel while a newer kernel is
	// already installed. Rebooting puts the newer one in use, which clears
	// it; the newer kernel may still have findings of its own.
	StatusRebootPending = "reboot_pending"
	// StatusNewerKernel: on a newer kernel that's installed but not yet
	// booted. It's live after the reboot, so rebooting won't clear it.
	StatusNewerKernel = "newer_kernel"
	// StatusUserland: only on packages built from a kernel source that
	// aren't a kernel (Userland). Not live kernel exposure; upgrading them
	// is still the fix.
	StatusUserland = "userland"
)

// Host kernel states (State.Name).
const (
	StateCurrent             = "current"        // running the newest installed kernel, nothing older installed
	StateRebootPending       = "reboot_pending" // a newer kernel is installed than the one running
	StateOldKernels          = "old_kernels"    // running the newest; older kernels are installed too
	StateRebootAndOldKernels = "reboot_pending_and_old_kernels"
)

// State is what a Debian/Ubuntu host's installed kernels say about the
// running one. For other package managers, or an unknown running kernel,
// it knows nothing: Name and every Status are "".
type State struct {
	Running string // uname -r
	// Newer is the newest installed kernel's release (as uname -r prints
	// it) when it's newer than the running one: a reboot puts it in use.
	Newer string
	// Old are the installed ABI packages of releases older than the
	// running one (what Older returns). Boot are the running release's ABI
	// packages when Newer is set: their findings clear after a reboot.
	Old, Boot []string

	old, boot, newer map[string]bool
	dpkg             bool
}

// HostState works out a host's kernel state from its installed packages.
func HostState(pm, running string, pkgs []Installed) State {
	r := runningRelease(running)
	if pm != "dpkg" || r == "" {
		return State{Running: running, dpkg: pm == "dpkg"}
	}
	s := State{Running: running, old: map[string]bool{}, boot: map[string]bool{}, newer: map[string]bool{}, dpkg: true}
	if n := Newest(pm, pkgs); n != "" {
		if nr := runningRelease(n); nr != "" && version.CompareDpkg(nr, r) > 0 {
			s.Newer = n
		}
	}
	for _, p := range pkgs {
		rel := Release(pm, p.Name)
		if rel == "" {
			continue
		}
		switch c := version.CompareDpkg(rel, r); {
		case c < 0:
			s.old[p.Name] = true
		case c == 0 && s.Newer != "":
			s.boot[p.Name] = true
		case c > 0:
			s.newer[p.Name] = true
		}
	}
	s.Old, s.Boot = sortedKeys(s.old), sortedKeys(s.boot)
	return s
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Name is the host's kernel state (StateCurrent and so on), or "" when it
// can't be told.
func (s State) Name() string {
	switch {
	case s.old == nil:
		return ""
	case s.Newer != "" && len(s.Old) > 0:
		return StateRebootAndOldKernels
	case s.Newer != "":
		return StateRebootPending
	case len(s.Old) > 0:
		return StateOldKernels
	}
	return StateCurrent
}

// Status is a finding's kernel status from its binary packages, or ""
// unless it's on Debian/Ubuntu kernel ABI or userland packages. The
// store's finding_counts recount mirrors the not_running, reboot_pending
// and userland rules (with the Old and Boot sets), so keep the two in step.
func (s State) Status(binaries []string) string {
	if s.dpkg && len(binaries) > 0 && !slices.ContainsFunc(binaries, func(b string) bool { return !Userland("dpkg", b) }) {
		return StatusUserland
	}
	if s.old == nil || len(binaries) == 0 {
		return ""
	}
	all := func(set map[string]bool) bool {
		for _, b := range binaries {
			if !set[b] {
				return false
			}
		}
		return true
	}
	switch {
	case all(s.old):
		return StatusNotRunning
	case all(s.boot):
		return StatusRebootPending
	case all(s.newer):
		return StatusNewerKernel
	}
	for _, b := range binaries {
		if ABIPackage("dpkg", b) {
			return StatusRunning
		}
	}
	return ""
}
