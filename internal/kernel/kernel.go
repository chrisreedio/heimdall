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
