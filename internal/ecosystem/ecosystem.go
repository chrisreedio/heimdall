// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ecosystem maps what a collector reports (os-release values and
// installed packages) onto OSV ecosystems, OSV query keys and language
// runtimes. Unsupported systems are reported as such, never guessed.
package ecosystem

import (
	"regexp"
	"strings"

	"github.com/realmwatch/heimdall/internal/snapshot"
	"github.com/realmwatch/heimdall/internal/version"
)

type Info struct {
	OSV    string         // OSV ecosystem to query, e.g. "Debian:12"
	Scheme version.Scheme // how versions in this ecosystem compare
}

var (
	majorRe         = regexp.MustCompile(`^([0-9]{1,2})(\.[0-9]+)*$`)
	ubuntuRe        = regexp.MustCompile(`^[0-9]{2}\.[0-9]{2}$`)
	ubuntuReleaseRe = regexp.MustCompile(`^[0-9]{2}\.(04|10)$`) // real Ubuntu releases only
	alpineRe        = regexp.MustCompile(`^([0-9]+\.[0-9]+)(\.[0-9]+)?$`)
)

// Resolve maps os-release ID/VERSION_ID and the package manager to an OSV
// ecosystem. ok is false for anything unsupported.
//
// ID_LIKE is only used for Debian and Ubuntu derivatives, and only when the
// derivative's VERSION_ID has the base distro's shape: a bare two-digit
// Debian major (Raspbian "12") or a real Ubuntu release (Pop!_OS "22.04").
// Derivatives with their own numbering (Linux Mint "21.2", LMDE "6", Kali
// "2024.1") are rejected rather than mapped to the wrong release.
//
// RHEL (and CentOS) are unsupported for now: OSV's "Red Hat" ecosystem uses
// CPE-style product streams ("Red Hat:enterprise_linux:9::baseos") that
// don't map one-to-one from os-release.
func Resolve(osID, versionID, idLike, packageManager string) (Info, bool) {
	osID = strings.ToLower(strings.TrimSpace(osID))
	versionID = strings.TrimSpace(versionID)
	if info, ok := resolveID(osID, versionID, packageManager, false); ok {
		return info, true
	}
	if known(osID) {
		return Info{}, false // a known distro with an unusable version
	}
	for _, like := range strings.Fields(strings.ToLower(idLike)) {
		if like != "debian" && like != "ubuntu" {
			continue
		}
		if info, ok := resolveID(like, versionID, packageManager, true); ok {
			return info, true
		}
	}
	return Info{}, false
}

func known(id string) bool {
	switch id {
	case "debian", "ubuntu", "alpine", "rocky", "almalinux", "rhel", "centos":
		return true
	}
	return false
}

func resolveID(id, ver, pm string, derived bool) (Info, bool) {
	switch id {
	case "debian":
		m := majorRe.FindStringSubmatch(ver)
		if m == nil || pm != "dpkg" {
			return Info{}, false
		}
		// Derivatives must carry a bare Debian major (Raspbian "12"). LMDE
		// "6" or Mint "21.2" have their own numbering.
		if derived && (m[0] != m[1] || len(m[1]) < 2) {
			return Info{}, false
		}
		return Info{OSV: "Debian:" + m[1], Scheme: version.Dpkg}, true
	case "ubuntu":
		re := ubuntuRe
		if derived {
			re = ubuntuReleaseRe
		}
		if !re.MatchString(ver) || pm != "dpkg" {
			return Info{}, false
		}
		return Info{OSV: "Ubuntu:" + ver, Scheme: version.Dpkg}, true
	case "alpine":
		m := alpineRe.FindStringSubmatch(ver)
		if m == nil || pm != "apk" {
			return Info{}, false
		}
		return Info{OSV: "Alpine:v" + m[1], Scheme: version.APK}, true
	case "rocky", "almalinux":
		m := majorRe.FindStringSubmatch(ver)
		if m == nil || pm != "rpm" {
			return Info{}, false
		}
		name := map[string]string{"rocky": "Rocky Linux", "almalinux": "AlmaLinux"}[id]
		return Info{OSV: name + ":" + m[1], Scheme: version.RPM}, true
	}
	return Info{}, false
}

// QueryFor returns the package name and version to query OSV with.
//
// Distro advisories are keyed by source package (openssl, not libssl3).
// dpkg queries use the source version, which is unaffected by binNMUs
// ("+b1"). rpm queries use the binary version, because it carries the
// epoch ("1:3.0.7-24.el9") and the source version from SOURCERPM does not.
// apk queries use the origin with the package version.
func QueryFor(info Info, p snapshot.Package) (name, ver string) {
	name = p.Name
	if p.SourceName != "" {
		name = p.SourceName
	}
	ver = p.Version
	if info.Scheme == version.Dpkg && p.SourceVersion != "" {
		ver = p.SourceVersion
	}
	return name, ver
}
