// SPDX-License-Identifier: AGPL-3.0-or-later

// Package composer parses Composer version constraints ("^8.2",
// "~8.1.0", ">=8.1 <9.0", "8.1.*", "^7.4 || ^8.0") and compares
// Packagist versions, following https://getcomposer.org/doc/articles/versions.md
// and Composer's VersionParser. Unsupported syntax is an error rather than
// a guess.
package composer

import (
	"regexp"
	"strconv"
	"strings"
)

// Stability ranks, lowest first. "patch" releases sort after stable.
const (
	stabDev = iota
	stabAlpha
	stabBeta
	stabRC
	stabStable
	stabPatch
)

// version is a normalized Composer version: four numeric parts plus a
// stability, or a dev branch ("dev-main").
type version struct {
	parts     [4]int64
	given     int // how many numeric parts were written (1-4)
	stab      int
	stabNum   [2]int64
	explicit  bool   // a stability suffix (incl. "-dev") was written
	branch    string // non-empty for dev-* branches
	devSuffix bool   // written with a trailing "-dev" ("1.2-dev")
}

// Mirrors Composer's normalize() for classical versions (dates aren't supported).
var versionRe = regexp.MustCompile(`(?i)^v?(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?` +
	`(?:[._-]?(stable|beta|b|rc|alpha|a|patch|pl|p)((?:[.-]?\d{1,9}){0,2}))?(?:[.-]?(dev))?$`)

var branchRe = regexp.MustCompile(`(?i)^dev-[A-Za-z0-9._/-]{1,80}$`)

func parseVersion(s string) (version, bool) {
	s = strings.TrimSpace(s)
	if branchRe.MatchString(s) {
		return version{branch: strings.ToLower(s), stab: stabDev}, true
	}
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return version{}, false
	}
	var v version
	for i := 0; i < 4; i++ {
		if m[i+1] == "" {
			continue
		}
		n, err := strconv.ParseInt(m[i+1], 10, 64)
		if err != nil {
			return version{}, false
		}
		v.parts[i] = n
		v.given = i + 1
	}
	v.stab = stabStable
	if m[5] != "" {
		v.explicit = true
		switch strings.ToLower(m[5]) {
		case "stable":
			v.stab = stabStable
		case "beta", "b":
			v.stab = stabBeta
		case "rc":
			v.stab = stabRC
		case "alpha", "a":
			v.stab = stabAlpha
		case "patch", "pl", "p":
			v.stab = stabPatch
		}
		nums := strings.FieldsFunc(m[6], func(r rune) bool { return r == '.' || r == '-' })
		for i, n := range nums {
			if i >= 2 {
				break
			}
			x, err := strconv.ParseInt(n, 10, 64)
			if err != nil {
				return version{}, false
			}
			v.stabNum[i] = x
		}
	}
	if m[7] != "" {
		v.explicit = true
		v.devSuffix = true
		v.stab = stabDev
	}
	return v, true
}

// cmp compares two numeric versions (branches must be handled by callers).
func cmp(a, b version) int {
	for i := range a.parts {
		if a.parts[i] != b.parts[i] {
			return sign(a.parts[i] - b.parts[i])
		}
	}
	if a.stab != b.stab {
		return sign(int64(a.stab - b.stab))
	}
	for i := range a.stabNum {
		if a.stabNum[i] != b.stabNum[i] {
			return sign(a.stabNum[i] - b.stabNum[i])
		}
	}
	return 0
}

func sign(n int64) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// CompareVersions compares Composer/Packagist versions and returns -1, 0
// or 1. A "v" prefix is ignored; alpha < beta < RC < stable < patch.
// Dev branches ("dev-main") sort below every numeric version, and
// unparsable strings below those; ties within each group compare as text.
func CompareVersions(a, b string) int {
	va, okA := parseVersion(a)
	vb, okB := parseVersion(b)
	rank := func(v version, ok bool) int {
		switch {
		case !ok:
			return 0
		case v.branch != "":
			return 1
		}
		return 2
	}
	ra, rb := rank(va, okA), rank(vb, okB)
	if ra != rb {
		return sign(int64(ra - rb))
	}
	if ra == 2 {
		return cmp(va, vb)
	}
	return strings.Compare(strings.ToLower(strings.TrimSpace(a)), strings.ToLower(strings.TrimSpace(b)))
}

// bump returns v with the part at position (1-based) incremented and the
// later parts zeroed, as a "-dev" bound (Composer's manipulateVersionString).
func bump(v version, position int) version {
	out := version{stab: stabDev, given: 4, explicit: true}
	for i := 0; i < position-1; i++ {
		out.parts[i] = v.parts[i]
	}
	out.parts[position-1] = v.parts[position-1] + 1
	return out
}

// asDev returns v with dev stability unless a stability was written,
// making a lower bound include pre-releases of that version.
func asDev(v version) version {
	if !v.explicit {
		v.stab = stabDev
		v.stabNum = [2]int64{}
	}
	return v
}
