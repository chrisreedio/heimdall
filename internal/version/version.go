// SPDX-License-Identifier: AGPL-3.0-or-later

// Package version compares package versions the way each package manager
// does. These are ports of the reference implementations (dpkg's
// verrevcmp, rpm's rpmvercmp, apk-tools' version.c) and are checked
// against the real tools by `make test-versions`.
package version

import (
	"fmt"

	"github.com/realmwatch/heimdall/internal/composer"
)

// Scheme identifies a version comparison algorithm.
type Scheme string

const (
	Dpkg     Scheme = "dpkg"
	RPM      Scheme = "rpm"
	APK      Scheme = "apk"
	Composer Scheme = "composer" // Packagist versions (see internal/composer)
)

// Compare returns -1, 0 or 1 as a is older than, equal to or newer than b.
func Compare(s Scheme, a, b string) (int, error) {
	switch s {
	case Dpkg:
		return CompareDpkg(a, b), nil
	case RPM:
		return CompareRPM(a, b), nil
	case APK:
		return CompareAPK(a, b), nil
	case Composer:
		return composer.CompareVersions(a, b), nil
	}
	return 0, fmt.Errorf("unknown version scheme %q", s)
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// splitEpoch splits "E:rest" into a numeric epoch and rest. A missing or
// non-numeric epoch counts as 0.
func splitEpoch(v string) (int, string) {
	for i := 0; i < len(v); i++ {
		if v[i] == ':' {
			e := 0
			for _, c := range []byte(v[:i]) {
				if !isDigit(c) {
					return 0, v[i+1:]
				}
				e = e*10 + int(c-'0')
				if e > 1<<30 {
					break
				}
			}
			return e, v[i+1:]
		}
		if !isDigit(v[i]) {
			break
		}
	}
	return 0, v
}
