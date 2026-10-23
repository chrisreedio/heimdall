// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import "strings"

// CompareDpkg compares Debian versions ([epoch:]upstream[-revision]) as
// `dpkg --compare-versions` does.
func CompareDpkg(a, b string) int {
	ae, arest := splitEpoch(a)
	be, brest := splitEpoch(b)
	if ae != be {
		return sign(ae - be)
	}
	au, ar := splitRevision(arest)
	bu, br := splitRevision(brest)
	if c := verrevcmp(au, bu); c != 0 {
		return sign(c)
	}
	return sign(verrevcmp(ar, br))
}

// splitRevision splits at the last hyphen; a missing revision is "0".
func splitRevision(v string) (upstream, revision string) {
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, "0"
}

// order is dpkg's character weight: '~' sorts before everything, even the
// end of the string; letters before other symbols.
func order(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	case c != 0:
		return int(c) + 256
	}
	return 0
}

func verrevcmp(a, b string) int {
	i, j := 0, 0
	at := func(s string, k int) byte {
		if k < len(s) {
			return s[k]
		}
		return 0
	}
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := order(at(a, i)), order(at(b, j))
			if ac != bc {
				return ac - bc
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && j < len(b) && isDigit(a[i]) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}
