// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import "strings"

// CompareRPM compares [epoch:]version[-release] as rpm's rpmverCmp does. A
// missing release compares as empty, so "2.0-1" is newer than "2.0".
func CompareRPM(a, b string) int {
	ae, arest := splitEpoch(a)
	be, brest := splitEpoch(b)
	if ae != be {
		return sign(ae - be)
	}
	av, ar := splitRelease(arest)
	bv, br := splitRelease(brest)
	if c := rpmvercmp(av, bv); c != 0 {
		return c
	}
	return rpmvercmp(ar, br)
}

// splitRelease splits at the last hyphen, as rpm's parseEVR does.
func splitRelease(v string) (version, release string) {
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// rpmvercmp is a port of rpm's rpmvercmp (rpmio/rpmvercmp.c), including
// '~' (sorts before anything) and '^' (sorts after the base, before more).
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		ai, bj := i < len(a), j < len(b)
		if (ai && a[i] == '~') || (bj && b[j] == '~') {
			if !ai || a[i] != '~' {
				return 1
			}
			if !bj || b[j] != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if (ai && a[i] == '^') || (bj && b[j] == '^') {
			if !ai {
				return -1
			}
			if !bj {
				return 1
			}
			if a[i] != '^' {
				return 1
			}
			if b[j] != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if !ai || !bj {
			break
		}

		si, sj := i, j
		isNum := isDigit(a[i])
		if isNum {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		sa, sb := a[si:i], b[sj:j]
		if sb == "" { // segment types differ: numeric beats alpha
			if isNum {
				return 1
			}
			return -1
		}
		if isNum {
			sa, sb = strings.TrimLeft(sa, "0"), strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				return sign(len(sa) - len(sb))
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i < len(a):
		return 1
	}
	return -1
}
