// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import "strings"

// apk-tools token types, in the order the algorithm relies on.
const (
	tokInvalid = iota - 1
	tokDigitOrZero
	tokDigit
	tokLetter
	tokSuffix
	tokSuffixNo
	tokRevisionNo
	tokEnd
)

var (
	apkPreSuffixes  = []string{"alpha", "beta", "pre", "rc"}
	apkPostSuffixes = []string{"cvs", "svn", "git", "hg", "p"}
)

// CompareAPK compares Alpine package versions as `apk version -t` does
// (a port of apk-tools 2.x src/version.c).
func CompareAPK(a, b string) int {
	at, bt := tokDigit, tokDigit
	av, bv := 0, 0
	for at == bt && at != tokEnd && at != tokInvalid && av == bv {
		av = apkGetToken(&at, &a)
		bv = apkGetToken(&bt, &b)
	}
	if av != bv {
		return sign(av - bv)
	}
	if at == bt {
		return 0
	}
	// Equal so far; the longer version is newer unless what follows is a
	// pre-release suffix (_alpha, _beta, _pre, _rc).
	tt := at
	if at == tokSuffix && apkGetToken(&tt, &a) < 0 {
		return -1
	}
	tt = bt
	if bt == tokSuffix && apkGetToken(&tt, &b) < 0 {
		return 1
	}
	if at > bt {
		return -1
	}
	if bt > at {
		return 1
	}
	return 0
}

func apkNextToken(typ *int, s *string) {
	n := tokInvalid
	v := *s
	switch {
	case v == "":
		n = tokEnd
	case (*typ == tokDigit || *typ == tokDigitOrZero) && v[0] >= 'a' && v[0] <= 'z':
		n = tokLetter
	case *typ == tokLetter && isDigit(v[0]):
		n = tokDigit
	case *typ == tokSuffix && isDigit(v[0]):
		n = tokSuffixNo
	default:
		switch v[0] {
		case '.':
			n = tokDigitOrZero
		case '_':
			n = tokSuffix
		case '-':
			if len(v) > 1 && v[1] == 'r' {
				n = tokRevisionNo
				v = v[1:]
			}
		}
		v = v[1:]
	}
	if n < *typ {
		if !((n == tokDigitOrZero && *typ == tokDigit) ||
			(n == tokSuffix && *typ == tokSuffixNo) ||
			(n == tokDigit && *typ == tokLetter)) {
			n = tokInvalid
		}
	}
	*typ, *s = n, v
}

func apkGetToken(typ *int, s *string) int {
	v := *s
	if v == "" {
		*typ = tokEnd
		return 0
	}
	val, i, nt := 0, 0, tokInvalid
	typeNow := *typ
	if typeNow == tokDigitOrZero {
		if v[0] == '0' {
			// Leading zeros: count all but the last, which stays a digit.
			for i+1 < len(v) && v[i+1] == '0' {
				i++
			}
			nt = tokDigit
			val = -i
			typeNow = tokInvalid // handled; skip the switch below
		} else {
			typeNow = tokDigit // falls through to digit parsing, as in C
		}
	}
	switch typeNow {
	case tokInvalid:
	case tokDigit, tokSuffixNo, tokRevisionNo:
		for i < len(v) && isDigit(v[i]) {
			val = val*10 + int(v[i]-'0')
			i++
		}
		if i >= 18 { // apk-tools rejects numbers that could overflow int64
			*typ = tokInvalid
			return -1
		}
	case tokLetter:
		val = int(v[0])
		i = 1
	case tokSuffix:
		found := false
		for k, suf := range apkPreSuffixes {
			if strings.HasPrefix(v, suf) {
				val, i, found = k-len(apkPreSuffixes), len(suf), true
				break
			}
		}
		if !found {
			for k, suf := range apkPostSuffixes {
				if strings.HasPrefix(v, suf) {
					val, i, found = k, len(suf), true
					break
				}
			}
		}
		if !found {
			*typ = tokInvalid
			return -1
		}
	default:
		*typ = tokInvalid
		return -1
	}
	v = v[i:]
	*s = v
	switch {
	case v == "":
		*typ = tokEnd
	case nt != tokInvalid:
		*typ = nt
	default:
		apkNextToken(typ, s)
	}
	return val
}
