// SPDX-License-Identifier: AGPL-3.0-or-later

package composer

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// MaxLength bounds constraint input; real-world constraints are short.
const MaxLength = 100

type op int

const (
	opAny op = iota // "*": any numeric version
	opEQ
	opNE
	opLT
	opLE
	opGT
	opGE
)

// atom is one comparison against a bound.
type atom struct {
	op op
	v  version
}

// Constraint is a parsed Composer constraint: an OR of AND-groups.
type Constraint struct {
	raw string
	or  [][]atom
}

func (c Constraint) String() string { return c.raw }

var (
	orSplitRe    = regexp.MustCompile(`\s*\|\|?\s*`)
	stabFlagRe   = regexp.MustCompile(`(?i)@(stable|rc|beta|alpha|dev)$`)
	opRe         = regexp.MustCompile(`^(<>|!=|>=|<=|==|=|>|<)?\s*(.+)$`)
	wildcardRe   = regexp.MustCompile(`(?i)^v?(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(?:\.[x*])+$`)
	operatorOnly = map[string]bool{"<>": true, "!=": true, ">=": true, "<=": true, "==": true, "=": true, ">": true, "<": true}
)

// Parse parses a Composer constraint. It returns an error for anything it
// doesn't fully understand.
func Parse(s string) (Constraint, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Constraint{}, errors.New("empty constraint")
	}
	if len(s) > MaxLength {
		return Constraint{}, fmt.Errorf("constraint longer than %d characters", MaxLength)
	}
	c := Constraint{raw: s}
	for _, part := range orSplitRe.Split(s, -1) {
		if part == "" {
			return Constraint{}, fmt.Errorf("%q: empty alternative", s)
		}
		group, err := parseAnd(part)
		if err != nil {
			return Constraint{}, fmt.Errorf("%q: %w", s, err)
		}
		c.or = append(c.or, group)
	}
	return c, nil
}

// parseAnd parses an AND-group: atoms separated by commas or spaces, with
// "a - b" hyphen ranges and ">= 1.0" (operator then space) allowed.
func parseAnd(s string) ([]atom, error) {
	var tokens []string
	for _, seg := range strings.Split(s, ",") {
		fields := strings.Fields(seg)
		if len(fields) == 0 {
			return nil, errors.New("empty constraint between commas")
		}
		tokens = append(tokens, fields...)
	}

	var atoms []atom
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		switch {
		case i+2 < len(tokens) && tokens[i+1] == "-":
			as, err := parseHyphen(tok, tokens[i+2])
			if err != nil {
				return nil, err
			}
			atoms = append(atoms, as...)
			i += 2
			continue
		case tok == "-":
			return nil, errors.New("misplaced '-'")
		case operatorOnly[tok]:
			if i+1 >= len(tokens) {
				return nil, fmt.Errorf("operator %q without a version", tok)
			}
			tok += tokens[i+1]
			i++
		}
		as, err := parseAtom(tok)
		if err != nil {
			return nil, err
		}
		atoms = append(atoms, as...)
	}
	return atoms, nil
}

func parseAtom(s string) ([]atom, error) {
	s = stabFlagRe.ReplaceAllString(s, "")
	if s == "" {
		return nil, errors.New("stability flag without a version")
	}
	if s == "*" || strings.EqualFold(s, "x") {
		return []atom{{op: opAny}}, nil
	}

	switch {
	case strings.HasPrefix(s, "~>"):
		return nil, fmt.Errorf("%q: '~>' is not Composer syntax (use '~' or '^')", s)
	case strings.HasPrefix(s, "~"):
		return parseTilde(s[1:])
	case strings.HasPrefix(s, "^"):
		return parseCaret(s[1:])
	}

	if m := wildcardRe.FindStringSubmatch(s); m != nil {
		return parseWildcard(m)
	}

	m := opRe.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("%q: unsupported constraint", s)
	}
	v, ok := parseVersion(m[2])
	if !ok {
		return nil, fmt.Errorf("%q: invalid version", s)
	}
	if v.branch != "" {
		switch m[1] {
		case "", "=", "==":
			return []atom{{op: opEQ, v: v}}, nil
		case "!=", "<>":
			return []atom{{op: opNE, v: v}}, nil
		}
		return nil, fmt.Errorf("%q: dev branches only support = and !=", s)
	}
	switch m[1] {
	case "", "=", "==":
		return []atom{{op: opEQ, v: v}}, nil
	case "!=", "<>":
		return []atom{{op: opNE, v: v}}, nil
	case ">":
		return []atom{{op: opGT, v: v}}, nil
	case "<=":
		return []atom{{op: opLE, v: v}}, nil
	case "<":
		// "<2.0" excludes 2.0's pre-releases too, as in Composer.
		return []atom{{op: opLT, v: asDev(v)}}, nil
	case ">=":
		// ">=2.0" includes 2.0's pre-releases, as in Composer.
		return []atom{{op: opGE, v: asDev(v)}}, nil
	}
	return nil, fmt.Errorf("%q: unsupported operator", s)
}

func numeric(s string) (version, error) {
	v, ok := parseVersion(s)
	if !ok || v.branch != "" {
		return version{}, fmt.Errorf("%q: invalid version", s)
	}
	return v, nil
}

// ~1.2 → >=1.2-dev <2.0-dev; ~1.2.3 → >=1.2.3-dev <1.3-dev; ~1 → <2.0-dev.
func parseTilde(s string) ([]atom, error) {
	v, err := numeric(s)
	if err != nil {
		return nil, err
	}
	if v.devSuffix {
		return nil, fmt.Errorf("~%s: x-dev tilde ranges are not supported", s)
	}
	high := max(1, v.given-1)
	return []atom{{op: opGE, v: asDev(v)}, {op: opLT, v: bump(v, high)}}, nil
}

// ^1.2.3 → <2.0-dev; ^0.3 → <0.4-dev; ^0.0.3 → <0.0.4-dev; ^0 → <1.0-dev.
func parseCaret(s string) ([]atom, error) {
	v, err := numeric(s)
	if err != nil {
		return nil, err
	}
	if v.devSuffix {
		return nil, fmt.Errorf("^%s: x-dev caret ranges are not supported", s)
	}
	position := 3
	switch {
	case v.parts[0] != 0 || v.given < 2:
		position = 1
	case v.parts[1] != 0 || v.given < 3:
		position = 2
	}
	return []atom{{op: opGE, v: asDev(v)}, {op: opLT, v: bump(v, position)}}, nil
}

// 8.1.* → >=8.1.0.0-dev <8.2.0.0-dev; 8.* → <9.0-dev.
func parseWildcard(m []string) ([]atom, error) {
	s := m[1]
	given := 1
	if m[2] != "" {
		s += "." + m[2]
		given = 2
	}
	if m[3] != "" {
		s += "." + m[3]
		given = 3
	}
	v, err := numeric(s)
	if err != nil {
		return nil, err
	}
	low := v
	low.stab, low.explicit = stabDev, true
	return []atom{{op: opGE, v: low}, {op: opLT, v: bump(v, given)}}, nil
}

// "1.0 - 2.0" → >=1.0-dev <2.1-dev; "1.0 - 2.0.3" (full upper) → <=2.0.3.
func parseHyphen(from, to string) ([]atom, error) {
	lo, err := numeric(stabFlagRe.ReplaceAllString(from, ""))
	if err != nil {
		return nil, err
	}
	hi, err := numeric(stabFlagRe.ReplaceAllString(to, ""))
	if err != nil {
		return nil, err
	}
	atoms := []atom{{op: opGE, v: asDev(lo)}}
	if hi.given >= 3 || hi.explicit {
		return append(atoms, atom{op: opLE, v: hi}), nil
	}
	return append(atoms, atom{op: opLT, v: bump(hi, hi.given)}), nil
}

// Allows reports whether version satisfies the constraint. "8.3" means
// 8.3.0; dev branches only satisfy an equal branch constraint.
func (c Constraint) Allows(ver string) bool {
	v, ok := parseVersion(ver)
	if !ok {
		return false
	}
	return c.allows(v)
}

func (c Constraint) allows(v version) bool {
	for _, group := range c.or {
		all := true
		for _, a := range group {
			if !a.allows(v) {
				all = false
				break
			}
		}
		if all && len(group) > 0 {
			return true
		}
	}
	return false
}

func (a atom) allows(v version) bool {
	switch {
	case v.branch != "" && a.v.branch == "":
		return false // a dev branch never satisfies a numeric bound (or "*")
	case a.v.branch != "":
		if a.op == opEQ {
			return v.branch == a.v.branch
		}
		return v.branch != a.v.branch // opNE
	}
	if a.op == opAny {
		return true
	}
	c := cmp(v, a.v)
	switch a.op {
	case opEQ:
		return c == 0
	case opNE:
		return c != 0
	case opLT:
		return c < 0
	case opLE:
		return c <= 0
	case opGT:
		return c > 0
	case opGE:
		return c >= 0
	}
	return false
}

// AllowsMinor reports whether some stable patch release of major.minor
// satisfies the constraint, for when only the minor version is known (a
// host's PHP-FPM socket says 8.3 but not 8.3.12).
func (c Constraint) AllowsMinor(majorMinor string) bool {
	v, ok := parseVersion(majorMinor)
	if !ok || v.branch != "" || v.given < 2 {
		return false
	}
	major, minor := v.parts[0], v.parts[1]

	// The constraint is constant between its bounds, so it's enough to
	// test the start of the minor and every bound inside it (and just
	// above each bound).
	candidates := []version{{parts: [4]int64{major, minor}, stab: stabStable}}
	for _, group := range c.or {
		for _, a := range group {
			b := a.v
			if b.branch != "" || b.parts[0] != major || b.parts[1] != minor {
				continue
			}
			for _, p := range []int64{b.parts[2], b.parts[2] + 1} {
				for _, q := range []int64{b.parts[3], b.parts[3] + 1} {
					candidates = append(candidates, version{parts: [4]int64{major, minor, p, q}, stab: stabStable})
				}
			}
		}
	}
	for _, cand := range candidates {
		if c.allows(cand) {
			return true
		}
	}
	return false
}
