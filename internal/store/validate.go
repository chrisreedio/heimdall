// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	slugRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	hostRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,251}[a-z0-9])?$`)
	tagRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9:._-]{0,63}$`)
)

// ValidationError describes input rejected before it reaches the database.
type ValidationError struct{ Field, Msg string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Msg }

func checkSlug(field, s string) error {
	if !slugRe.MatchString(s) {
		return &ValidationError{field, fmt.Sprintf("%q must be 1-63 lowercase letters, digits or '-', not starting or ending with '-'", s)}
	}
	return nil
}

func normalizeHostName(s string) (string, error) {
	s = strings.ToLower(s)
	if !hostRe.MatchString(s) {
		return "", &ValidationError{"host", fmt.Sprintf("%q must be a hostname: letters, digits, '.', '-' or '_'", s)}
	}
	return s, nil
}

func normalizeTags(tags []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if !tagRe.MatchString(t) {
			return nil, &ValidationError{"tag", fmt.Sprintf("%q must be up to 64 lowercase letters, digits or ':._-'", t)}
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}

func normalizeName(field, s string) (string, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return "", &ValidationError{field, "is required"}
	case utf8.RuneCountInString(s) > 200:
		return "", &ValidationError{field, "must be at most 200 characters"}
	case strings.ContainsFunc(s, unicode.IsControl):
		return "", &ValidationError{field, "must not contain control characters"}
	}
	return s, nil
}

// guidRe matches Entra tenant and object IDs.
var guidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
