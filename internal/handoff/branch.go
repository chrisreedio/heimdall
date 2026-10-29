// SPDX-License-Identifier: AGPL-3.0-or-later

package handoff

import (
	"regexp"
	"strings"
)

// MaxBranchLen caps a branch name.
const MaxBranchLen = 200

var (
	branchRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/-]*$`)
	commitRe = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

// ValidBranch reports whether name is a branch Heimdall accepts: refname-
// safe characters only (letters, digits, ".", "_", "-", "/"), at most
// MaxBranchLen of them, and none of the forms git refuses ("..", "//",
// "/.", a trailing "/", "." or ".lock"). It mirrors the collector's
// valid_branch, and it's checked again here because the value goes into a
// message a bot acts on.
func ValidBranch(name string) bool {
	if len(name) > MaxBranchLen || !branchRe.MatchString(name) {
		return false
	}
	for _, bad := range []string{"..", "//", "/.", "/-"} {
		if strings.Contains(name, bad) {
			return false
		}
	}
	return !strings.HasSuffix(name, "/") && !strings.HasSuffix(name, ".") && !strings.HasSuffix(name, ".lock")
}

// ValidCommit reports whether s is a full commit hash (SHA-1 or SHA-256).
func ValidCommit(s string) bool { return commitRe.MatchString(s) }

// BranchSlug is a branch name made safe for the end of a branch name of
// Heimdall's own ("env/beta" is "env-beta"): lower-case letters, digits
// and single dashes, at most 40 characters.
func BranchSlug(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r)
			dash = false
		} else {
			dash = true
		}
		if b.Len() >= 40 {
			break
		}
	}
	if b.Len() == 0 {
		return "branch"
	}
	return strings.TrimSuffix(b.String(), "-")
}
