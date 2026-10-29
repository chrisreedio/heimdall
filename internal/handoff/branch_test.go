// SPDX-License-Identifier: AGPL-3.0-or-later

package handoff

import (
	"strings"
	"testing"
)

func TestValidBranch(t *testing.T) {
	for _, ok := range []string{"main", "dev", "env/beta", "release-1.2", "feature/x_y", "v2"} {
		if !ValidBranch(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "-x", "/x", ".x", "x/", "x.", "x.lock", "a..b", "a//b", "a/.b", "a/-b",
		"feat;reboot", "a b", "a`b", "<@123>", "a\nb", "@", "a@{1}", "a:b", strings.Repeat("a", MaxBranchLen+1)} {
		if ValidBranch(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestBranchSlug(t *testing.T) {
	for in, want := range map[string]string{"main": "main", "env/beta": "env-beta", "Feature/X__Y": "feature-x-y",
		"___": "branch", strings.Repeat("ab", 30): strings.Repeat("ab", 20)} {
		if got := BranchSlug(in); got != want {
			t.Errorf("BranchSlug(%q) = %q, want %q", in, got, want)
		}
	}
}
