// SPDX-License-Identifier: AGPL-3.0-or-later

package kernel

import (
	"slices"
	"testing"
)

func TestNotRunningAndOlder(t *testing.T) {
	const running = "7.0.0-1014-aws"
	old := []string{"linux-aws-6.17-headers-6.17.0-1009", "linux-headers-6.17.0-1009-aws", "linux-image-6.17.0-1009-aws",
		"linux-modules-6.17.0-1009-aws", "linux-tools-6.17.0-1009-aws"}
	installed := append([]string{"linux-aws", "linux-image-aws", "linux-image-7.0.0-1014-aws", "linux-modules-7.0.0-1014-aws",
		"linux-image-7.0.0-1020-aws", "linux-libc-dev", "openssl"}, old...)
	if got := Older("dpkg", running, installed); !slices.Equal(got, old) {
		t.Errorf("Older = %v, want %v (never the running or a newer kernel)", got, old)
	}
	for _, c := range []struct {
		bins []string
		want bool
	}{
		{old[:2], true},
		{[]string{"linux-image-7.0.0-1014-aws"}, false},                    // running
		{[]string{"linux-image-7.0.0-1020-aws"}, false},                    // newer, after a reboot
		{[]string{"linux-image-6.17.0-1009-aws", "linux-libc-dev"}, false}, // a userland package too
		{nil, false},
	} {
		if got := NotRunning("dpkg", running, c.bins); got != c.want {
			t.Errorf("NotRunning(%v) = %v, want %v", c.bins, got, c.want)
		}
	}
	if NotRunning("dpkg", "", old) || Older("dpkg", "", installed) != nil || NotRunning("rpm", running, old) {
		t.Error("an unknown kernel or another package manager never counts as not running")
	}
}
