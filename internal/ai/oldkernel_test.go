// SPDX-License-Identifier: AGPL-3.0-or-later

package ai

import "testing"

func TestPurgeOnlyOldKernels(t *testing.T) {
	h := HostAllowed{PM: "dpkg", Commands: []string{"sudo apt-get purge linux-headers-6.17.0-1009-aws linux-image-6.17.0-1009-aws"}}
	for cmd, ok := range map[string]bool{
		"sudo apt-get purge linux-image-6.17.0-1009-aws":                               true,
		"sudo apt-get purge linux-headers-6.17.0-1009-aws linux-image-6.17.0-1009-aws": true,
		"sudo apt-get purge linux-image-7.0.0-1014-aws":                                false, // the running kernel
		"sudo apt-get purge openssl":                                                   false,
		"sudo apt-get purge linux-image-6.17.0-1009-aws && sudo reboot":                false,
		"sudo apt-get purge -y linux-image-6.17.0-1009-aws":                            false,
	} {
		if got := checkCommand(cmd, h) != ""; got != ok {
			t.Errorf("checkCommand(%q) = %v, want %v", cmd, got, ok)
		}
	}
	if checkCommand("sudo apt-get purge linux-image-6.17.0-1009-aws", HostAllowed{PM: "rpm"}) != "" {
		t.Error("purge is dpkg only")
	}
	if !commandShapeOK("sudo apt-get purge linux-image-6.17.0-1009-aws") || commandShapeOK("sudo apt-get purge openssl") {
		t.Error("stored purge commands may name only ABI kernel packages")
	}
}
