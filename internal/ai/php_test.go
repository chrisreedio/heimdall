// SPDX-License-Identifier: AGPL-3.0-or-later

package ai

import (
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/report"
)

func TestUnusedPHPCommands(t *testing.T) {
	rts := []report.Runtime{
		{Name: "php", Version: "8.1.2", Use: &report.PHPUse{Minor: "8.1", Unused: true, CLI: true, CLITo: "8.4",
			Commands: []string{"sudo update-alternatives --set php /usr/bin/php8.4", "sudo apt-get purge php8.1-cli php8.1-common"}}},
		{Name: "php", Version: "8.4.1", Use: &report.PHPUse{Minor: "8.4", Sites: []string{"app.example.com"}}},
	}
	cmds := unusedPHPCommands("dpkg", rts)
	if len(cmds) != 2 || cmds[0].Command != "sudo update-alternatives --set php /usr/bin/php8.4" ||
		cmds[1].Command != "sudo apt-get purge php8.1-cli php8.1-common" || !strings.Contains(cmds[1].Label, "Remove PHP 8.1") {
		t.Fatalf("commands: %+v", cmds)
	}
	if unusedPHPCommands("rpm", rts) != nil {
		t.Error("rpm hosts get apt commands")
	}

	h := HostAllowed{PM: "dpkg", Commands: []string{cmds[0].Command, cmds[1].Command,
		"sudo apt-get purge linux-image-6.17.0-1009-aws"}}
	for cmd, ok := range map[string]bool{
		"sudo apt-get purge php8.1-cli php8.1-common":               true,
		"sudo apt-get purge php8.1-common":                          true,
		"sudo update-alternatives --set php /usr/bin/php8.4":        true,
		"sudo update-alternatives --set php /usr/bin/php8.3":        false, // not one Heimdall suggested
		"sudo apt-get purge php8.4-cli":                             false, // in use
		"sudo apt-get purge php8.1-cli linux-image-6.17.0-1009-aws": false, // two commands' packages
		"sudo apt-get purge php8.1-cli; rm -rf /":                   false,
	} {
		if got := checkCommand(cmd, h) != ""; got != ok {
			t.Errorf("checkCommand(%q) = %v, want %v", cmd, got, ok)
		}
	}
	if !commandShapeOK("sudo apt-get purge php8.1-cli php8.1-common") || !commandShapeOK("sudo update-alternatives --set php /usr/bin/php8.4") ||
		commandShapeOK("sudo apt-get purge php8.1-cli openssl") || commandShapeOK("sudo update-alternatives --set php /usr/bin/php8.4 && reboot") {
		t.Error("stored command shapes")
	}
}
