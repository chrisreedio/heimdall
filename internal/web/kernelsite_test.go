// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/ai"
	"github.com/realmwatch/heimdall/internal/kernel"
	"github.com/realmwatch/heimdall/internal/report"
)

// A step about one site offers a hand-off for that site only, even when
// another site has fixable findings in the same packages.
func TestAIHandoffNamesItsSite(t *testing.T) {
	a, b := "/home/forge/affiliates.example.dev/current", "/home/forge/shop.example.com/current"
	h := report.Host{Findings: []report.Finding{
		{Site: a, Package: "laravel/framework", Version: "12.64.0", Fixed: "12.68.0", Advisory: "GHSA-aaaa-bbbb-cccc"},
		{Site: b, Package: "laravel/framework", Version: "13.5.0", Fixed: "13.29.0", Advisory: "GHSA-aaaa-bbbb-cccc"},
	}}
	sites := []siteSection{{Site: report.Site{Root: a, ServerNames: []string{"affiliates.example.dev"}}},
		{Site: report.Site{Root: b, ServerNames: []string{"shop.example.com"}}}}
	view := &aiView{View: ai.View{Result: &ai.Result{Actions: []ai.Action{
		step("Upgrade affiliates.example.dev dependencies", "", "web-01", "composer update laravel/framework --with-dependencies"),
		step("Upgrade dependencies", "Run this in "+b+" and test.", "web-01", "composer update laravel/framework --with-dependencies"),
		step("Upgrade Laravel everywhere", "", "web-01", "composer update laravel/framework --with-dependencies"),
	}}}}
	aiHandoffs(view, "acme", "web-01", sites, h)
	if l := view.Handoffs[0]; len(l) != 1 || !strings.Contains(l[0].URL, "affiliates") || l[0].Site != "" {
		t.Errorf("step about affiliates: %+v", l)
	}
	if l := view.Handoffs[1]; len(l) != 1 || !strings.Contains(l[0].URL, "shop") {
		t.Errorf("step naming the shop's root: %+v", l)
	}
	if l := view.Handoffs[2]; len(l) != 2 {
		t.Errorf("a step naming no site offers both: %+v", l)
	}
}

// Findings on an old kernel that isn't running stay out of the upgrade
// command (upgrading never clears them); a removal command clears them.
func TestOldKernelCommands(t *testing.T) {
	installed := pending("linux-aws", "linux-image-aws", "openssl")
	list := []report.Finding{
		{Package: "linux-aws-6.17", Binaries: []string{"linux-image-6.17.0-1009-aws"}, Fixed: "6.17.0-1017.17", KEV: true, NotRunning: true, KernelStatus: kernel.StatusNotRunning},
		{Package: "openssl", Binaries: []string{"openssl"}, Fixed: "3.0.13-1"},
	}
	cmd, _, _ := planFix("dpkg", list, installed)
	if cmd == nil || cmd.Text != "sudo apt-get update && sudo apt-get install --only-upgrade openssl" || strings.Contains(cmd.Note, "kernel") {
		t.Errorf("upgrade command = %+v", cmd)
	}
	old := oldKernelCommand([]string{"linux-headers-6.17.0-1009-aws", "linux-image-6.17.0-1009-aws"}, 1)
	if old == nil || old.Text != "sudo apt-get purge linux-headers-6.17.0-1009-aws linux-image-6.17.0-1009-aws" {
		t.Errorf("removal command = %+v", old)
	}
	if oldKernelCommand([]string{"linux-image-6.17.0-1009-aws"}, 0) != nil {
		t.Error("no removal command when no findings are on the old kernel")
	}
}
