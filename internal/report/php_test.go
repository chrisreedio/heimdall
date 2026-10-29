// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"slices"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/store"
)

func phpHost(sites map[string]string, minors ...string) (Host, []store.InventoryPackage) {
	h := Host{}
	var pkgs []store.InventoryPackage
	for _, m := range minors {
		h.Runtimes = append(h.Runtimes, Runtime{Name: "php", Version: m + ".9-1+ubuntu22.04.1", Package: "php" + m + "-cli"})
		for _, p := range []string{"php" + m + "-cli", "php" + m + "-common", "php" + m + "-xml"} {
			pkgs = append(pkgs, store.InventoryPackage{Name: p, Version: m + ".9"})
		}
	}
	pkgs = append(pkgs, store.InventoryPackage{Name: "php-cli", Version: "2:8.4"}, store.InventoryPackage{Name: "libapache2-mod-php8.1", Version: "8.1.9"})
	for name, v := range sites {
		h.Sites = append(h.Sites, Site{Root: "/var/www/" + name, ServerNames: []string{name}, PHPFPM: v})
	}
	return h, pkgs
}

func useOf(h Host, minor string) *PHPUse {
	for _, rt := range h.Runtimes {
		if rt.Use != nil && rt.Use.Minor == minor {
			return rt.Use
		}
	}
	return nil
}

func TestPHPUse(t *testing.T) {
	// 8.4 runs the site, 8.3's PHP-FPM is running for something unknown,
	// 8.1 is installed and the command line's; 8.5 is just installed.
	h, pkgs := phpHost(map[string]string{"app.example.com": "8.4"}, "8.1", "8.3", "8.4", "8.5")
	phpUse(&h, store.HostPHP{CLI: "8.1", FPM: []string{"8.3", "8.4"}}, pkgs)
	if !h.PHPKnown {
		t.Error("PHPKnown not set")
	}
	if u := useOf(h, "8.4"); u.Unused || !slices.Equal(u.Sites, []string{"app.example.com"}) || !u.FPMRunning {
		t.Errorf("8.4: %+v", u)
	}
	if u := useOf(h, "8.3"); u.Unused || !u.FPMRunning {
		t.Errorf("8.3 (PHP-FPM running): %+v", u)
	}
	u := useOf(h, "8.1")
	if !u.Unused || !u.CLI || u.CLITo != "8.4" {
		t.Fatalf("8.1 (the command line's): %+v", u)
	}
	if want := "sudo apt-get purge php8.1-cli php8.1-common php8.1-xml"; !slices.Equal(u.Commands, []string{"sudo update-alternatives --set php /usr/bin/php8.4", want}) ||
		u.DryRun != "sudo apt-get purge -s php8.1-cli php8.1-common php8.1-xml" {
		t.Errorf("8.1 commands: %q, dry run %q", u.Commands, u.DryRun)
	}
	if !strings.Contains(u.Check, `'php8\.1([^0-9]|$)'`) {
		t.Errorf("8.1 check: %q", u.Check)
	}
	if u := useOf(h, "8.5"); !u.Unused || u.CLITo != "" || len(u.Commands) != 1 {
		t.Errorf("8.5: %+v", u)
	}
	// libapache2-mod-php8.1 isn't php8.1-*: it isn't removed.
	if slices.Contains(useOf(h, "8.1").Packages, "libapache2-mod-php8.1") {
		t.Error("removes libapache2-mod-php8.1")
	}
}

func TestPHPUseCLIOnly(t *testing.T) {
	// The only version, run by nothing but the command line: it stays.
	h, pkgs := phpHost(nil, "8.1")
	phpUse(&h, store.HostPHP{CLI: "8.1"}, pkgs)
	if u := useOf(h, "8.1"); u == nil || u.Unused {
		t.Errorf("only version: %+v", u)
	}
	// With another installed but unused, the command line moves to the
	// newest other one.
	h, pkgs = phpHost(nil, "8.1", "8.2", "8.3")
	phpUse(&h, store.HostPHP{CLI: "8.1"}, pkgs)
	if u := useOf(h, "8.1"); !u.Unused || u.CLITo != "8.3" {
		t.Errorf("8.1 with others: %+v", u)
	}
	// 8.3 is where php goes, so it stays; 8.2 goes.
	if u := useOf(h, "8.3"); u.Unused {
		t.Errorf("8.3 (php's new version) suggested for removal: %+v", u)
	}
	if u := useOf(h, "8.2"); !u.Unused {
		t.Errorf("8.2: %+v", u)
	}
}
