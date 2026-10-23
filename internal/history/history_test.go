// SPDX-License-Identifier: AGPL-3.0-or-later

package history

import (
	"testing"

	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/version"
)

func pk(name, ver string) store.InventoryPackage {
	return store.InventoryPackage{Name: name, Version: ver, Arch: "amd64"}
}

func TestCompare(t *testing.T) {
	from := []store.InventoryPackage{pk("openssl", "3.0.11-1~deb12u2"), pk("curl", "7.88.1-10"), pk("nano", "7.2-1"),
		pk("linux-image", "6.1.0-25"), pk("linux-image", "6.1.0-26")}
	to := []store.InventoryPackage{pk("openssl", "3.0.13-1~deb12u1"), pk("curl", "7.88.1-9"), pk("nmap", "7.93"),
		pk("linux-image", "6.1.0-26"), pk("linux-image", "6.1.0-27")}
	d := Compare(version.Dpkg, from, to)
	if len(d.Upgraded) != 2 || d.Upgraded[0].Name != "linux-image" || d.Upgraded[1].Name != "openssl" {
		t.Errorf("upgraded = %+v", d.Upgraded)
	}
	if len(d.Downgraded) != 1 || d.Downgraded[0].Name != "curl" {
		t.Errorf("downgraded = %+v", d.Downgraded)
	}
	if len(d.Added) != 1 || d.Added[0].Name != "nmap" || len(d.Removed) != 1 || d.Removed[0].Name != "nano" {
		t.Errorf("added %+v removed %+v", d.Added, d.Removed)
	}
	if !Compare(version.Dpkg, from, from).Empty() {
		t.Error("identical lists must not differ")
	}
	// The scheme matters: dpkg's ~ sorts before release, so this is an upgrade.
	if d := Compare(version.Dpkg, []store.InventoryPackage{pk("x", "1.0~rc1")}, []store.InventoryPackage{pk("x", "1.0")}); len(d.Upgraded) != 1 {
		t.Errorf("tilde: %+v", d)
	}
}
