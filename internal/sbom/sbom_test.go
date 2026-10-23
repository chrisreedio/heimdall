// SPDX-License-Identifier: AGPL-3.0-or-later

package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

func TestWrite(t *testing.T) {
	inv := store.HostInventory{
		Host: store.IngestHost{Name: "web-01", OrgSlug: "acme"}, OSID: "debian", OSVersion: "12", PackageManager: "dpkg",
		Packages: []store.InventoryPackage{{Name: "libssl3", Version: "3.0.13-1~deb12u1", Arch: "amd64", SourceName: "openssl"}},
		Sites:    []store.InventorySite{{Root: "/srv/app", Packages: []store.AppPackage{{Name: "laravel/framework", Version: "11.31.0"}}}},
		Lockfiles: []store.InventoryLockfile{{Path: "/srv/js/package-lock.json", Ecosystem: "npm",
			Packages: []store.AppPackage{{Name: "@babel/core", Version: "7.24.0"}}}},
		Containers: []store.InventoryContainer{{Name: "web", Image: "nginx", Tag: "1.27"}},
	}
	var buf bytes.Buffer
	if err := Write(&buf, inv, "0.9.0", time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	var doc document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" || !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") || len(doc.Components) != 4 {
		t.Fatalf("doc = %+v", doc)
	}
	want := []string{
		"pkg:deb/debian/libssl3@3.0.13-1~deb12u1?arch=amd64&distro=debian-12",
		"pkg:composer/laravel/framework@11.31.0",
		"pkg:npm/@babel/core@7.24.0",
	}
	for i, w := range want {
		if doc.Components[i].PURL != w {
			t.Errorf("purl %d = %q, want %q", i, doc.Components[i].PURL, w)
		}
	}
	if doc.Components[3].Type != "container" {
		t.Errorf("container component: %+v", doc.Components[3])
	}
}
