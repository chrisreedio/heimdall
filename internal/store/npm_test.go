// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/snapshot"
)

// A v4 site's npm packages are stored with their dev flags and come back
// on the site; an allowlisted lockfile at the same path folds into the
// site instead of showing up twice, while one elsewhere stays a lockfile.
func TestSiteNpmPackages(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	setupHost(t, s)
	host, _ := s.HostByName(ctx, "acme", "web-01.example.com")
	at := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	snap := &snapshot.Snapshot{
		Format: snapshot.FormatV4, CollectedAt: at, PackageManager: "dpkg",
		Collector: snapshot.Collector{Version: "0.5.0"},
		OS:        snapshot.OS{ID: "debian", VersionID: "12"},
		Kernel:    snapshot.Kernel{Release: "6.1.0", Arch: "x86_64"},
		Packages:  []snapshot.Package{{Name: "openssl", Version: "3.0.11-1", Arch: "amd64"}},
		Sites: []snapshot.Site{{Root: "/srv/app", Readable: true,
			ComposerPackages: []snapshot.ComposerPackage{{Name: "laravel/framework", Version: "11.31.0"}},
			NpmPackages: []snapshot.NpmPackage{
				{Name: "axios", Version: "1.7.2"},
				{Name: "vite", Version: "5.0.10", Dev: true},
			}}},
		Containers: []snapshot.Container{},
		Lockfiles: []snapshot.Lockfile{
			{Path: "/srv/app/package-lock.json", Ecosystem: "npm", Packages: []snapshot.ComposerPackage{{Name: "vite", Version: "5.0.10"}}},
			{Path: "/srv/tools/package-lock.json", Ecosystem: "npm", Packages: []snapshot.ComposerPackage{{Name: "lodash", Version: "4.17.21"}}},
		},
	}
	if _, err := s.SaveSnapshot(ctx, NewSnapshot{Host: host, Source: "push", ReceivedAt: at, Snapshot: snap,
		PayloadSHA256: sha256.Sum256([]byte("npm"))}, nil); err != nil {
		t.Fatal(err)
	}
	inv, err := s.Inventory(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Sites) != 1 {
		t.Fatalf("sites %+v", inv.Sites)
	}
	site := inv.Sites[0]
	want := []AppPackage{{Name: "axios", Version: "1.7.2"}, {Name: "vite", Version: "5.0.10", Dev: true}}
	if len(site.Packages) != 1 || len(site.NpmPackages) != 2 || site.NpmPackages[0] != want[0] || site.NpmPackages[1] != want[1] {
		t.Errorf("composer %+v, npm %+v", site.Packages, site.NpmPackages)
	}
	if len(inv.Lockfiles) != 1 || inv.Lockfiles[0].Path != "/srv/tools/package-lock.json" {
		t.Errorf("lockfiles %+v", inv.Lockfiles)
	}
}
