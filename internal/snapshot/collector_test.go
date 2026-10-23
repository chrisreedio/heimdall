// SPDX-License-Identifier: AGPL-3.0-or-later

package snapshot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCollectorOutput validates real collector output produced by
// collector/test/run-containers.sh. Skipped unless HEIMDALL_COLLECTOR_OUT
// points at that script's output directory.
func TestCollectorOutput(t *testing.T) {
	dir := os.Getenv("HEIMDALL_COLLECTOR_OUT")
	if dir == "" {
		t.Skip("HEIMDALL_COLLECTOR_OUT not set; run collector/test/run-containers.sh")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no snapshots in %s (%v)", dir, err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			s, err := DecodeBytes(b)
			if err != nil {
				t.Fatal(err)
			}
			pending := 0
			for _, u := range s.Updates {
				if u.Security != nil && *u.Security {
					pending++
				}
			}
			t.Logf("%s %s via %s: %d packages, %d updates (%d security), reboot=%v, unavailable=%v",
				s.OS.ID, s.OS.VersionID, s.PackageManager, len(s.Packages), len(s.Updates), pending,
				ptr(s.RebootRequired), s.Unavailable)
		})
	}
}

func ptr(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

// TestCollectorSites checks site discovery against the fixture laid out by
// collector/test/sites-fixture.sh (the *-sites targets).
func TestCollectorSites(t *testing.T) {
	dir := os.Getenv("HEIMDALL_COLLECTOR_OUT")
	if dir == "" {
		t.Skip("HEIMDALL_COLLECTOR_OUT not set; run collector/test/run-containers.sh")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*-sites.json"))
	if len(files) == 0 {
		t.Fatalf("no *-sites.json snapshots in %s", dir)
	}
	type want struct {
		docroot, web, php, framework, version, phpReq string
		names                                         []string
		readable                                      bool
		packages                                      int
	}
	expect := map[string]want{
		// Forge layout; a second vhost for the same app merges its names.
		"/home/forge/example.com": {"/home/forge/example.com/public", "nginx", "8.3", "laravel", "11.31.0", "^8.2",
			[]string{"example.com", "www.example.com", "example.org"}, true, 4},
		// Regex server_name skipped; quoted root; PHP from the location block.
		"/var/www/api": {"/var/www/api/public", "nginx", "8.2", "laravel", "10.48.22", "^8.1",
			[]string{"api.example.com"}, true, 4},
		"/var/www/html": {"/var/www/html", "nginx", "", "", "", "", []string{"_"}, true, 0},
		// The collector can't enter /home/locked, so the root stays the docroot.
		"/home/locked/app/public": {"/home/locked/app/public", "nginx", "", "", "", "", []string{"locked.example.com"}, false, 0},
		"/var/www/alp":            {"/var/www/alp/public", "nginx", "8.3", "laravel", "11.31.0", "^8.3", []string{"alp.example.com"}, true, 4},
		// Unreadable composer.lock: no composer data at all.
		"/var/www/legacy":  {"/var/www/legacy/public", "apache", "8.1", "", "", "", []string{"legacy.example.com", "old.example.com"}, false, 0},
		"/srv/worker":      {"/srv/worker", "", "", "laravel", "11.31.0", "^8.2", nil, true, 4},
		"/var/www/missing": {"/var/www/missing", "", "", "", "", "", nil, false, 0},
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			s, err := DecodeBytes(b)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]Site{}
			for _, site := range s.Sites {
				got[site.Root] = site
			}
			if len(got) != len(expect) {
				roots := make([]string, 0, len(got))
				for r := range got {
					roots = append(roots, r)
				}
				t.Errorf("found %d sites %v, want %d", len(got), roots, len(expect))
			}
			for root, w := range expect {
				site, ok := got[root]
				if !ok {
					t.Errorf("%s: not found", root)
					continue
				}
				if site.DocumentRoot != w.docroot || site.WebServer != w.web || site.PHPFPMVersion != w.php ||
					site.Framework != w.framework || site.FrameworkVersion != w.version || site.PHPRequirement != w.phpReq ||
					site.Readable != w.readable || len(site.ComposerPackages) != w.packages ||
					strings.Join(site.ServerNames, ",") != strings.Join(w.names, ",") {
					t.Errorf("%s:\n got %+v\nwant %+v", root, site, w)
				}
				if w.version != "" && site.DeployedAt == nil {
					t.Errorf("%s: deployed_at missing", root)
				}
			}
		})
	}
}
