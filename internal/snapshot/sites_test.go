// SPDX-License-Identifier: AGPL-3.0-or-later

package snapshot

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// mutateV2 decodes the Debian v2 example, applies fn, and re-encodes it.
func mutateV2(t *testing.T, fn func(*Snapshot)) []byte {
	t.Helper()
	var s Snapshot
	if err := json.Unmarshal(load(t, "debian12-v2.json"), &s); err != nil {
		t.Fatal(err)
	}
	fn(&s)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeV2(t *testing.T) {
	s, err := DecodeBytes(load(t, "debian12-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Format != FormatV2 || len(s.Sites) != 3 {
		t.Fatalf("format %q, %d sites", s.Format, len(s.Sites))
	}
	site := s.Sites[0]
	if site.Framework != "laravel" || site.FrameworkVersion != "11.31.0" || site.PHPFPMVersion != "8.3" ||
		len(site.ComposerPackages) != 4 || site.DeployedAt == nil {
		t.Errorf("site = %+v", site)
	}
}

func TestV1StillDecodes(t *testing.T) {
	for _, name := range []string{"debian12.json", "alpine320.json"} {
		s, err := DecodeBytes(load(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s.Format != FormatV1 || s.Sites != nil {
			t.Errorf("%s: format %q sites %v", name, s.Format, s.Sites)
		}
	}
}

func TestV1RejectsSites(t *testing.T) {
	b := mutate(t, func(s *Snapshot) { s.Sites = []Site{} })
	if _, err := DecodeBytes(b); err == nil || !strings.Contains(err.Error(), "sites:") {
		t.Fatalf("want sites error, got %v", err)
	}
	b = mutate(t, func(s *Snapshot) { s.Unavailable = []string{"sites"} })
	if _, err := DecodeBytes(b); err == nil {
		t.Fatal("v1 must not declare sites unavailable")
	}
}

func TestV2SitesRules(t *testing.T) {
	when := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		fn    func(*Snapshot)
		field string
	}{
		{"sites missing", func(s *Snapshot) { s.Sites = nil }, "sites"},
		{"too many sites", func(s *Snapshot) {
			s.Sites = make([]Site, MaxSites+1)
		}, "sites"},
		{"declared unavailable but present", func(s *Snapshot) { s.Unavailable = []string{"sites"} }, "sites"},
		{"relative root", func(s *Snapshot) { s.Sites[0].Root = "home/forge/example.com" }, "sites[0].root"},
		{"dotdot root", func(s *Snapshot) { s.Sites[0].Root = "/home/forge/../etc" }, "sites[0].root"},
		{"space in root", func(s *Snapshot) { s.Sites[0].Root = "/home/forge/my site" }, "sites[0].root"},
		{"control char docroot", func(s *Snapshot) { s.Sites[0].DocumentRoot = "/var/www/\x1b" }, "sites[0].document_root"},
		{"duplicate root", func(s *Snapshot) { s.Sites[1].Root = s.Sites[0].Root }, "sites[1].root"},
		{"uppercase server name", func(s *Snapshot) { s.Sites[0].ServerNames = []string{"Example.com"} }, "sites[0].server_names[0]"},
		{"server name with port", func(s *Snapshot) { s.Sites[0].ServerNames = []string{"example.com:80"} }, "sites[0].server_names[0]"},
		{"html server name", func(s *Snapshot) { s.Sites[0].ServerNames = []string{"<b>x</b>"} }, "sites[0].server_names[0]"},
		{"too many server names", func(s *Snapshot) {
			s.Sites[0].ServerNames = make([]string, MaxServerNames+1)
			for i := range s.Sites[0].ServerNames {
				s.Sites[0].ServerNames[i] = "a.example.com"
			}
		}, "sites[0].server_names"},
		{"unknown web server", func(s *Snapshot) { s.Sites[0].WebServer = "caddy" }, "sites[0].web_server"},
		{"bad php version", func(s *Snapshot) { s.Sites[0].PHPFPMVersion = "8.3.12" }, "sites[0].php_fpm_version"},
		{"unknown framework", func(s *Snapshot) { s.Sites[0].Framework = "symfony" }, "sites[0].framework"},
		{"bad framework version", func(s *Snapshot) { s.Sites[0].FrameworkVersion = "11 beta" }, "sites[0].framework_version"},
		{"bad php requirement", func(s *Snapshot) { s.Sites[0].PHPRequirement = "^8.2; rm -rf /" }, "sites[0].php_requirement"},
		{"implausible deploy time", func(s *Snapshot) { s.Sites[0].DeployedAt = &when }, "sites[0].deployed_at"},
		{"unreadable with data", func(s *Snapshot) { s.Sites[0].Readable = false }, "sites[0]"},
		{"bad composer name", func(s *Snapshot) { s.Sites[0].ComposerPackages[0].Name = "Laravel/Framework" }, "sites[0].composer_packages[0].name"},
		{"composer name without vendor", func(s *Snapshot) { s.Sites[0].ComposerPackages[0].Name = "framework" }, "sites[0].composer_packages[0].name"},
		{"bad composer version", func(s *Snapshot) { s.Sites[0].ComposerPackages[0].Version = "v11 .0" }, "sites[0].composer_packages[0].version"},
		{"duplicate composer package", func(s *Snapshot) {
			s.Sites[0].ComposerPackages = append(s.Sites[0].ComposerPackages, s.Sites[0].ComposerPackages[0])
		}, "sites[0].composer_packages[4]"},
		{"too many composer packages", func(s *Snapshot) {
			s.Sites[0].ComposerPackages = make([]ComposerPackage, MaxComposerPackages+1)
		}, "sites[0].composer_packages"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeBytes(mutateV2(t, tt.fn))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.field+":") {
				t.Errorf("error should name %s, got: %v", tt.field, err)
			}
		})
	}
}

func TestV2SitesAllowed(t *testing.T) {
	ok := []struct {
		name string
		fn   func(*Snapshot)
	}{
		{"no sites", func(s *Snapshot) { s.Sites = []Site{} }},
		{"sites unavailable", func(s *Snapshot) { s.Sites, s.Unavailable = nil, []string{"sites"} }},
		{"wildcard and catch-all names", func(s *Snapshot) { s.Sites[0].ServerNames = []string{"*.example.com", "_", "localhost"} }},
		{"dev branch version", func(s *Snapshot) { s.Sites[0].ComposerPackages[1].Version = "dev-main" }},
		{"complex php requirement", func(s *Snapshot) { s.Sites[0].PHPRequirement = ">=8.1 <8.4 || ^8.4" }},
	}
	for _, tt := range ok {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeBytes(mutateV2(t, tt.fn)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestV3ContainersAndLockfiles(t *testing.T) {
	b := mutate(t, func(s *Snapshot) {
		s.Format = FormatV3
		s.Sites = []Site{}
		s.Containers = []Container{{Name: "web", Image: "nginx", Tag: "1.27", State: "running",
			Digest: "sha256:" + strings.Repeat("a", 64)}}
		s.Lockfiles = []Lockfile{
			{Path: "/srv/app/package-lock.json", Ecosystem: "npm", Packages: []ComposerPackage{{Name: "@babel/core", Version: "7.24.0"}, {Name: "lodash", Version: "4.17.21"}}},
			{Path: "/srv/app/requirements.txt", Ecosystem: "PyPI", Packages: []ComposerPackage{{Name: "Django", Version: "4.2.11"}}},
		}
	})
	if _, err := DecodeBytes(b); err != nil {
		t.Fatalf("valid v3: %v", err)
	}
	bad := map[string]func(*Snapshot){
		"v2 with containers": func(s *Snapshot) {
			s.Format = FormatV2
			s.Sites = []Site{}
			s.Containers = []Container{{Name: "x", Image: "nginx"}}
		},
		"bad image": func(s *Snapshot) {
			s.Format = FormatV3
			s.Sites = []Site{}
			s.Lockfiles = []Lockfile{}
			s.Containers = []Container{{Name: "x", Image: "NGINX;rm"}}
		},
		"bad ecosystem": func(s *Snapshot) {
			s.Format = FormatV3
			s.Sites, s.Containers = []Site{}, []Container{}
			s.Lockfiles = []Lockfile{{Path: "/a/go.sum", Ecosystem: "Go"}}
		},
		"missing containers": func(s *Snapshot) { s.Format = FormatV3; s.Sites = []Site{}; s.Lockfiles = []Lockfile{} },
	}
	for name, fn := range bad {
		if _, err := DecodeBytes(mutate(t, fn)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWindowsPackageNames(t *testing.T) {
	win := func(name string) []byte {
		return mutate(t, func(s *Snapshot) {
			s.Format, s.PackageManager = FormatV3, "windows"
			s.Sites, s.Containers, s.Lockfiles = []Site{}, []Container{}, []Lockfile{}
			s.Packages = []Package{{Name: name, Version: "14.38.33130"}}
			s.Updates = nil
		})
	}
	if _, err := DecodeBytes(win("Microsoft Visual C++ 2022 X64 Runtime (v14.38)")); err != nil {
		t.Fatalf("windows name rejected: %v", err)
	}
	if _, err := DecodeBytes(win("<script>alert(1)</script>")); err == nil {
		t.Error("markup in a windows name accepted")
	}
}
