// SPDX-License-Identifier: AGPL-3.0-or-later

package snapshot

import (
	"strconv"
	"strings"
	"testing"
)

// v4Site is the Debian v2 example as v4, its first site with npm packages,
// then fn applied.
func v4Site(t *testing.T, fn func(*Snapshot)) []byte {
	t.Helper()
	return mutateV2(t, func(s *Snapshot) {
		s.Format = FormatV4
		s.Containers, s.Lockfiles = []Container{}, []Lockfile{}
		s.Sites[0].NpmPackages = []NpmPackage{
			{Name: "axios", Version: "1.7.2"},
			{Name: "@vitejs/plugin-vue", Version: "5.0.4", Dev: true},
			// Nested node_modules: the same name at another version.
			{Name: "semver", Version: "6.3.1", Dev: true},
			{Name: "semver", Version: "7.6.0"},
		}
		if fn != nil {
			fn(s)
		}
	})
}

func TestV4NpmPackages(t *testing.T) {
	s, err := DecodeBytes(v4Site(t, nil))
	if err != nil {
		t.Fatalf("valid v4: %v", err)
	}
	if got := s.Sites[0].NpmPackages; len(got) != 4 || !got[1].Dev || got[0].Dev {
		t.Errorf("npm packages: %+v", got)
	}

	for name, fn := range map[string]func(*Snapshot){
		"no npm packages": func(s *Snapshot) { s.Sites[0].NpmPackages = nil },
		"empty npm list":  func(s *Snapshot) { s.Sites[0].NpmPackages = []NpmPackage{} },
		"prerelease":      func(s *Snapshot) { s.Sites[0].NpmPackages[0].Version = "2.0.0-beta.1" },
		"lockfiles too": func(s *Snapshot) {
			s.Lockfiles = []Lockfile{{Path: "/srv/js/package-lock.json", Ecosystem: "npm", Packages: []ComposerPackage{}}}
		},
		"unreadable site, no packages": func(s *Snapshot) { s.Sites[0] = Site{Root: "/srv/locked", ServerNames: []string{}} },
	} {
		if _, err := DecodeBytes(v4Site(t, fn)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	for name, fn := range map[string]func(*Snapshot){
		"duplicate":   func(s *Snapshot) { s.Sites[0].NpmPackages[3].Version = "6.3.1" },
		"bad name":    func(s *Snapshot) { s.Sites[0].NpmPackages[0].Name = "Axios;rm -rf" },
		"uppercase":   func(s *Snapshot) { s.Sites[0].NpmPackages[0].Name = "Axios" },
		"range":       func(s *Snapshot) { s.Sites[0].NpmPackages[0].Version = "^1.7.2" },
		"git version": func(s *Snapshot) { s.Sites[0].NpmPackages[0].Version = "github:acme/x#main" },
		"unreadable": func(s *Snapshot) {
			site := &s.Sites[0]
			site.Readable, site.Framework, site.FrameworkVersion = false, "", ""
			site.PHPRequirement, site.DeployedAt, site.ComposerPackages = "", nil, nil
		},
		"too many": func(s *Snapshot) {
			s.Sites[0].NpmPackages = make([]NpmPackage, MaxNpmPackages+1)
			for i := range s.Sites[0].NpmPackages {
				s.Sites[0].NpmPackages[i] = NpmPackage{Name: "p", Version: "1.0." + strconv.Itoa(i)}
			}
		},
		"missing v3 lists": func(s *Snapshot) { s.Containers, s.Lockfiles = nil, nil },
	} {
		if _, err := DecodeBytes(v4Site(t, fn)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// Before v4, npm_packages must be absent.
	for _, f := range []string{FormatV2, FormatV3} {
		b := v4Site(t, func(s *Snapshot) {
			s.Format = f
			if f == FormatV2 {
				s.Containers, s.Lockfiles = nil, nil
			}
		})
		if _, err := DecodeBytes(b); err == nil || !strings.Contains(err.Error(), "npm_packages") {
			t.Errorf("%s with npm_packages: %v", f, err)
		}
	}
}

// A site's npm packages count as inventory, in any order; documents
// without them hash as they did before v4.
func TestInventoryHashNpm(t *testing.T) {
	decode := func(b []byte) *Snapshot {
		s, err := DecodeBytes(b)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	base := decode(v4Site(t, nil)).InventoryHash()
	reordered := decode(v4Site(t, func(s *Snapshot) {
		p := s.Sites[0].NpmPackages
		p[0], p[3] = p[3], p[0]
	})).InventoryHash()
	if reordered != base {
		t.Error("npm package order changed the hash")
	}
	if decode(v4Site(t, func(s *Snapshot) { s.Sites[0].NpmPackages[0].Dev = true })).InventoryHash() == base {
		t.Error("dev flag didn't change the hash")
	}
	if decode(v4Site(t, func(s *Snapshot) { s.Sites[0].NpmPackages[0].Version = "1.7.3" })).InventoryHash() == base {
		t.Error("npm version didn't change the hash")
	}
	if strings.Contains(string(mutateV2(t, func(*Snapshot) {})), "npm_packages") {
		t.Error("a v2 document gained npm_packages when re-encoded")
	}
}
