// SPDX-License-Identifier: AGPL-3.0-or-later

package snapshot

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestCollectorNpmLockfiles runs the collector over sites holding the
// package-lock.json fixtures in testdata/npm (lockfileVersion 1, 2 and 3,
// and a malformed one) and checks what it reports for each, dev flags
// included. The same parser reads allowlisted lockfiles (HEIMDALL_LOCKFILES).
func TestCollectorNpmLockfiles(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	var roots []string
	for _, name := range []string{"v1", "v2", "v3", "malformed", "unreadable", "none"} {
		root := filepath.Join(dir, name)
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, root)
		src := name
		switch name {
		case "none":
			continue
		case "unreadable":
			src = "v3"
		}
		b, err := os.ReadFile(filepath.Join("testdata/npm", src, "package-lock.json"))
		if err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if name == "unreadable" {
			mode = 0
		}
		if err := os.WriteFile(filepath.Join(root, "package-lock.json"), b, mode); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command("sh", "../../collector/collect.sh", "--print")
	cmd.Env = append(os.Environ(), "HEIMDALL_DISCOVER_SITES=0", "HEIMDALL_SITES="+strings.Join(roots, " "),
		"HEIMDALL_LOCKFILES="+filepath.Join(dir, "v1", "package-lock.json"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("collect.sh --print: %v", err)
	}
	s, err := DecodeBytes(out)
	if err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if s.Format != FormatV4 {
		t.Errorf("format %s", s.Format)
	}

	pkgs := func(list []NpmPackage) []string {
		var out []string
		for _, p := range list {
			e := p.Name + "@" + p.Version
			if p.Dev {
				e += " dev"
			}
			out = append(out, e)
		}
		slices.Sort(out)
		return out
	}
	want := map[string][]string{
		// Nested dependencies, dev flags; git and alias versions dropped.
		"v1": {"@babel/code-frame@7.12.13 dev", "jquery@3.4.1", "laravel-mix@6.0.49 dev", "lru-cache@6.0.0 dev",
			"semver@5.7.1", "semver@7.3.5 dev"},
		// "packages" wins over the v1-compatible "dependencies".
		"v2": {"laravel-vite-plugin@1.0.1 dev", "lodash@4.17.20", "picocolors@1.0.0 dev"},
		// devOptional counts as runtime; semver 7.5.4 is dev in one place
		// only, so it isn't dev; an alias reports its real name; links,
		// workspace folders, git versions and bad names or versions are left out.
		"v3": {"@esbuild/linux-x64@0.19.11 dev", "axios@1.6.0", "esbuild@0.19.11", "follow-redirects@1.15.4",
			"semver@6.3.0 dev", "semver@7.5.4", "string-width@4.2.3", "vite@5.0.10 dev"},
		"malformed": nil,
		"none":      nil,
	}
	if os.Geteuid() != 0 { // root reads it anyway
		want["unreadable"] = nil
	}
	got := map[string]Site{}
	for _, site := range s.Sites {
		got[filepath.Base(site.Root)] = site
	}
	for name, w := range want {
		site, ok := got[name]
		if !ok {
			t.Errorf("%s: site not reported", name)
			continue
		}
		if !site.Readable {
			t.Errorf("%s: not readable", name)
		}
		if g := pkgs(site.NpmPackages); !slices.Equal(g, w) {
			t.Errorf("%s:\n got %q\nwant %q", name, g, w)
		}
	}

	if len(s.Lockfiles) != 1 || s.Lockfiles[0].Ecosystem != "npm" || len(s.Lockfiles[0].Packages) != len(want["v1"]) {
		t.Errorf("allowlisted v1 lockfile: %+v", s.Lockfiles)
	}
}
