// SPDX-License-Identifier: AGPL-3.0-or-later

package ecosystem

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/snapshot"
	"github.com/realmwatch/heimdall/internal/version"
)

func TestResolve(t *testing.T) {
	tests := []struct {
		id, ver, like, pm string
		want              string // "" means unsupported
	}{
		{"debian", "12", "", "dpkg", "Debian:12"},
		{"debian", "11", "", "dpkg", "Debian:11"},
		{"debian", "", "", "dpkg", ""}, // testing/sid has no VERSION_ID
		{"ubuntu", "22.04", "debian", "dpkg", "Ubuntu:22.04"},
		{"ubuntu", "24.04", "debian", "dpkg", "Ubuntu:24.04"},
		{"ubuntu", "24.10", "debian", "dpkg", "Ubuntu:24.10"},
		{"Ubuntu", " 22.04 ", "", "dpkg", "Ubuntu:22.04"},
		{"alpine", "3.20.10", "", "apk", "Alpine:v3.20"},
		{"alpine", "3.21.0", "", "apk", "Alpine:v3.21"},
		{"alpine", "3.20", "", "apk", "Alpine:v3.20"},
		{"alpine", "3.21_alpha20240807", "", "apk", ""}, // edge
		{"rocky", "9.3", "rhel centos fedora", "rpm", "Rocky Linux:9"},
		{"rocky", "8.10", "rhel centos fedora", "rpm", "Rocky Linux:8"},
		{"almalinux", "9.8", "rhel centos fedora", "rpm", "AlmaLinux:9"},
		{"rhel", "9.4", "fedora", "rpm", ""},
		{"centos", "9", "rhel fedora", "rpm", ""},
		{"fedora", "40", "", "rpm", ""},
		{"arch", "", "", "pacman", ""},
		// Wrong package manager for the distro.
		{"debian", "12", "", "rpm", ""},
		{"alpine", "3.20.1", "", "dpkg", ""},
		// Derivatives via ID_LIKE.
		{"raspbian", "12", "debian", "dpkg", "Debian:12"},
		{"pop", "22.04", "ubuntu debian", "dpkg", "Ubuntu:22.04"},
		{"linuxmint", "21.2", "ubuntu debian", "dpkg", ""},
		{"linuxmint", "6", "debian", "dpkg", ""}, // LMDE 6
		{"kali", "2024.1", "debian", "dpkg", ""},
		{"ol", "9.4", "fedora", "rpm", ""},
		{"", "", "", "", ""},
	}
	for _, tt := range tests {
		info, ok := Resolve(tt.id, tt.ver, tt.like, tt.pm)
		if got := map[bool]string{true: info.OSV, false: ""}[ok]; got != tt.want {
			t.Errorf("Resolve(%q, %q, %q, %q) = %q, %v; want %q", tt.id, tt.ver, tt.like, tt.pm, info.OSV, ok, tt.want)
		}
		if ok {
			want := map[string]version.Scheme{"dpkg": version.Dpkg, "rpm": version.RPM, "apk": version.APK}[tt.pm]
			if info.Scheme != want {
				t.Errorf("Resolve(%q, %q): scheme %q, want %q", tt.id, tt.ver, info.Scheme, want)
			}
		}
	}
}

func TestQueryFor(t *testing.T) {
	deb := Info{"Debian:12", version.Dpkg}
	rpm := Info{"Rocky Linux:9", version.RPM}
	apk := Info{"Alpine:v3.20", version.APK}
	tests := []struct {
		info              Info
		pkg               snapshot.Package
		wantName, wantVer string
	}{
		{deb, snapshot.Package{Name: "libssl3", Version: "3.0.14-1~deb12u2", SourceName: "openssl", SourceVersion: "3.0.14-1~deb12u2"},
			"openssl", "3.0.14-1~deb12u2"},
		// binNMU: binary version has +b1, source version doesn't.
		{deb, snapshot.Package{Name: "libfoo1", Version: "1.2-3+b1", SourceName: "foo", SourceVersion: "1.2-3"}, "foo", "1.2-3"},
		// Source fields empty when they equal the binary package.
		{deb, snapshot.Package{Name: "tzdata", Version: "2024a-0+deb12u1"}, "tzdata", "2024a-0+deb12u1"},
		{rpm, snapshot.Package{Name: "openssl-libs", Version: "1:3.0.7-24.el9", SourceName: "openssl", SourceVersion: "3.0.7-24.el9"},
			"openssl", "1:3.0.7-24.el9"},
		{rpm, snapshot.Package{Name: "gpg-pubkey", Version: "5a6340b3-6229229e"}, "gpg-pubkey", "5a6340b3-6229229e"},
		{apk, snapshot.Package{Name: "libssl3", Version: "3.3.2-r0", SourceName: "openssl"}, "openssl", "3.3.2-r0"},
		{apk, snapshot.Package{Name: "musl", Version: "1.2.5-r0", SourceName: "musl"}, "musl", "1.2.5-r0"},
	}
	for _, tt := range tests {
		n, v := QueryFor(tt.info, tt.pkg)
		if n != tt.wantName || v != tt.wantVer {
			t.Errorf("QueryFor(%s, %s) = %q, %q; want %q, %q", tt.info.OSV, tt.pkg.Name, n, v, tt.wantName, tt.wantVer)
		}
	}
}

// loadTSV reads name, version, arch, source_name, source_version rows
// recorded from real containers (see testdata).
func loadTSV(t *testing.T, name string) []snapshot.Package {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []snapshot.Package
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		c := strings.Split(sc.Text(), "\t")
		for len(c) < 5 {
			c = append(c, "")
		}
		out = append(out, snapshot.Package{Name: c[0], Version: c[1], Arch: c[2], SourceName: c[3], SourceVersion: c[4]})
	}
	return out
}

func format(rs []Runtime) string {
	var parts []string
	for _, r := range rs {
		parts = append(parts, fmt.Sprintf("%s %s (%s)", r.Name, r.Version, r.Package))
	}
	return strings.Join(parts, "; ")
}

func TestRuntimesFromRealPackages(t *testing.T) {
	tests := []struct {
		pm, file, want string
	}{
		{"dpkg", "ubuntu2204-runtimes.tsv",
			"nodejs 12.22.9 (nodejs); php 8.1.2 (php8.1-cli); python 3.10.12 (python3.10)"},
		{"rpm", "rocky9-runtimes.tsv",
			"nodejs 20.20.2 (nodejs); php 8.0.30 (php-cli); python 3.9.18 (python3); python 3.11.13 (python3.11)"},
		{"apk", "alpine320-runtimes.tsv",
			"nodejs 20.15.1 (nodejs); php 8.3.15 (php83); python 3.12.13 (python3)"},
	}
	for _, tt := range tests {
		if got := format(Runtimes(tt.pm, loadTSV(t, tt.file))); got != tt.want {
			t.Errorf("%s:\n got  %s\n want %s", tt.file, got, tt.want)
		}
	}
}

func TestRuntimesSideBySidePHP(t *testing.T) {
	// A Forge-style Ubuntu box with ondrej/sury PHP 8.1 (FPM only) and 8.3.
	pkgs := []snapshot.Package{
		{Name: "php-common", Version: "2:93+ubuntu22.04.1+deb.sury.org+3"},
		{Name: "php8.1-common", Version: "8.1.31-1+ubuntu22.04.1+deb.sury.org+1"},
		{Name: "php8.1-fpm", Version: "8.1.31-1+ubuntu22.04.1+deb.sury.org+1"},
		{Name: "php8.1-mbstring", Version: "8.1.31-1+ubuntu22.04.1+deb.sury.org+1"},
		{Name: "php8.3-cli", Version: "8.3.12-1+ubuntu22.04.1+deb.sury.org+1"},
		{Name: "php8.3-fpm", Version: "8.3.12-1+ubuntu22.04.1+deb.sury.org+1"},
		{Name: "php8.3-common", Version: "8.3.12-1+ubuntu22.04.1+deb.sury.org+1"},
		{Name: "phpmyadmin", Version: "4:5.1.1+dfsg1-5ubuntu1"},
		{Name: "libapache2-mod-php7.4", Version: "7.4.33-1+ubuntu22.04.1+deb.sury.org+1"},
	}
	want := "php 7.4.33 (libapache2-mod-php7.4); php 8.1.31 (php8.1-fpm); php 8.3.12 (php8.3-cli)"
	if got := format(Runtimes("dpkg", pkgs)); got != want {
		t.Errorf("\n got  %s\n want %s", got, want)
	}
}

func TestRuntimesFromCollectorOutput(t *testing.T) {
	// Base images ship Python on some distros; whatever is found must be
	// well-formed and never come from a metapackage or library.
	files, _ := os.ReadDir("../../bin/collector-out")
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile("../../bin/collector-out/" + f.Name())
		if err != nil {
			t.Fatal(err)
		}
		var s snapshot.Snapshot
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		for _, r := range Runtimes(s.PackageManager, s.Packages) {
			if upstream(r.Version) != r.Version || strings.HasPrefix(r.Package, "lib") {
				t.Errorf("%s: suspicious runtime %+v", f.Name(), r)
			}
		}
	}
}

func TestUpstream(t *testing.T) {
	for in, want := range map[string]string{
		"1:20.12.2-2.module+el9.4.0+20000+abcdef12": "20.12.2",
		"12.22.9~dfsg-1ubuntu3.6":                   "12.22.9",
		"8.3.12-1+ubuntu22.04.1+deb.sury.org+1":     "8.3.12",
		"8.3.15-r0":                                 "8.3.15",
		"3.9.18-1.el9_3":                            "3.9.18",
		"2:92ubuntu1":                               "92",
		"abc":                                       "",
	} {
		if got := upstream(in); got != want {
			t.Errorf("upstream(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRuntimesUnknownManager(t *testing.T) {
	if rs := Runtimes("pacman", []snapshot.Package{{Name: "php", Version: "8.3.0-1"}}); len(rs) != 0 {
		t.Errorf("got %v", rs)
	}
}
