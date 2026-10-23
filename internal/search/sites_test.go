// SPDX-License-Identifier: AGPL-3.0-or-later

package search

import (
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/snapshot"
	"github.com/chrisreedio/heimdall/internal/store"
)

func TestParseSites(t *testing.T) {
	tests := []struct {
		in   string
		want Query
	}{
		{"laravel", Query{Kind: KindFramework, Name: "laravel"}},
		{"Laravel < 11", Query{Kind: KindFramework, Name: "laravel", Op: "<", Version: "11"}},
		{"laravel = 10.48", Query{Kind: KindFramework, Name: "laravel", Op: "=", Version: "10.48"}},
		{"php-fpm = 8.1", Query{Kind: KindPHPFPM, Name: "php-fpm", Op: "=", Version: "8.1"}},
		{"fpm>=8.2", Query{Kind: KindPHPFPM, Name: "php-fpm", Op: ">=", Version: "8.2"}},
		{"php = 8.1", Query{Kind: KindRuntime, Name: "php", Op: "=", Version: "8.1"}}, // still the runtime search
		{"site:example", Query{Kind: KindSite, Name: "example"}},
		{"composer:guzzlehttp/guzzle < 7.9", Query{Kind: KindComposer, Name: "guzzlehttp/guzzle", Op: "<", Version: "7.9"}},
		{"Symfony/HTTP-Foundation", Query{Kind: KindComposer, Name: "symfony/http-foundation"}},
		{"laravel/framework == 11.31.0", Query{Kind: KindComposer, Name: "laravel/framework", Op: "=", Version: "11.31.0"}},
		{"pkg:laravel/framework", Query{Kind: KindPackage, Name: "laravel/framework"}}, // pkg: still forces OS packages
	}
	for _, tt := range tests {
		got, err := Parse(tt.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tt.in, err)
			continue
		}
		tt.want.Raw = strings.TrimSpace(tt.in)
		if got != tt.want {
			t.Errorf("Parse(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
	for _, bad := range []string{"site:", "site:a b", "php-fpm = 8.x", "composer:notapackage", "composer:a//b", "composer:"} {
		if q, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) = %+v, want error", bad, q)
		}
	}
}

func siteMatches(r *Result) string {
	var out []string
	for _, m := range r.Matches {
		out = append(out, m.Host+":"+m.Site+":"+m.Version)
	}
	return strings.Join(out, " ")
}

func siteFleet(t *testing.T) (*fleet, store.IngestHost) {
	f := newFleet(t)
	web := f.push("acme", "web-01", "debian12-v2.json", nil)
	// A second host with an older Laravel on PHP-FPM 8.1.
	f.push("acme", "web-02", "debian12-v2.json", func(s *snapshot.Snapshot) {
		s.Sites = s.Sites[:1]
		s.Sites[0].PHPFPMVersion = "8.1"
		s.Sites[0].FrameworkVersion = "10.48.22"
		s.Sites[0].ServerNames = []string{"shop.example.net"}
		for i := range s.Sites[0].ComposerPackages {
			if s.Sites[0].ComposerPackages[i].Name == "laravel/framework" {
				s.Sites[0].ComposerPackages[i].Version = "10.48.22"
			}
		}
	})
	return f, web
}

func TestFrameworkSearch(t *testing.T) {
	f, _ := siteFleet(t)
	if got := siteMatches(f.run("laravel")); got != "web-01:/home/forge/example.com:11.31.0 web-02:/home/forge/example.com:10.48.22" {
		t.Errorf("laravel: %s", got)
	}
	if got := siteMatches(f.run("laravel < 11")); got != "web-02:/home/forge/example.com:10.48.22" {
		t.Errorf("laravel < 11: %s", got)
	}
	if got := siteMatches(f.run("laravel = 11")); got != "web-01:/home/forge/example.com:11.31.0" {
		t.Errorf("laravel = 11: %s", got)
	}
	if got := siteMatches(f.run("laravel = 10.48")); got != "web-02:/home/forge/example.com:10.48.22" {
		t.Errorf("laravel = 10.48: %s", got)
	}
	if got := siteMatches(f.run("laravel = 10.4")); got != "" {
		t.Errorf("laravel = 10.4 must not match 10.48: %s", got)
	}
	r := f.run("laravel >= 11.31.0")
	if got := siteMatches(r); got != "web-01:/home/forge/example.com:11.31.0" {
		t.Errorf("laravel >= 11.31.0: %s", got)
	}
	if d := r.Matches[0].Detail; !strings.Contains(d, "example.com") || !strings.Contains(d, "PHP-FPM 8.3") {
		t.Errorf("detail = %q", d)
	}
}

func TestPHPFPMSearch(t *testing.T) {
	f, _ := siteFleet(t)
	if got := siteMatches(f.run("php-fpm = 8.1")); got != "web-01:/var/www/legacy:8.1 web-02:/home/forge/example.com:8.1" {
		t.Errorf("php-fpm = 8.1: %s", got)
	}
	if got := siteMatches(f.run("fpm > 8.2")); got != "web-01:/home/forge/example.com:8.3" {
		t.Errorf("fpm > 8.2: %s", got)
	}
	// Sites with no known PHP-FPM version never match.
	if got := siteMatches(f.run("php-fpm")); strings.Contains(got, "/var/www/html") {
		t.Errorf("php-fpm (any): %s", got)
	}
}

func TestSiteFragmentSearch(t *testing.T) {
	f, _ := siteFleet(t)
	if got := siteMatches(f.run("site:legacy")); got != "web-01:/var/www/legacy:" {
		t.Errorf("site:legacy: %s", got)
	}
	if got := siteMatches(f.run("site:EXAMPLE.NET")); got != "web-02:/home/forge/example.com:" {
		t.Errorf("site:EXAMPLE.NET: %s", got)
	}
	if got := siteMatches(f.run("site:forge")); got != "web-01:/home/forge/example.com: web-02:/home/forge/example.com:" {
		t.Errorf("site:forge (root): %s", got)
	}
}

func TestComposerSearch(t *testing.T) {
	f, _ := siteFleet(t)
	if got := siteMatches(f.run("laravel/framework < 11")); got != "web-02:/home/forge/example.com:10.48.22" {
		t.Errorf("laravel/framework < 11: %s", got)
	}
	r := f.run("composer:guzzlehttp/guzzle")
	if got := siteMatches(r); got != "web-01:/home/forge/example.com:7.9.2 web-02:/home/forge/example.com:7.9.2" {
		t.Errorf("guzzle: %s", got)
	}
	if !strings.Contains(r.Matches[0].Detail, "/home/forge/example.com/composer.lock") {
		t.Errorf("detail = %q", r.Matches[0].Detail)
	}
	if got := siteMatches(f.run("guzzlehttp/guzzle >= 7.10")); got != "" {
		t.Errorf("guzzle >= 7.10: %s", got)
	}
	if got := siteMatches(f.run("laravel/framework = 11")); got != "web-01:/home/forge/example.com:11.31.0" {
		t.Errorf("laravel/framework = 11: %s", got)
	}
}

func TestCVESearchHitsSiteFindings(t *testing.T) {
	f, web := siteFleet(t)
	ctx := t.Context()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	if err := f.st.PutAdvisory(ctx, store.Advisory{ID: "GHSA-78fx-h6xr-vch4", Modified: now, Summary: "Laravel file validation bypass",
		Severity: "medium", Raw: []byte("{}"), Aliases: []string{"CVE-2025-27515"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.st.SetFindings(ctx, web.ID, []store.Finding{{
		AdvisoryID: "GHSA-78fx-h6xr-vch4", Ecosystem: "Packagist", Package: "laravel/framework", Version: "11.31.0",
		Binaries: []string{"laravel/framework"}, FixedVersion: "11.44.1", SiteRoot: "/home/forge/example.com",
	}}, now); err != nil {
		t.Fatal(err)
	}
	r := f.run("CVE-2025-27515")
	if len(r.Matches) != 1 {
		t.Fatalf("matches = %+v", r.Matches)
	}
	m := r.Matches[0]
	if m.Host != "web-01" || m.Site != "/home/forge/example.com" || m.Name != "laravel/framework" {
		t.Errorf("match = %+v", m)
	}
	if !strings.Contains(m.Detail, "fixed in 11.44.1") || !strings.Contains(m.Detail, "in site /home/forge/example.com") {
		t.Errorf("detail = %q", m.Detail)
	}
}
