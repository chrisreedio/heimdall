// SPDX-License-Identifier: AGPL-3.0-or-later

package handoff

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// threeSites is one repository deployed from three branches, plus a site
// with an unknown branch and one with nothing of this hand-off to fix.
func threeSites() Request {
	req := testRequest()
	prod := req.Findings
	staging := []Finding{
		{Ecosystem: "composer", Package: "laravel/framework", Installed: "11.40.0", Fixed: "11.44.1", Advisory: "GHSA-aaaa-bbbb-cccc"},
		{Ecosystem: "npm", Package: "@babel/core", Installed: "7.25.0", Fixed: "7.26.10", Advisory: "GHSA-4444-5555-6666",
			Lockfile: "/home/forge/staging.example.com/package-lock.json"},
		{Ecosystem: "composer", Package: "other/pkg", Installed: "1.0.0", Fixed: "1.0.1", Advisory: "GHSA-zzzz-zzzz-zzzz"},
	}
	beta := []Finding{{Ecosystem: "composer", Package: "guzzlehttp/guzzle", Installed: "7.9.0", Fixed: "7.9.3", Advisory: "GHSA-1111-2222-3333"}}
	req.Sites = []Site{
		{Host: "app-01", Site: "example.com", SitePath: "/home/forge/example.com", Label: "production", Branch: "main", Findings: prod},
		{Host: "staging-01", Site: "staging.example.com", SitePath: "/home/forge/staging.example.com", Label: "staging", Branch: "dev", Findings: staging},
		{Host: "staging-01", Site: "beta.example.com", SitePath: "/home/forge/beta.example.com/current", Label: "development", Branch: "env/beta", Findings: beta},
		{Host: "web-02", Site: "old.example.com", SitePath: "/home/forge/old.example.com/current", Label: "bogus",
			Commit: strings.Repeat("ab", 20), Findings: beta},
		{Host: "web-03", Site: "clean.example.com", SitePath: "/var/www/clean", Branch: "main",
			Findings: []Finding{{Ecosystem: "composer", Package: "other/pkg", Installed: "1.0.0", Fixed: "1.0.1", Advisory: "X"}}},
		{Host: "web-04", Site: "bad", SitePath: "relative", Branch: "main", Findings: prod},
	}
	return req
}

func fileOf(t *testing.T, m Message) FileData {
	t.Helper()
	var f FileData
	dec := json.NewDecoder(strings.NewReader(string(m.File)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("file: %v\n%s", err, m.File)
	}
	return f
}

func TestBuildSites(t *testing.T) {
	m, err := Build(Agent{UserID: testUser}, threeSites())
	if err != nil {
		t.Fatal(err)
	}
	f := fileOf(t, m)
	var got []string
	for _, s := range f.Sites {
		b := "null"
		if s.Branch != nil {
			b = *s.Branch
		}
		got = append(got, s.Host+" "+s.SitePath+" "+b+" "+s.Label)
	}
	want := []string{
		"app-01 /home/forge/example.com main production",
		"staging-01 /home/forge/staging.example.com dev staging",
		"staging-01 /home/forge/beta.example.com/current env/beta development",
		"web-02 /home/forge/old.example.com/current null ", // a detached HEAD: its commit, no branch; a bad label dropped
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sites:\n got %q\nwant %q", got, want)
	}
	if f.Sites[3].Commit != strings.Repeat("ab", 20) {
		t.Errorf("detached commit: %+v", f.Sites[3])
	}
	// Each site's own installed versions of the hand-off's packages only,
	// npm matched by the lockfile's place in the site.
	st := f.Sites[1].Installed
	if len(st) != 2 || st[0] != (Installed{Ecosystem: "composer", Name: "laravel/framework", Installed: "11.40.0"}) ||
		st[1] != (Installed{Ecosystem: "npm", Name: "@babel/core", Installed: "7.25.0", Lockfile: "/home/forge/staging.example.com/package-lock.json"}) {
		t.Errorf("staging installed: %+v", st)
	}
	if len(f.Sites[0].Installed) != 3 {
		t.Errorf("own site installed: %+v", f.Sites[0].Installed)
	}
	// The message block lists them too (without versions) and says how many.
	d := block(t, m.Content)
	if len(d.Sites) != 4 || d.Sites[1].Installed != nil || d.Host != "app-01" || d.SitePath != "/home/forge/example.com" {
		t.Errorf("block sites: %+v", d.Sites)
	}
	if !strings.Contains(m.Content, "4 sites, 3 branches and 1 unknown (`sites`).") {
		t.Errorf("content doesn't count the sites: %q", m.Content)
	}
}

func TestBuildTargets(t *testing.T) {
	id := "0123456789abcdef"
	ptr := func(s string) *string { return &s }
	cases := []struct {
		target    Target
		want      TargetData
		suggested string
		prose     string
		step      string
	}{
		{Target{}, TargetData{Mode: "default", Branches: []string{}, PullRequests: []PullRequest{{SuggestedBranch: "heimdall/security-" + id}}},
			"heimdall/security-" + id, "against the default branch", "this pull request targets the default branch only"},
		{Target{Mode: TargetBranch, Branches: []string{"env/beta"}}, TargetData{Mode: "branch", Branches: []string{"env/beta"},
			PullRequests: []PullRequest{{Base: ptr("env/beta"), SuggestedBranch: "heimdall/security-" + id + "-env-beta"}}},
			"heimdall/security-" + id + "-env-beta", "against the branch in `target.branches`, not the default branch", "check out the branch in `target.branches`"},
		// Each known branch, sorted; the detached site (no branch) isn't targeted.
		{Target{Mode: TargetEach}, TargetData{Mode: "each", Branches: []string{"dev", "env/beta", "main"}, PullRequests: []PullRequest{
			{Base: ptr("dev"), SuggestedBranch: "heimdall/security-" + id + "-dev"},
			{Base: ptr("env/beta"), SuggestedBranch: "heimdall/security-" + id + "-env-beta"},
			{Base: ptr("main"), SuggestedBranch: "heimdall/security-" + id + "-main"}}},
			"", "Open one pull request per branch in `target.branches` (3)", "once for each entry in `target.pull_requests`"},
	}
	digests := map[string]bool{}
	for _, c := range cases {
		req := threeSites()
		req.Target = c.target
		m, err := Build(Agent{UserID: testUser}, req)
		if err != nil {
			t.Fatalf("%+v: %v", c.target, err)
		}
		f := fileOf(t, m)
		if !reflect.DeepEqual(f.Target, c.want) || !reflect.DeepEqual(block(t, m.Content).Target, TargetData{Mode: c.want.Mode, Branches: c.want.Branches}) {
			t.Errorf("%s target:\n got %+v\nwant %+v", c.want.Mode, f.Target, c.want)
		}
		if f.SuggestedBranch != c.suggested {
			t.Errorf("%s suggested_branch %q", c.want.Mode, f.SuggestedBranch)
		}
		if !strings.Contains(m.Content, c.prose) || !strings.Contains(f.Steps[0], c.step) {
			t.Errorf("%s: content %q\nstep %q", c.want.Mode, m.Content, f.Steps[0])
		}
		// The digest covers the target: each mode's differs.
		digests[m.Digest] = true
	}
	if len(digests) != len(cases) {
		t.Error("the digest doesn't change with the target")
	}
	// Two branches with one slug still get distinct pull request branches.
	req := threeSites()
	req.Sites[3].Branch = "env-beta"
	req.Target = Target{Mode: TargetEach}
	m, _ := Build(Agent{UserID: testUser}, req)
	seen := map[string]bool{}
	for _, pr := range fileOf(t, m).Target.PullRequests {
		if seen[pr.SuggestedBranch] {
			t.Errorf("duplicate branch %s", pr.SuggestedBranch)
		}
		seen[pr.SuggestedBranch] = true
	}
}

// A branch the sites don't have, any text that isn't a branch, and "each"
// with no known branch are refused.
func TestBuildTargetInvalid(t *testing.T) {
	for _, tg := range []Target{
		{Mode: TargetBranch, Branches: []string{"release"}},
		{Mode: TargetBranch, Branches: []string{"main; reboot"}},
		{Mode: TargetBranch, Branches: []string{"main", "dev"}},
		{Mode: TargetBranch},
		{Mode: TargetDefault, Branches: []string{"main"}},
		{Mode: "all"},
	} {
		req := threeSites()
		req.Target = tg
		if _, err := Build(Agent{UserID: testUser}, req); !errors.Is(err, ErrTarget) {
			t.Errorf("%+v: %v", tg, err)
		}
	}
	// No known branch (one site, from before branches were reported).
	req := testRequest()
	req.Target = Target{Mode: TargetEach}
	if _, err := Build(Agent{UserID: testUser}, req); !errors.Is(err, ErrTarget) {
		t.Errorf("each with no branches: %v", err)
	}
	if b := Branches(threeSites().Sites); !reflect.DeepEqual(b, []string{"dev", "env/beta", "main"}) {
		t.Errorf("Branches = %v", b)
	}
}

// With many sites, packages are kept and the last sites are left out of
// the block (the file has them all), and the text says so.
func TestBuildSitesFit(t *testing.T) {
	req := threeSites()
	for i := range 30 {
		req.Sites = append(req.Sites, Site{Host: fmt.Sprintf("web-%02d", 10+i), Site: fmt.Sprintf("site-%02d.example.com", i),
			SitePath: fmt.Sprintf("/var/www/site-%02d", i), Branch: "main", Findings: req.Sites[0].Findings})
	}
	m, err := Build(Agent{UserID: testUser}, req)
	if err != nil {
		t.Fatal(err)
	}
	d, f := block(t, m.Content), fileOf(t, m)
	if m.Omitted != 0 || d.OmittedSites == 0 || len(d.Sites)+d.OmittedSites != len(f.Sites) || len(f.Sites) != 34 {
		t.Errorf("omitted %d packages, block %d sites + %d omitted, file %d", m.Omitted, len(d.Sites), d.OmittedSites, len(f.Sites))
	}
	if !strings.Contains(m.Content, fmt.Sprintf("%d more sites didn't fit", d.OmittedSites)) || utf8.RuneCountInString(m.Content) > MaxContent {
		t.Errorf("content: %q", m.Content)
	}
}
