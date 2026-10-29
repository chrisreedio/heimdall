// SPDX-License-Identifier: AGPL-3.0-or-later

package handoff

import (
	"cmp"
	"errors"
	"slices"
	"strconv"
	"strings"
)

// Site is one site that deploys the hand-off's repository, with its own
// fixable findings, for the message's sites list. The first of
// Request.Sites is the hand-off's own site (Host, SitePath).
type Site struct {
	Host, Site, SitePath string
	Label                string // production, staging, development or ""
	Branch               string // its checked-out branch, "" when unknown
	Commit               string // a detached HEAD's commit, when Branch is ""
	Findings             []Finding
}

// MaxSites caps the sites a message lists.
const MaxSites = 50

// SiteEntry is one site in the JSON block and the file.
type SiteEntry struct {
	Host     string  `json:"host"`
	Site     string  `json:"site"`
	SitePath string  `json:"site_path,omitempty"` // only in the file
	Label    string  `json:"label,omitempty"`
	Branch   *string `json:"branch"`           // null when unknown
	Commit   string  `json:"commit,omitempty"` // a detached HEAD; only in the file
	// Installed is the site's installed version of each of the hand-off's
	// packages that it has a fixable finding in. Only in the file: the
	// message's block has the hand-off's own site's, in packages.
	Installed []Installed `json:"installed,omitempty"`
}

// Installed is a package's installed version on one site.
type Installed struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Installed string `json:"installed"`
	Lockfile  string `json:"lockfile,omitempty"`
}

// Target modes: where the pull request goes.
const (
	TargetDefault = "default" // one pull request against the default branch
	TargetBranch  = "branch"  // one against a chosen site branch
	TargetEach    = "each"    // one per distinct known branch
)

// Target is where the pull request (or requests) go. Branches is the one
// branch for TargetBranch; it's ignored otherwise (TargetEach takes every
// known branch).
type Target struct {
	Mode     string
	Branches []string
}

// TargetData is the target in the JSON block and the file.
type TargetData struct {
	Mode     string   `json:"mode"`
	Branches []string `json:"branches"`
	// PullRequests is each pull request to open, only in the file.
	PullRequests []PullRequest `json:"pull_requests,omitempty"`
}

// PullRequest is one pull request to open: from SuggestedBranch, against
// Base (null: the repository's default branch).
type PullRequest struct {
	Base            *string `json:"base"`
	SuggestedBranch string  `json:"suggested_branch"`
}

// ErrTarget is returned for a target that isn't one of the sites' known
// branches.
var ErrTarget = errors.New("handoff: the target branch isn't one of the sites' known branches")

// Branches is the distinct valid branches of sites, sorted: what "one
// branch" may pick from and "each branch" targets.
func Branches(sites []Site) []string {
	var out []string
	for _, s := range sites {
		if ValidBranch(s.Branch) && !slices.Contains(out, s.Branch) {
			out = append(out, s.Branch)
		}
	}
	slices.Sort(out)
	return out
}

// pkgKey matches a package across sites: an npm lockfile by its path
// inside the site, since each site has its own copy.
func pkgKey(eco, name, lockfile, sitePath string) string {
	if lockfile != "" {
		lockfile = strings.TrimPrefix(lockfile, strings.TrimSuffix(sitePath, "/")+"/")
	}
	return eco + "\x00" + lockfile + "\x00" + name
}

var siteLabels = []string{"production", "staging", "development"}

// siteEntries validates the sites and keeps those with a fixable finding
// in pkgs (the hand-off's packages, from the first site), each with its
// installed versions. The hand-off's own site is always first.
func siteEntries(req Request, pkgs []Package) []SiteEntry {
	sites := req.Sites
	if len(sites) == 0 || sites[0].Host != req.Host || sites[0].SitePath != req.SitePath {
		sites = append([]Site{{Host: req.Host, Site: req.Site, SitePath: req.SitePath, Findings: req.Findings}}, sites...)
	}
	want := map[string]bool{}
	for _, p := range pkgs {
		want[pkgKey(p.Ecosystem, p.Name, p.Lockfile, req.SitePath)] = true
	}
	var out []SiteEntry
	seen := map[string]bool{}
	for i, s := range sites {
		if len(out) == MaxSites || seen[s.Host+"\x00"+s.SitePath] || !nameRe.MatchString(s.Host) ||
			!pathRe.MatchString(s.SitePath) || len(s.SitePath) > 512 {
			continue
		}
		e := SiteEntry{Host: s.Host, SitePath: s.SitePath, Installed: installed(want, s)}
		if nameRe.MatchString(s.Site) {
			e.Site = s.Site
		}
		if slices.Contains(siteLabels, s.Label) {
			e.Label = s.Label
		}
		if ValidBranch(s.Branch) {
			b := s.Branch
			e.Branch = &b
		} else if ValidCommit(s.Commit) {
			e.Commit = s.Commit
		}
		if len(e.Installed) == 0 && i > 0 {
			continue // nothing of this hand-off to fix there
		}
		seen[s.Host+"\x00"+s.SitePath] = true
		out = append(out, e)
	}
	return out
}

// SiteInstalled is site's installed version of each of own's fixable
// packages (own being the hand-off's site) that it has a fixable finding
// in: what the message lists for it. Empty means it has nothing of this
// hand-off to fix, and isn't listed.
func SiteInstalled(own, site Site) []Installed {
	want := map[string]bool{}
	for _, p := range packages(own.Findings, 1) {
		want[pkgKey(p.Ecosystem, p.Name, p.Lockfile, own.SitePath)] = true
	}
	return installed(want, site)
}

func installed(want map[string]bool, s Site) []Installed {
	out := []Installed{}
	for _, p := range packages(s.Findings, 1) {
		if want[pkgKey(p.Ecosystem, p.Name, p.Lockfile, s.SitePath)] {
			out = append(out, Installed{Ecosystem: p.Ecosystem, Name: p.Name, Installed: p.Installed, Lockfile: p.Lockfile})
		}
	}
	return out
}

// entryBranches is Branches for validated entries.
func entryBranches(sites []SiteEntry) []string {
	var out []string
	for _, s := range sites {
		if s.Branch != nil && !slices.Contains(out, *s.Branch) {
			out = append(out, *s.Branch)
		}
	}
	slices.Sort(out)
	return out
}

// targetData checks the target against the sites' branches and names
// each pull request's branch.
func targetData(t Target, sites []SiteEntry, requestID string) (TargetData, error) {
	known := entryBranches(sites)
	base := "heimdall/security-" + requestID
	switch cmp.Or(t.Mode, TargetDefault) {
	case TargetDefault:
		if len(t.Branches) != 0 {
			return TargetData{}, ErrTarget
		}
		return TargetData{Mode: TargetDefault, Branches: []string{}, PullRequests: []PullRequest{{SuggestedBranch: base}}}, nil
	case TargetBranch:
		if len(t.Branches) != 1 || !slices.Contains(known, t.Branches[0]) {
			return TargetData{}, ErrTarget
		}
		b := t.Branches[0]
		return TargetData{Mode: TargetBranch, Branches: []string{b},
			PullRequests: []PullRequest{{Base: &b, SuggestedBranch: base + "-" + BranchSlug(b)}}}, nil
	case TargetEach:
		if len(known) == 0 {
			return TargetData{}, ErrTarget
		}
		d := TargetData{Mode: TargetEach, Branches: known}
		used := map[string]bool{}
		for _, b := range known {
			slug := BranchSlug(b)
			for n := 2; used[slug]; n++ { // env/beta and env-beta
				slug = BranchSlug(b) + "-" + strconv.Itoa(n)
			}
			used[slug] = true
			d.PullRequests = append(d.PullRequests, PullRequest{Base: &b, SuggestedBranch: base + "-" + slug})
		}
		return d, nil
	}
	return TargetData{}, ErrTarget
}
