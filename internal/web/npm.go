// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/version"
)

// npmEcosystem is OSV's name for npm, as findings carry it.
const npmEcosystem = "npm"

var (
	// npm names that are safe to paste into a shell: lowercase, an optional
	// @scope/, never a leading "-", ".", "_" or "~".
	npmCmdName = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]{0,213}$`)
	// A plain semver fixed version: no ranges, tags, URLs or shell syntax.
	npmCmdVersion = regexp.MustCompile(`^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}(-[0-9A-Za-z.-]{1,64})?$`)
)

// npmCommands builds the fix commands for a site's npm findings, run in
// the site root. Only runtime dependencies get one: dev dependencies only
// build the site (they're marked dev, and left out of what needs
// attention). A package's fix is the highest fixed version among its
// advisories, so one update clears them all.
//
//   - When that's within the version's caret range (same major; same minor
//     for 0.x), `npm update <pkg>...` installs it: npm update follows the
//     ranges package.json and the dependents declare, which by default
//     (npm install's ^) allow it, and updates a package wherever it is in
//     the tree, including one that's only a dependency of a dependency.
//   - Otherwise no range allows it, and `npm install <pkg>@<fixed>...`
//     asks for it outright. That records each as a direct dependency in
//     package.json, so the label says to check: a package that only comes
//     in through another one is better fixed by updating that parent, or
//     pinned with "overrides".
func npmCommands(id string, fs []report.Finding) []command {
	fixed := map[string]string{}
	var names []string
	installed := map[string]string{}
	for _, f := range fs {
		if f.Ecosystem != npmEcosystem || f.Dev || f.Fixed == "" ||
			!npmCmdName.MatchString(f.Package) || !npmCmdVersion.MatchString(f.Fixed) {
			continue
		}
		cur, seen := fixed[f.Package]
		if !seen {
			names = append(names, f.Package)
		}
		if !seen || cmpVersion(f.Fixed, cur) > 0 {
			fixed[f.Package] = f.Fixed
		}
		if v, ok := installed[f.Package]; !ok || cmpVersion(f.Version, v) < 0 {
			installed[f.Package] = f.Version
		}
	}
	slices.Sort(names)
	var update, install []string
	for _, n := range names {
		if inCaretRange(installed[n], fixed[n]) {
			update = append(update, n)
		} else {
			install = append(install, n+"@"+fixed[n])
		}
	}
	var out []command
	if len(update) > 0 {
		out = append(out, command{ID: id, Text: "npm update " + strings.Join(update, " "),
			Label: "Update " + plural(len(update), "npm package", "npm packages") + " to fixed versions within their ranges (run in the site root)",
			Note: "npm update keeps package.json's version ranges and rewrites package-lock.json, wherever in the tree each package is. " +
				"Rebuild the frontend (npm run build) and deploy as usual afterwards."})
	}
	if len(install) > 0 {
		out = append(out, command{ID: id + "-major", Text: "npm install " + strings.Join(install, " "),
			Label: "Install " + plural(len(install), "npm fix", "npm fixes") + " that need a newer major version (run in the site root)",
			Note: "No version range allows these fixes, so check each changelog for breaking changes. npm install records each package as a direct " +
				"dependency in package.json: for one that only comes in through another package, update that package instead, or pin it with \"overrides\"."})
	}
	return out
}

// inCaretRange reports whether ^installed allows fixed: the same major
// version, or for 0.x the same minor too. Unknown versions don't.
func inCaretRange(installed, fixed string) bool {
	a, b := semverParts(installed), semverParts(fixed)
	if a == nil || b == nil || a[0] != b[0] {
		return false
	}
	return a[0] != 0 || a[1] == b[1]
}

// semverParts is a version's major, minor and patch, or nil.
func semverParts(v string) []int {
	core, _, _ := strings.Cut(strings.TrimPrefix(v, "v"), "-")
	core, _, _ = strings.Cut(core, "+")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return nil
	}
	out := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil
		}
		out[i] = n
	}
	return out
}

func cmpVersion(a, b string) int {
	c, _ := version.Compare(version.Composer, a, b)
	return c
}
