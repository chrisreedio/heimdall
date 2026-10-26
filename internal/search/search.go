// SPDX-License-Identifier: AGPL-3.0-or-later

package search

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/composer"
	"github.com/realmwatch/heimdall/internal/findings"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/version"
)

// MaxMatches caps a result; the Note says when it was hit.
const MaxMatches = 2000

const maxQueryLen = 200

var (
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,199}$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:^-]{0,127}$`)
	// Advisory IDs: CVE-2024-6387, GHSA-xxxx-xxxx-xxxx, DEBIAN-CVE-…, RLSA-2024:1234, USN-6000-1, …
	advisoryRe = regexp.MustCompile(`(?i)^(CVE-\d{4}-\d{4,}|GHSA(-[0-9a-z]{4}){3}|(DEBIAN|UBUNTU|ALPINE)-CVE-\d{4}-\d{4,}|(RLSA|ALSA|RHSA)-\d{4}:\d+|USN-\d+-\d+|(DSA|DLA)-\d+(-\d+)?)$`)
	// name, optional op, optional version; op may touch either side.
	exprRe = regexp.MustCompile(`^(\S+?)\s*(<=|>=|==|=|<|>)\s*(\S+)$`)
	// Composer package names (vendor/package), as Composer validates them.
	composerNameRe = regexp.MustCompile(`^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*$`)
)

// Site-level keywords: the framework and PHP-FPM searches.
var (
	frameworkAliases = map[string]string{"laravel": "laravel"}
	fpmAliases       = map[string]bool{"php-fpm": true, "fpm": true}
)

var runtimeAliases = map[string]string{"php": "php", "nodejs": "nodejs", "node": "nodejs", "python": "python"}

// Parse turns user input into a Query.
func Parse(s string) (Query, error) {
	raw := strings.TrimSpace(s)
	q := Query{Raw: raw}
	switch {
	case raw == "":
		return q, errors.New("enter a package, runtime, CVE, laravel, php-fpm, host:<name> or site:<name>")
	case len(raw) > maxQueryLen:
		return q, fmt.Errorf("query is longer than %d characters", maxQueryLen)
	}

	if advisoryRe.MatchString(raw) {
		q.Kind, q.Name = KindCVE, strings.ToUpper(raw)
		if strings.HasPrefix(q.Name, "GHSA-") {
			q.Name = "GHSA-" + strings.ToLower(q.Name[5:]) // GHSA IDs are lowercase after the prefix
		}
		return q, nil
	}

	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "host:"):
		frag := strings.TrimSpace(raw[len("host:"):])
		if frag == "" || !nameRe.MatchString(frag) {
			return q, fmt.Errorf("invalid hostname fragment %q", frag)
		}
		q.Kind, q.Name = KindHost, frag
		return q, nil
	case strings.HasPrefix(lower, "site:"):
		frag := strings.TrimSpace(raw[len("site:"):])
		if frag == "" || !nameRe.MatchString(frag) {
			return q, fmt.Errorf("invalid site fragment %q", frag)
		}
		q.Kind, q.Name = KindSite, frag
		return q, nil
	case strings.HasPrefix(lower, "composer:"):
		q.Kind = KindComposer
		raw = strings.TrimSpace(raw[len("composer:"):])
	case strings.HasPrefix(lower, "pkg:"):
		q.Kind = KindPackage
		raw = strings.TrimSpace(raw[len("pkg:"):])
	case strings.HasPrefix(lower, "runtime:"):
		q.Kind = KindRuntime
		raw = strings.TrimSpace(raw[len("runtime:"):])
	}

	name, op, ver := raw, "", ""
	if m := exprRe.FindStringSubmatch(raw); m != nil {
		name, op, ver = m[1], m[2], m[3]
	} else if strings.ContainsAny(raw, " \t") {
		return q, fmt.Errorf("could not parse %q; try e.g. \"openssl < 3.0.13\"", s)
	}
	if op == "==" {
		op = "="
	}
	if !nameRe.MatchString(name) {
		return q, fmt.Errorf("invalid name %q", name)
	}
	if op != "" && !versionRe.MatchString(ver) {
		return q, fmt.Errorf("invalid version %q", ver)
	}

	lname := strings.ToLower(name)
	if q.Kind == "" {
		switch {
		case frameworkAliases[lname] != "":
			q.Kind = KindFramework
		case fpmAliases[lname]:
			q.Kind = KindPHPFPM
		case runtimeAliases[lname] != "":
			q.Kind = KindRuntime
		case strings.Contains(name, "/") && composerNameRe.MatchString(lname):
			q.Kind = KindComposer
		default:
			q.Kind = KindPackage
		}
	}
	switch q.Kind {
	case KindFramework:
		name = frameworkAliases[lname]
	case KindPHPFPM:
		name = "php-fpm"
		if op != "" && !numericVersion(ver) {
			return q, fmt.Errorf("PHP-FPM versions are numeric, e.g. 8.1 (got %q)", ver)
		}
	case KindComposer:
		if !composerNameRe.MatchString(lname) {
			return q, fmt.Errorf("invalid Composer package %q (want vendor/package)", name)
		}
		name = lname
	}
	if q.Kind == KindRuntime {
		canon, ok := runtimeAliases[strings.ToLower(name)]
		if !ok {
			return q, fmt.Errorf("unknown runtime %q (php, nodejs, python)", name)
		}
		name = canon
		if op != "" && !numericVersion(ver) {
			return q, fmt.Errorf("runtime versions are numeric, e.g. 8.1 (got %q)", ver)
		}
	}
	q.Name, q.Op, q.Version = name, op, ver
	return q, nil
}

// Run executes q against every host's latest snapshot.
func Run(ctx context.Context, st *store.Store, q Query, scope store.Scope) (*Result, error) {
	res, err := run(ctx, st, q)
	if err != nil || scope.Admin {
		return res, err
	}
	// Access control happens here, once, for every kind of query.
	visible, err := st.VisibleOrgSlugs(ctx, scope)
	if err != nil {
		return nil, err
	}
	kept := res.Matches[:0]
	for _, m := range res.Matches {
		if visible[m.Org] {
			kept = append(kept, m)
		}
	}
	res.Matches = kept
	return res, nil
}

func run(ctx context.Context, st *store.Store, q Query) (*Result, error) {
	res := &Result{Query: q, Matches: []Match{}}
	var err error
	switch q.Kind {
	case KindPackage:
		err = runPackage(ctx, st, q, res)
	case KindRuntime:
		err = runRuntime(ctx, st, q, res)
	case KindCVE:
		err = runCVE(ctx, st, q, res)
	case KindHost:
		err = runHost(ctx, st, q, res)
	case KindFramework, KindPHPFPM, KindSite:
		err = runSites(ctx, st, q, res)
	case KindComposer:
		err = runComposer(ctx, st, q, res)
	default:
		return nil, fmt.Errorf("unknown query kind %q", q.Kind)
	}
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(res.Matches, func(a, b Match) int {
		return cmpStrings(a.Org, b.Org, a.Host, b.Host, a.Site, b.Site, a.Name, b.Name)
	})
	if len(res.Matches) > MaxMatches {
		res.Matches = res.Matches[:MaxMatches]
		addNote(res, fmt.Sprintf("showing the first %d matches", MaxMatches))
	}
	return res, nil
}

func runPackage(ctx context.Context, st *store.Store, q Query, res *Result) error {
	hits, err := st.PackagesNamed(ctx, q.Name)
	if err != nil {
		return err
	}
	unsupported := map[int64]bool{}
	for _, h := range hits {
		ver := h.Version
		if q.Op != "" {
			info, ok := findings.HostEcosystem(h.Inventory())
			if !ok {
				unsupported[h.HostID] = true
				continue
			}
			// The user may name a source package (openssl) whose binaries
			// (libssl3) carry a different version on Debian; compare the
			// source version then.
			if !strings.EqualFold(h.Name, q.Name) && h.SourceVersion != "" {
				ver = h.SourceVersion
			}
			if !satisfies(compareVersions(info.Scheme, ver, q.Version), q.Op) {
				continue
			}
		}
		m := Match{HostID: h.HostID, Org: h.Org, Host: h.Host, OS: osName(h.SearchHost), Name: h.Name, Version: h.Version}
		if !strings.EqualFold(h.Name, q.Name) {
			m.Detail = "from source package " + h.SourceName
		}
		if h.PendingVersion != "" {
			m.Detail = joinDetail(m.Detail, "update pending: "+h.PendingVersion)
		}
		res.Matches = append(res.Matches, m)
	}
	if n := len(unsupported); n > 0 {
		addNote(res, fmt.Sprintf("%d %s skipped: version comparison isn't supported for its OS", n, plural(n, "host", "hosts")))
	}
	return nil
}

func runRuntime(ctx context.Context, st *store.Store, q Query, res *Result) error {
	hosts, err := st.HostsWithSnapshots(ctx)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		inv, err := st.Inventory(ctx, h)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		for _, rt := range findings.HostRuntimes(inv) {
			if rt.Name != q.Name {
				continue
			}
			if q.Op != "" && !runtimeSatisfies(rt.Version, q.Op, q.Version) {
				continue
			}
			os := inv.OSPretty
			if os == "" {
				os = strings.TrimSpace(inv.OSID + " " + inv.OSVersion)
			}
			res.Matches = append(res.Matches, Match{HostID: h.ID, Org: h.OrgSlug, Host: h.Name, OS: os,
				Name: rt.Name, Version: rt.Version, Detail: "from package " + rt.Package})
		}
	}
	return nil
}

func runCVE(ctx context.Context, st *store.Store, q Query, res *Result) error {
	hits, err := st.OpenFindingsFor(ctx, q.Name)
	if err != nil {
		return err
	}
	for _, f := range hits {
		detail := f.Package + ": no fix yet"
		if f.FixedVersion != "" {
			detail = f.Package + ": fixed in " + f.FixedVersion
		}
		if !strings.EqualFold(f.AdvisoryID, q.Name) {
			detail += " (" + f.AdvisoryID + ")"
		}
		if f.SiteRoot != "" {
			detail += " in site " + f.SiteRoot
		}
		res.Matches = append(res.Matches, Match{HostID: f.HostID, Org: f.Org, Host: f.Host, OS: osName(f.SearchHost),
			Name: f.Package, Version: f.Version, Detail: detail, Site: f.SiteRoot})
	}
	return nil
}

func runHost(ctx context.Context, st *store.Store, q Query, res *Result) error {
	hosts, err := st.HostsMatching(ctx, q.Name)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		m := Match{HostID: h.HostID, Org: h.Org, Host: h.Host, OS: osName(h), Name: h.Host}
		if h.OSID == "" {
			m.Detail = "never reported"
		}
		res.Matches = append(res.Matches, m)
	}
	return nil
}

// runSites answers framework, PHP-FPM and site-fragment queries.
func runSites(ctx context.Context, st *store.Store, q Query, res *Result) error {
	sites, err := st.SitesAll(ctx)
	if err != nil {
		return err
	}
	frag := strings.ToLower(q.Name)
	for _, s := range sites {
		m := Match{HostID: s.HostID, Org: s.Org, Host: s.Host, OS: osName(s.SearchHost), Site: s.Root}
		switch q.Kind {
		case KindFramework:
			if s.Framework != q.Name || s.FrameworkVersion == "" {
				continue
			}
			if q.Op != "" && !composerSatisfies(s.FrameworkVersion, q.Op, q.Version) {
				continue
			}
			m.Name, m.Version = s.Framework, s.FrameworkVersion
		case KindPHPFPM:
			if s.PHPFPMVersion == "" {
				continue
			}
			if q.Op != "" && !runtimeSatisfies(s.PHPFPMVersion, q.Op, q.Version) {
				continue
			}
			m.Name, m.Version = "php-fpm", s.PHPFPMVersion
		case KindSite:
			hit := strings.Contains(strings.ToLower(s.Root), frag)
			for _, n := range s.ServerNames {
				hit = hit || strings.Contains(strings.ToLower(n), frag)
			}
			if !hit {
				continue
			}
			m.Name = s.Root
		}
		m.Detail = siteDetail(s)
		res.Matches = append(res.Matches, m)
	}
	return nil
}

// runComposer finds sites whose composer.lock has the package.
func runComposer(ctx context.Context, st *store.Store, q Query, res *Result) error {
	hits, err := st.ComposerPackagesNamed(ctx, q.Name)
	if err != nil {
		return err
	}
	for _, h := range hits {
		if q.Op != "" && !composerSatisfies(h.Version, q.Op, q.Version) {
			continue
		}
		res.Matches = append(res.Matches, Match{HostID: h.HostID, Org: h.Org, Host: h.Host, OS: osName(h.SearchHost),
			Name: h.Name, Version: h.Version, Site: h.SiteRoot, Detail: "in " + h.SiteRoot + "/composer.lock"})
	}
	return nil
}

func siteDetail(s store.SiteHit) string {
	var parts []string
	if len(s.ServerNames) > 0 {
		parts = append(parts, strings.Join(s.ServerNames, ", "))
	}
	if s.WebServer != "" {
		parts = append(parts, s.WebServer)
	}
	if s.PHPFPMVersion != "" {
		parts = append(parts, "PHP-FPM "+s.PHPFPMVersion)
	}
	if s.Framework != "" {
		parts = append(parts, strings.TrimSpace(s.Framework+" "+s.FrameworkVersion))
	}
	return strings.Join(parts, "; ")
}

// composerSatisfies compares Composer versions; "=" matches by component
// prefix, so laravel = 11 matches 11.31.0 and laravel = 10.48 matches 10.48.22.
func composerSatisfies(have, op, want string) bool {
	if op == "=" {
		hv := strings.Split(strings.TrimPrefix(strings.ToLower(have), "v"), ".")
		wv := strings.Split(strings.TrimPrefix(strings.ToLower(want), "v"), ".")
		return len(hv) >= len(wv) && slices.Equal(hv[:len(wv)], wv)
	}
	return satisfies(composer.CompareVersions(have, want), op)
}

// compareVersions applies the host's scheme. An rpm version without an
// epoch is compared against the other without its epoch, matching how the
// findings engine treats epoch-less advisory versions.
func compareVersions(s version.Scheme, a, b string) int {
	if s == version.RPM && strings.Contains(a, ":") != strings.Contains(b, ":") {
		a, b = stripEpoch(a), stripEpoch(b)
	}
	c, _ := version.Compare(s, a, b)
	return c
}

func stripEpoch(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		return v[i+1:]
	}
	return v
}

func satisfies(c int, op string) bool {
	switch op {
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case "=":
		return c == 0
	case ">=":
		return c >= 0
	case ">":
		return c > 0
	}
	return true
}

// runtimeSatisfies compares dotted numeric versions; "=" matches by
// prefix, so php = 8.1 matches 8.1.27.
func runtimeSatisfies(have, op, want string) bool {
	hv, wv := numericParts(have), numericParts(want)
	if hv == nil || wv == nil {
		return false
	}
	if op == "=" {
		return len(hv) >= len(wv) && slices.Equal(hv[:len(wv)], wv)
	}
	return satisfies(slices.Compare(hv, wv), op)
}

func numericParts(v string) []int {
	var out []int
	for p := range strings.SplitSeq(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil
		}
		out = append(out, n)
	}
	return out
}

func numericVersion(v string) bool { return numericParts(v) != nil }

func osName(h store.SearchHost) string {
	if h.OSPretty != "" {
		return h.OSPretty
	}
	return strings.TrimSpace(h.OSID + " " + h.OSVersion)
}

func joinDetail(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func addNote(res *Result, note string) {
	res.Note = joinDetail(res.Note, note)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func cmpStrings(pairs ...string) int {
	for i := 0; i+1 < len(pairs); i += 2 {
		if c := strings.Compare(pairs[i], pairs[i+1]); c != 0 {
			return c
		}
	}
	return 0
}
