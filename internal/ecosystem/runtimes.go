// SPDX-License-Identifier: AGPL-3.0-or-later

package ecosystem

import (
	"regexp"
	"slices"
	"strings"

	"github.com/realmwatch/heimdall/internal/snapshot"
	"github.com/realmwatch/heimdall/internal/version"
)

type Runtime struct {
	Name    string // "php", "nodejs", "python"
	Version string // upstream version, e.g. "8.3.6"
	Package string // package it was derived from
}

// runtimeRule recognizes the packages that carry a runtime. Lower rank
// wins when several packages describe the same runtime version.
type runtimeRule struct {
	name string
	re   *regexp.Regexp
	rank func(pkg string) int
}

// byOrder ranks packages by which suffix they end in, in the order given.
// An empty suffix stands for "none of the other suffixes" (the base name).
func byOrder(suffixes ...string) func(string) int {
	return func(pkg string) int {
		base := -1
		for i, s := range suffixes {
			if s == "" {
				base = i
			} else if strings.HasSuffix(pkg, s) {
				return i
			}
		}
		if base >= 0 {
			return base
		}
		return len(suffixes)
	}
}

var runtimeRules = map[string][]runtimeRule{
	"dpkg": {
		// php8.3-cli, php8.3-fpm, ... (Ubuntu, Debian and the ondrej/sury repos)
		{"php", regexp.MustCompile(`^php[0-9]+\.[0-9]+-(cli|fpm|common|cgi)$|^libapache2-mod-php[0-9]+\.[0-9]+$`),
			byOrder("-cli", "-fpm", "-common")},
		{"nodejs", regexp.MustCompile(`^nodejs$`), byOrder()},
		// python3.10 / python3.10-minimal; "python3" itself is a metapackage
		// whose version (3.10.6) lags the interpreter's (3.10.12).
		{"python", regexp.MustCompile(`^python3\.[0-9]+(-minimal)?$`), byOrder("", "-minimal")},
	},
	"rpm": {
		{"php", regexp.MustCompile(`^php(-cli|-fpm|-common)?$`), byOrder("-cli", "-fpm", "-common")},
		{"nodejs", regexp.MustCompile(`^nodejs$`), byOrder()},
		{"python", regexp.MustCompile(`^python3(\.[0-9]+)?$`), byOrder()},
	},
	"apk": {
		// php83 is the CLI; php83-fpm/-common share its version.
		{"php", regexp.MustCompile(`^php[0-9]+(-fpm|-common|-cgi)?$`), byOrder("", "-fpm", "-common", "-cgi")},
		{"nodejs", regexp.MustCompile(`^nodejs(-current)?$`), byOrder()},
		{"python", regexp.MustCompile(`^python3$`), byOrder()},
	},
}

var upstreamRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*`)

// upstream strips the epoch, distro revision and packaging suffixes:
// "1:20.12.2-2.module+el9.4.0" → "20.12.2", "12.22.9~dfsg-1ubuntu3" →
// "12.22.9", "8.3.12-1+ubuntu22.04.1+deb.sury.org+1" → "8.3.12".
func upstream(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 && strings.Trim(v[:i], "0123456789") == "" {
		v = v[i+1:]
	}
	return upstreamRe.FindString(v)
}

func majorMinor(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return v
	}
	return parts[0] + "." + parts[1]
}

// Runtimes derives language runtimes from installed packages, without
// running anything. Several versions of one runtime side by side (e.g.
// PHP 8.1 and 8.3) are each reported. The result is sorted by name, then
// version.
func Runtimes(packageManager string, pkgs []snapshot.Package) []Runtime {
	rules := runtimeRules[packageManager]
	type key struct{ name, minor string }
	type pick struct {
		rt   Runtime
		rank int
	}
	best := map[key]pick{}
	for _, p := range pkgs {
		for _, r := range rules {
			if !r.re.MatchString(p.Name) {
				continue
			}
			up := upstream(p.Version)
			if up == "" {
				break
			}
			k := key{r.name, majorMinor(up)}
			cand := pick{Runtime{Name: r.name, Version: up, Package: p.Name}, r.rank(p.Name)}
			if cur, ok := best[k]; !ok || cand.rank < cur.rank ||
				(cand.rank == cur.rank && version.CompareDpkg(up, cur.rt.Version) > 0) {
				best[k] = cand
			}
			break
		}
	}
	out := make([]Runtime, 0, len(best))
	for _, b := range best {
		out = append(out, b.rt)
	}
	slices.SortStableFunc(out, func(a, b Runtime) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		if c := version.CompareDpkg(a.Version, b.Version); c != 0 {
			return c
		}
		return strings.Compare(a.Package, b.Package)
	})
	return out
}
