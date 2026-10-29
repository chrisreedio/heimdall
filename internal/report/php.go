// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"cmp"
	"regexp"
	"slices"
	"strings"

	"github.com/realmwatch/heimdall/internal/kernel"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/version"
)

// PHPUse is what uses one installed PHP version on a Debian or Ubuntu
// host, from the sites' PHP-FPM sockets and the collector's X-Heimdall-PHP
// header (the command line's version and the running PHP-FPMs).
type PHPUse struct {
	Minor      string   `json:"minor"`           // e.g. "8.1"
	Sites      []string `json:"sites,omitempty"` // sites whose PHP-FPM runs it
	CLI        bool     `json:"cli,omitempty"`   // the command line's `php`
	FPMRunning bool     `json:"fpm_running,omitempty"`
	// Unused: no site and no running PHP-FPM uses it, so it can be
	// removed. When it's the command line's, CLITo is the version `php`
	// should point to first (one the sites use, else the newest other).
	Unused bool   `json:"unused,omitempty"`
	CLITo  string `json:"cli_to,omitempty"`
	// Packages are its installed packages (php8.1-*), when unused; DryRun
	// and Commands remove them (Commands in order: the CLI switch first).
	Packages []string `json:"packages,omitempty"`
	// Check looks for anything that runs this version's binaries by name
	// (cron, supervisor or systemd units calling php8.1), which Heimdall
	// can't see.
	Check    string   `json:"check,omitempty"`
	DryRun   string   `json:"dry_run,omitempty"`
	Commands []string `json:"commands,omitempty"`
}

// phpPackage is a package of one PHP version: php8.1, php8.1-cli, ...
var phpPackage = regexp.MustCompile(`^php([0-9]+\.[0-9]+)(-[a-z0-9][a-z0-9.+-]*)?$`)

// PHPPackageMinor is the PHP version a package belongs to ("" for none,
// e.g. the unversioned php-cli).
func PHPPackageMinor(name string) string {
	if m := phpPackage.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return ""
}

// maxPHPPackages bounds one removal command.
const maxPHPPackages = 60

// phpUse sets Use on the host's PHP runtimes.
func phpUse(host *Host, p store.HostPHP, pkgs []store.InventoryPackage) {
	byMinor := map[string][]string{}
	for _, pk := range pkgs {
		if m := PHPPackageMinor(pk.Name); m != "" && !slices.Contains(byMinor[m], pk.Name) {
			byMinor[m] = append(byMinor[m], pk.Name)
		}
	}
	uses := map[string]*PHPUse{}
	var minors []string
	for i := range host.Runtimes {
		rt := &host.Runtimes[i]
		m := minorOf(rt.Version)
		if rt.Name != "php" || m == "" || byMinor[m] == nil {
			continue
		}
		u := uses[m]
		if u == nil {
			u = &PHPUse{Minor: m, CLI: p.CLI == m, FPMRunning: slices.Contains(p.FPM, m)}
			for _, s := range host.Sites {
				if s.PHPFPM == m {
					u.Sites = append(u.Sites, cmp.Or(siteLabel(s), s.Root))
				}
			}
			uses[m] = u
			minors = append(minors, m)
		}
		rt.Use = u
	}
	used := func(m string) bool { u := uses[m]; return len(u.Sites) > 0 || u.FPMRunning }
	slices.SortFunc(minors, func(a, b string) int { return version.CompareDpkg(b, a) }) // newest first
	// When the command line's version is unused, `php` moves to one that
	// stays: one the sites use, else the newest other one, which is then
	// kept. With no other, the command line's version is kept.
	keep, cliTo := map[string]bool{}, ""
	if u := uses[p.CLI]; u != nil && !used(p.CLI) {
		for _, o := range minors {
			if o != p.CLI && used(o) {
				cliTo = o
				break
			}
		}
		for _, o := range minors {
			if cliTo == "" && o != p.CLI {
				cliTo = o
			}
		}
		if cliTo == "" {
			keep[p.CLI] = true
		} else {
			keep[cliTo] = true
		}
	}
	for _, m := range minors {
		u := uses[m]
		if used(m) || keep[m] || len(byMinor[m]) > maxPHPPackages {
			continue
		}
		if u.CLI {
			u.CLITo = cliTo
		}
		u.Unused = true
		u.Packages = slices.Sorted(slices.Values(byMinor[m]))
		list := strings.Join(u.Packages, " ")
		u.Check = `sudo grep -rlsE 'php` + strings.ReplaceAll(m, ".", `\.`) + `([^0-9]|$)' /etc/cron* /var/spool/cron /etc/supervisor /etc/systemd/system`
		u.DryRun = kernel.PurgePrefix + " -s " + list
		if u.CLITo != "" {
			u.Commands = append(u.Commands, PHPCLICommand(u.CLITo))
		}
		u.Commands = append(u.Commands, kernel.PurgePrefix+" "+list)
	}
	host.PHPKnown = true
}

// PHPCLICommand points the command line's `php` at a version.
func PHPCLICommand(minor string) string {
	return "sudo update-alternatives --set php /usr/bin/php" + minor
}

// minorOf is a version's major.minor ("8.1.2-1ubuntu2" → "8.1").
func minorOf(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	minor := parts[1]
	if i := strings.IndexFunc(minor, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minor = minor[:i]
	}
	if minor == "" {
		return ""
	}
	return parts[0] + "." + minor
}

func siteLabel(s Site) string {
	if len(s.ServerNames) > 0 && s.ServerNames[0] != "_" {
		return s.ServerNames[0]
	}
	return ""
}
