// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/kernel"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

// A host's OS findings can number in the thousands, so the host page shows
// them one row per package by default, with severity and fixable filters
// and paging. "All findings" lists them individually, a page at a time.
// Unfiltered, it shows only what needs attention (needsAction); the rest,
// with no fix and little sign of exploitation, is one click away.

const findingsPerPage = 50

var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// pkgGroup is one package's findings.
type pkgGroup struct {
	Package, Version string
	Ecosystem        string // OSV's: "npm" marks an npm package in a site's list
	Dev              bool   // every finding is on an npm dev dependency
	Binaries         []string
	Worst            string // highest severity
	KEV              int
	News             int    // findings named by a live news incident
	NotRunning       bool   // every finding is on an old kernel that isn't running
	KernelStatus     string // the findings' common kernel status, or ""
	ClientOnly       string // the server package that isn't installed (report.Finding.ClientOnly)
	BySev            map[string]int
	Total, Fixable   int
	FixPending       bool // an update that fixes some of them is already pending
	Findings         []report.Finding
}

type findingsView struct {
	View    string // "packages" or "all"
	PM      string // dpkg, rpm, apk or composer (a site: Composer and npm): what the patch command uses
	Sev     string // "" or kev, critical, high, medium, low, unknown
	Fixable bool
	// Focus: no filter is set and show=all isn't, so only the findings
	// that need attention are shown; Hidden counts the rest.
	Focus     bool
	Hidden    int // with no fix and little sign of exploitation
	HiddenDev int // on npm dev dependencies (a site's)
	Total     int // findings after filters
	Groups    []pkgGroup
	Rows      []report.Finding
	Page      int
	Pages     int
	// Links, built here so templates don't assemble query strings.
	SevLinks          map[string]string
	AllSevLink        string // every finding, no filters
	FocusLink         string // the default: what needs attention
	FixLink, ViewLink map[string]string
	PrevLink          string
	NextLink          string
	// FixCmd upgrades just the packages that fix the findings shown, and
	// have a pending update.
	FixCmd     *command
	NpmCmds    []command // a site's npm fixes (PM composer), after FixCmd
	FixPkgs    int
	FixPending int // of those, how many have an update that reaches the fixed version
	// RebootCmd puts the newer installed kernel in use, which clears the
	// RebootFindings on the running kernel. It comes before FixCmd unless
	// FixCmd installs a kernel itself.
	RebootCmd      *command
	RebootFindings int
	RebootFirst    bool
	// NotInCache counts findings shown with a published fix that no
	// pending update installs yet.
	NotInCache int
	// OldKernelCmd removes installed kernels older than the running one,
	// which clears OldKernelFindings (upgrading never does).
	OldKernelCmd      *command
	OldKernelFindings int
}

// oldKernelCommand removes the installed kernel packages older than the
// running kernel (report.Host.OldKernels), when findings are on them.
func oldKernelCommand(pkgs []string, findings int) *command {
	var names []string
	for _, p := range pkgs {
		if safePackage.MatchString(p) {
			names = append(names, p)
		}
	}
	if findings == 0 || len(names) == 0 {
		return nil
	}
	return &command{ID: "cmd-old-kernels", Text: kernel.PurgePrefix + " " + strings.Join(names, " "),
		Note: "These kernels are installed but not running (apt keeps the previous one as a boot fallback), so upgrading never clears their findings. " +
			"Check that uname -r shows the kernel you expect first; afterwards there's no older kernel to fall back to at boot."}
}

// live reports whether a finding is live exposure: not on an old kernel
// that isn't running, nor only on kernel userland packages, nor on an npm
// dev dependency (needed to build the site, not to run it).
func live(f report.Finding) bool {
	return !f.NotRunning && f.KernelStatus != kernel.StatusUserland && !f.Dev
}

// needsAction reports whether a finding needs attention: it's live, and
// fixable now or, with no fix yet, still worth watching (known-exploited,
// in the news, or likely to be exploited). report.Counts.Attention counts
// the same.
func needsAction(f report.Finding) bool {
	return live(f) && (f.Fixed != "" || watched(f))
}

// watched: worth watching even with no fix (report.Counts.Watch). On a
// source installed only for its clients, only when known-exploited.
func watched(f report.Finding) bool {
	return f.KEV || (f.ClientOnly == "" && (f.InNews || f.EPSS >= store.WatchEPSS))
}

// kernelInfo is what the findings view needs about the host's kernels.
type kernelInfo struct{ Running, Newer string }

// fixCommands fills in the view's patch commands for the findings shown
// (see fixCommand and rebootCommand).
func (fv *findingsView) fixCommands(list []report.Finding, pkgs report.Pkgs, k kernelInfo) {
	if fv.PM == "composer" {
		fv.FixCmd, fv.FixPkgs, fv.FixPending = composerFixCommand(list)
		fv.NpmCmds = npmCommands("cmd-fix-npm", list)
		return
	}
	u := report.PlanUpgrade(fv.PM, list, pkgs)
	fv.FixCmd, fv.FixPkgs, fv.FixPending = fixCommand(fv.PM, u)
	fv.NotInCache = u.NotInCache
	fv.RebootFindings = u.RebootFindings
	fv.RebootCmd = rebootCommand(u, k)
	fv.RebootFirst = fv.RebootCmd != nil && len(u.Metas) == 0
}

// rebootCommand is "Reboot to run <newer>", when findings are on the
// running kernel and a newer one is already installed.
func rebootCommand(u report.Upgrade, k kernelInfo) *command {
	if u.RebootFindings == 0 || k.Newer == "" {
		return nil
	}
	c := &command{ID: "cmd-reboot", Label: "Reboot to run " + k.Newer, Text: "sudo reboot",
		Note: "Kernel " + k.Newer + " is already installed, and " + k.Running + " is still running. Rebooting puts the newer kernel in use, " +
			"which clears the findings marked \"reboot pending\": no package upgrade does. The newer kernel may still have findings of its own; " +
			"they show here once the host reports after the reboot. " + k.Running + " then stays installed as a boot fallback, marked \"not running\"."}
	if len(u.Metas) > 0 {
		c.Label = "Then reboot to run the newest kernel"
		c.Note = "The upgrade above installs a newer kernel still. Rebooting afterwards puts it in use, which also clears the findings marked " +
			"\"reboot pending\" on the running kernel (" + k.Running + "). The new kernel may still have findings of its own."
	}
	return c
}

func composerFixCommand(list []report.Finding) (*command, int, int) {
	var names []string
	for _, f := range list {
		if f.Fixed != "" && f.Ecosystem != npmEcosystem && composerName.MatchString(f.Package) && !slices.Contains(names, f.Package) {
			names = append(names, f.Package)
		}
	}
	if len(names) == 0 {
		return nil, 0, 0
	}
	slices.Sort(names)
	return &command{ID: "cmd-fix", Text: "composer update " + strings.Join(names, " ") + " --with-dependencies"}, len(names), 0
}

// fixCommand builds an upgrade command from the planned upgrade (see
// report.PlanUpgrade): only packages that have a pending update, using the
// binary package names the package manager installs. nil when nothing
// shown has an update, or the package manager isn't one we write commands
// for. Kernel fixes are special (see internal/kernel): on Debian and
// Ubuntu they go through the installed kernel metapackages, never the
// ABI-named packages, and all of them need a reboot.
func fixCommand(pm string, u report.Upgrade) (*command, int, int) {
	prefix := map[string]string{
		"dpkg": "sudo apt-get update && sudo apt-get install --only-upgrade",
		"rpm":  "sudo dnf upgrade --refresh",
		"apk":  "sudo apk update && sudo apk upgrade",
	}[pm]
	if prefix == "" {
		return nil, 0, 0
	}
	if u.FullUpgrade {
		return &command{ID: "cmd-fix", Text: kernel.DpkgFullUpgrade, Note: noMetapackageNote}, len(u.Names) + 1, u.NamesFixPending
	}
	if len(u.Names) == 0 {
		return nil, 0, 0
	}
	note := ""
	switch {
	case len(u.Metas) > 0:
		note = "Includes a kernel update through the kernel metapackage (" + strings.Join(u.Metas, ", ") +
			"), which installs the new kernel beside the running one. Reboot afterwards to run it."
	case u.Kernel:
		note = "Includes a kernel update. Reboot afterwards to run the new kernel."
	}
	names := slices.Clone(u.Names)
	slices.Sort(names)
	return &command{ID: "cmd-fix", Text: prefix + " " + strings.Join(names, " "), Note: note}, len(names), u.NamesFixPending
}

const noMetapackageNote = "Includes a kernel fix, but no kernel metapackage (such as linux-generic, linux-aws or linux-image-amd64) " +
	"is installed, so apt won't install a newer kernel by itself. This upgrades every package instead; install your kernel's " +
	"metapackage to get kernel fixes, then reboot."

// pkgs is the host's installed packages (nil for Composer), k its kernels.
func buildFindingsView(base, pm string, q url.Values, list []report.Finding, pkgs report.Pkgs, k kernelInfo) findingsView {
	fv := findingsView{View: "packages", PM: pm, Sev: q.Get("sev"), Fixable: q.Get("fix") == "1"}
	if q.Get("view") == "all" {
		fv.View = "all"
	}
	if _, ok := severityRank[fv.Sev]; !ok && fv.Sev != "kev" && fv.Sev != "unknown" {
		fv.Sev = ""
	}
	fv.Page, _ = strconv.Atoi(q.Get("page"))
	showAll := q.Get("show") == "all"
	fv.Focus = !showAll && fv.Sev == "" && !fv.Fixable

	var kept []report.Finding
	for _, f := range list {
		if fv.Focus && !needsAction(f) {
			if f.Dev {
				fv.HiddenDev++
			} else {
				fv.Hidden++
			}
			continue
		}
		// Like the chips' counts, the known-exploited and fixable filters
		// leave out what isn't live kernel exposure.
		notLive := !live(f)
		if fv.Fixable && (f.Fixed == "" || notLive) {
			continue
		}
		if f.Dev && fv.Sev != "" { // like the chips' severity counts
			continue
		}
		switch fv.Sev {
		case "":
		case "kev":
			if !f.KEV || notLive {
				continue
			}
		case "unknown":
			if _, known := severityRank[f.Severity]; known {
				continue
			}
		default:
			if f.Severity != fv.Sev {
				continue
			}
		}
		kept = append(kept, f)
	}
	fv.Total = len(kept)
	fv.fixCommands(kept, pkgs, k)

	n := len(kept)
	if fv.View == "packages" {
		fv.Groups = groupByPackage(kept)
		n = len(fv.Groups)
	}
	fv.Pages = max(1, (n+findingsPerPage-1)/findingsPerPage)
	fv.Page = min(max(fv.Page, 1), fv.Pages)
	lo, hi := (fv.Page-1)*findingsPerPage, min(fv.Page*findingsPerPage, n)
	if fv.View == "packages" {
		fv.Groups = fv.Groups[lo:hi]
	} else {
		fv.Rows = kept[lo:hi]
	}

	link := func(change map[string]string) string {
		v := url.Values{}
		set := func(k, val, dflt string) {
			if val != "" && val != dflt {
				v.Set(k, val)
			}
		}
		cur := map[string]string{"view": fv.View, "sev": fv.Sev, "fix": map[bool]string{true: "1"}[fv.Fixable],
			"show": map[bool]string{true: "all"}[showAll]}
		for k, val := range change {
			cur[k] = val
		}
		set("view", cur["view"], "packages")
		set("sev", cur["sev"], "")
		set("fix", cur["fix"], "")
		set("show", cur["show"], "")
		set("page", change["page"], "1") // any other change goes back to page 1
		if len(v) == 0 {
			return base + "#findings"
		}
		return base + "?" + v.Encode() + "#findings"
	}
	fv.SevLinks = map[string]string{}
	for _, s := range []string{"kev", "critical", "high", "medium", "low", "unknown"} {
		target := s
		if fv.Sev == s {
			target = "" // clicking the active filter clears it
		}
		fv.SevLinks[s] = link(map[string]string{"sev": target})
	}
	fv.AllSevLink = link(map[string]string{"sev": "", "fix": "", "show": "all"})
	fv.FocusLink = link(map[string]string{"sev": "", "fix": "", "show": ""})
	fv.FixLink = map[string]string{"on": link(map[string]string{"fix": "1"}), "off": link(map[string]string{"fix": ""})}
	fv.ViewLink = map[string]string{"packages": link(map[string]string{"view": "packages"}), "all": link(map[string]string{"view": "all"})}
	if fv.Page > 1 {
		fv.PrevLink = link(map[string]string{"page": strconv.Itoa(fv.Page - 1)})
	}
	if fv.Page < fv.Pages {
		fv.NextLink = link(map[string]string{"page": strconv.Itoa(fv.Page + 1)})
	}
	return fv
}

// groupByPackage folds findings into one row per package, most urgent
// first: known-exploited, then in the news, then worst severity, then how many.
func groupByPackage(list []report.Finding) []pkgGroup {
	idx := map[string]int{}
	var groups []pkgGroup
	for _, f := range list {
		key := f.Ecosystem + "\x00" + f.Package + "\x00" + f.Version
		i, ok := idx[key]
		if !ok {
			i = len(groups)
			idx[key] = i
			groups = append(groups, pkgGroup{Package: f.Package, Version: f.Version, Ecosystem: f.Ecosystem, Binaries: f.Binaries,
				BySev: map[string]int{}, NotRunning: f.NotRunning, KernelStatus: f.KernelStatus, Dev: f.Dev,
				ClientOnly: f.ClientOnly})
		}
		g := &groups[i]
		g.NotRunning = g.NotRunning && f.NotRunning
		g.Dev = g.Dev && f.Dev
		if g.KernelStatus != f.KernelStatus {
			g.KernelStatus = ""
		}
		g.Total++
		g.Findings = append(g.Findings, f)
		if f.KEV {
			g.KEV++
		}
		if f.InNews {
			g.News++
		}
		sev := f.Severity
		if _, known := severityRank[sev]; !known {
			sev = "unknown"
		}
		g.BySev[sev]++
		if severityRank[f.Severity] > severityRank[g.Worst] || g.Worst == "" {
			g.Worst = sev
		}
		if f.Fixed != "" {
			g.Fixable++
			g.FixPending = g.FixPending || f.FixPending
		}
	}
	slices.SortStableFunc(groups, func(a, b pkgGroup) int {
		running := map[bool]int{false: 1, true: 0} // old kernels that aren't running, kernel userland and npm dev dependencies go last
		for _, d := range [][2]int{
			{running[a.NotRunning || a.KernelStatus == kernel.StatusUserland || a.Dev], running[b.NotRunning || b.KernelStatus == kernel.StatusUserland || b.Dev]}, {a.KEV, b.KEV}, {a.News, b.News}, {severityRank[a.Worst], severityRank[b.Worst]},
			{a.BySev["critical"], b.BySev["critical"]}, {a.BySev["high"], b.BySev["high"]}, {a.Total, b.Total},
		} {
			if d[0] != d[1] {
				return d[1] - d[0]
			}
		}
		return strings.Compare(a.Package, b.Package)
	})
	return groups
}
