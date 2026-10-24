// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/chrisreedio/heimdall/internal/kernel"
	"github.com/chrisreedio/heimdall/internal/report"
)

// A host's OS findings can number in the thousands, so the host page shows
// them one row per package by default, with severity and fixable filters
// and paging. "All findings" lists them individually, a page at a time.

const findingsPerPage = 50

var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// pkgGroup is one package's findings.
type pkgGroup struct {
	Package, Version string
	Binaries         []string
	Worst            string // highest severity
	KEV              int
	News             int  // findings named by a live news incident
	NotRunning       bool // every finding is on an old kernel that isn't running
	BySev            map[string]int
	Total, Fixable   int
	FixPending       bool // an update that fixes some of them is already pending
	Findings         []report.Finding
}

type findingsView struct {
	View    string // "packages" or "all"
	PM      string // dpkg, rpm, apk or composer: what the patch command uses
	Sev     string // "" or kev, critical, high, medium, low, unknown
	Fixable bool
	Total   int // findings after filters
	Groups  []pkgGroup
	Rows    []report.Finding
	Page    int
	Pages   int
	// Links, built here so templates don't assemble query strings.
	SevLinks          map[string]string
	AllSevLink        string
	FixLink, ViewLink map[string]string
	PrevLink          string
	NextLink          string
	// FixCmd upgrades just the packages that fix the findings shown.
	FixCmd     *command
	FixPkgs    int
	FixPending int // of those, how many already have the update pending
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

// fixCommand builds an upgrade command for the packages that fix the
// given findings, using the binary package names the package manager
// installs. nil when nothing shown can be fixed, or the package manager
// isn't one we write commands for. Kernel fixes are special (see
// internal/kernel): on Debian and Ubuntu they go through the installed
// kernel metapackages, never the ABI-named packages, and all of them need
// a reboot.
func fixCommand(pm string, list []report.Finding, installed map[string]bool) (*command, int, int) {
	if pm == "composer" {
		var names []string
		pending := 0
		for _, f := range list {
			if f.Fixed != "" && composerName.MatchString(f.Package) && !slices.Contains(names, f.Package) {
				names = append(names, f.Package)
			}
		}
		if len(names) == 0 {
			return nil, 0, 0
		}
		slices.Sort(names)
		return &command{ID: "cmd-fix", Text: "composer update " + strings.Join(names, " ") + " --with-dependencies"}, len(names), pending
	}
	prefix := map[string]string{
		"dpkg": "sudo apt-get update && sudo apt-get install --only-upgrade",
		"rpm":  "sudo dnf upgrade --refresh",
		"apk":  "sudo apk update && sudo apk upgrade",
	}[pm]
	if prefix == "" {
		return nil, 0, 0
	}
	has := func(n string) bool { return installed[n] }
	var names []string
	pendingPkgs := 0
	kernelFix := false
	for _, f := range list {
		if f.Fixed == "" || f.NotRunning { // an old kernel: removing it is the fix
			continue
		}
		bins, isKernel := kernel.Split(pm, f.Binaries, f.Package, has)
		kernelFix = kernelFix || isKernel
		for _, b := range bins {
			if safePackage.MatchString(b) && !slices.Contains(names, b) {
				names = append(names, b)
				if f.FixPending {
					pendingPkgs++
				}
			}
		}
	}
	note := ""
	if kernelFix {
		note = "Includes a kernel update. Reboot afterwards to run the new kernel."
		if pm == "dpkg" {
			var all []string
			for n := range installed {
				if safePackage.MatchString(n) {
					all = append(all, n)
				}
			}
			metas := kernel.Metapackages(pm, all)
			if len(metas) == 0 {
				return &command{ID: "cmd-fix", Text: kernel.DpkgFullUpgrade, Note: noMetapackageNote}, len(names) + 1, pendingPkgs
			}
			for _, m := range metas {
				if !slices.Contains(names, m) {
					names = append(names, m)
				}
			}
			note = "Includes a kernel update through the kernel metapackage (" + strings.Join(metas, ", ") +
				"), which installs the new kernel beside the running one. Reboot afterwards to run it."
		}
	}
	if len(names) == 0 {
		return nil, 0, 0
	}
	slices.Sort(names)
	return &command{ID: "cmd-fix", Text: prefix + " " + strings.Join(names, " "), Note: note}, len(names), pendingPkgs
}

const noMetapackageNote = "Includes a kernel fix, but no kernel metapackage (such as linux-generic, linux-aws or linux-image-amd64) " +
	"is installed, so apt won't install a newer kernel by itself. This upgrades every package instead; install your kernel's " +
	"metapackage to get kernel fixes, then reboot."

// installed is the host's installed package names (nil for Composer).
func buildFindingsView(base, pm string, q url.Values, list []report.Finding, installed map[string]bool) findingsView {
	fv := findingsView{View: "packages", PM: pm, Sev: q.Get("sev"), Fixable: q.Get("fix") == "1"}
	if q.Get("view") == "all" {
		fv.View = "all"
	}
	if _, ok := severityRank[fv.Sev]; !ok && fv.Sev != "kev" && fv.Sev != "unknown" {
		fv.Sev = ""
	}
	fv.Page, _ = strconv.Atoi(q.Get("page"))

	var kept []report.Finding
	for _, f := range list {
		if fv.Fixable && f.Fixed == "" {
			continue
		}
		switch fv.Sev {
		case "":
		case "kev":
			if !f.KEV {
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
	fv.FixCmd, fv.FixPkgs, fv.FixPending = fixCommand(pm, kept, installed)

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
		cur := map[string]string{"view": fv.View, "sev": fv.Sev, "fix": map[bool]string{true: "1"}[fv.Fixable]}
		for k, val := range change {
			cur[k] = val
		}
		set("view", cur["view"], "packages")
		set("sev", cur["sev"], "")
		set("fix", cur["fix"], "")
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
	fv.AllSevLink = link(map[string]string{"sev": ""})
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
		key := f.Package + "\x00" + f.Version
		i, ok := idx[key]
		if !ok {
			i = len(groups)
			idx[key] = i
			groups = append(groups, pkgGroup{Package: f.Package, Version: f.Version, Binaries: f.Binaries, BySev: map[string]int{},
				NotRunning: f.NotRunning})
		}
		g := &groups[i]
		g.NotRunning = g.NotRunning && f.NotRunning
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
		running := map[bool]int{false: 1, true: 0} // old kernels that aren't running go last
		for _, d := range [][2]int{
			{running[a.NotRunning], running[b.NotRunning]}, {a.KEV, b.KEV}, {a.News, b.News}, {severityRank[a.Worst], severityRank[b.Worst]},
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
