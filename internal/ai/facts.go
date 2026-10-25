// SPDX-License-Identifier: AGPL-3.0-or-later

package ai

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/findings"
	"github.com/chrisreedio/heimdall/internal/kernel"
	"github.com/chrisreedio/heimdall/internal/report"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/version"
)

// The facts are what leaves the hub: compact, pre-aggregated, and only
// what the analysis needs. docs/ai.md lists every field; keep it in sync.

type lifeFact struct {
	Product string `json:"product"`
	Cycle   string `json:"cycle"`
	EOL     bool   `json:"eol"`
	EOLDate string `json:"eol_date,omitempty"`
	Known   bool   `json:"known"`
}

type findingFact struct {
	Package    string   `json:"package"`
	Installed  string   `json:"installed"`
	FixedIn    string   `json:"fixed_in,omitempty"`
	FixPending bool     `json:"fix_pending,omitempty"`
	Advisory   string   `json:"advisory"`
	CVEs       []string `json:"cves,omitempty"`
	Severity   string   `json:"severity"`
	KEV        bool     `json:"kev,omitempty"`
	EPSS       float64  `json:"epss,omitempty"`
	InNews     bool     `json:"in_news,omitempty"`
	NotRunning bool     `json:"not_running,omitempty"`
	// KernelStatus: running, not_running, reboot_pending or newer_kernel
	// (see kernel.State.Status), on kernel findings only.
	KernelStatus string `json:"kernel_status,omitempty"`
	Summary      string `json:"summary,omitempty"`
}

type noFixFact struct {
	Package  string `json:"package"`
	Findings int    `json:"findings"`
	Worst    string `json:"worst_severity"`
}

type siteFact struct {
	Name             string        `json:"name"`
	Root             string        `json:"root"`
	Framework        string        `json:"framework,omitempty"`
	FrameworkVersion string        `json:"framework_version,omitempty"`
	FrameworkLife    *lifeFact     `json:"framework_lifecycle,omitempty"`
	PHP              string        `json:"php_fpm,omitempty"`
	PHPLife          *lifeFact     `json:"php_lifecycle,omitempty"`
	PHPRequirement   string        `json:"php_requirement,omitempty"`
	PHPAllowed       *bool         `json:"php_requirement_met,omitempty"`
	Counts           report.Counts `json:"composer_counts"`
	Fixable          []findingFact `json:"composer_fixable,omitempty"`
}

type anomalyFact struct {
	Host     string `json:"host,omitempty"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	Detected string `json:"detected"`
}

type newsFact struct {
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Status   string   `json:"status"`
	Hosts    []string `json:"hosts,omitempty"`
}

type commandFact struct {
	Label   string `json:"label"`
	Command string `json:"command"`
}

type hostFact struct {
	Name           string    `json:"name"`
	Env            string    `json:"env,omitempty"`
	OS             string    `json:"os"`
	OSLife         *lifeFact `json:"os_lifecycle,omitempty"`
	LastReport     string    `json:"last_report"`
	Stale          bool      `json:"stale,omitempty"`
	RebootRequired *bool     `json:"reboot_required"`
	RunningKernel  string    `json:"running_kernel,omitempty"`
	// OldKernels counts installed kernel packages older than the running
	// one; NotRunning counts findings that are only on them.
	OldKernels int `json:"old_kernel_packages,omitempty"`
	NotRunning int `json:"findings_on_old_kernels,omitempty"`
	// Userland counts findings only on kernel userland packages.
	Userland     int    `json:"findings_on_kernel_userland,omitempty"`
	NewestKernel string `json:"newest_installed_kernel,omitempty"`
	// KernelState is kernel.State.Name; NewerKernel the newer kernel that
	// a reboot puts in use, and RebootPending the findings that reboot
	// clears (on the running kernel).
	KernelState   string `json:"kernel_state,omitempty"`
	NewerKernel   string `json:"newer_installed_kernel,omitempty"`
	RebootPending int    `json:"findings_cleared_by_reboot,omitempty"`
	// NotInCache counts OS findings with a published fix that no pending
	// update installs (report.Upgrade.NotInCache).
	NotInCache      int           `json:"fixed_upstream_not_in_package_cache,omitempty"`
	PackageManager  string        `json:"package_manager,omitempty"`
	PendingUpdates  int           `json:"pending_updates"`
	PendingSecurity int           `json:"pending_security_updates"`
	Counts          report.Counts `json:"finding_counts"`
	// Attention is report.Counts.Attention: fixable, plus watch.
	Attention   int           `json:"findings_needing_attention"`
	InNews      int           `json:"findings_in_news,omitempty"`
	NewFindings *int          `json:"new_findings_in_period,omitempty"`
	Resolved    *int          `json:"resolved_findings_in_period,omitempty"`
	Runtimes    []runtimeFact `json:"runtimes,omitempty"`
	Top         []findingFact `json:"top_findings"`
	NoFix       []noFixFact   `json:"no_fix_yet_by_package,omitempty"`
	Sites       []siteFact    `json:"sites,omitempty"`
	Anomalies   []anomalyFact `json:"open_anomalies,omitempty"`
	News        []newsFact    `json:"in_the_news,omitempty"`
	InOpenPlan  bool          `json:"in_open_patch_plan,omitempty"`
	Commands    []commandFact `json:"suggested_commands,omitempty"`
}

type runtimeFact struct {
	Name    string    `json:"name"`
	Version string    `json:"version"`
	Life    *lifeFact `json:"lifecycle,omitempty"`
}

// HostFacts is the data for "explain this host".
type HostFacts struct {
	Today   string   `json:"today"`
	Host    hostFact `json:"host"`
	Windows []string `json:"maintenance_windows,omitempty"`
}

// FleetFacts is the data for an org's brief.
type FleetFacts struct {
	Today       string        `json:"today"`
	Org         string        `json:"org"`
	PeriodHours int           `json:"period_hours"`
	Totals      fleetTotals   `json:"totals"`
	Hosts       []hostFact    `json:"hosts"`
	MoreHosts   int           `json:"more_hosts_not_listed,omitempty"`
	Anomalies   []anomalyFact `json:"open_anomalies,omitempty"`
	News        []newsFact    `json:"in_the_news,omitempty"`
	Windows     []string      `json:"maintenance_windows,omitempty"`
	Plans       []planFact    `json:"open_patch_plans,omitempty"`
}

type fleetTotals struct {
	Hosts, KEV, Critical, HostsFixable, HostsEOL, Reboots, Stale, PendingSecurity, NewFindings, Resolved int
}

func (t fleetTotals) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]int{
		"hosts_reporting": t.Hosts, "kev_findings": t.KEV, "critical_findings": t.Critical,
		"hosts_with_fixes": t.HostsFixable, "hosts_end_of_life": t.HostsEOL, "reboots_required": t.Reboots,
		"stale_hosts": t.Stale, "pending_security_updates": t.PendingSecurity,
		"new_findings_in_period": t.NewFindings, "resolved_findings_in_period": t.Resolved,
	})
}

type planFact struct {
	Name     string `json:"name"`
	Hosts    int    `json:"hosts"`
	Done     int    `json:"done"`
	Verified int    `json:"verified"`
}

// detail controls how much goes in, so a run fits the input budget.
type detail struct {
	top       int  // findings per host
	summaries bool // advisory summaries
	hosts     int  // hosts in a brief
	perHost   int  // findings per host in a brief
	siteFix   int  // Composer findings per site
	anomalies int
}

var detailLevels = []detail{
	{top: 25, summaries: true, hosts: 60, perHost: 3, siteFix: 10, anomalies: 30},
	{top: 15, summaries: true, hosts: 40, perHost: 2, siteFix: 5, anomalies: 20},
	{top: 10, summaries: false, hosts: 25, perHost: 1, siteFix: 3, anomalies: 10},
	{top: 5, summaries: false, hosts: 12, perHost: 0, siteFix: 0, anomalies: 5},
}

// Sources is what the facts are built from.
type Sources struct {
	Store      *store.Store
	Now        time.Time
	StaleAfter time.Duration
}

var sevRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// rank orders findings the way "Patch first" does: known-exploited, then
// in the news, then fixable, severity, EPSS and CVSS.
func rank(a, b report.Finding) int {
	bi := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	return cmp.Or(
		bi(a.NotRunning || a.KernelStatus == kernel.StatusUserland)-bi(b.NotRunning || b.KernelStatus == kernel.StatusUserland), // not live kernel exposure last
		bi(b.KEV)-bi(a.KEV), bi(b.InNews)-bi(a.InNews), bi(b.Fixed != "")-bi(a.Fixed != ""),
		sevRank[b.Severity]-sevRank[a.Severity], cmp.Compare(b.EPSS, a.EPSS), cmp.Compare(b.CVSS, a.CVSS),
		strings.Compare(a.Package, b.Package))
}

func life(l *report.Lifecycle) *lifeFact {
	if l == nil {
		return nil
	}
	f := &lifeFact{Product: clip(l.Product, 40), Cycle: clip(l.Cycle, 40), EOL: l.EOL, Known: l.Known}
	if l.EOLDate != nil {
		f.EOLDate = l.EOLDate.UTC().Format("2006-01-02")
	}
	return f
}

func finding(f report.Finding, summary bool) findingFact {
	ff := findingFact{Package: clip(f.Package, 100), Installed: clip(f.Version, 80), FixedIn: clip(f.Fixed, 80),
		FixPending: f.FixPending, Advisory: clip(f.Advisory, 60), Severity: f.Severity, KEV: f.KEV,
		EPSS: float64(int(f.EPSS*1000)) / 1000, InNews: f.InNews, NotRunning: f.NotRunning, KernelStatus: f.KernelStatus}
	for i, c := range f.CVEs {
		if i == 3 {
			break
		}
		ff.CVEs = append(ff.CVEs, clip(c, 30))
	}
	if summary {
		ff.Summary = clip(f.Summary, 160)
	}
	return ff
}

// clip trims untrusted text to n runes and one line.
func clip(s string, n int) string { return cleanLine(s, n) }

// hostData is one host's raw material.
type hostData struct {
	host    store.IngestHost
	env     string
	rep     report.Host
	sum     store.SnapshotSummary
	inv     store.HostInventory
	pm      string
	anoms   []store.AnomalyRow
	news    []store.NewsEntry
	inPlan  bool
	changes *store.FindingChange
}

func (src Sources) load(ctx context.Context, org store.Org, only int64, since time.Time) ([]hostData, error) {
	st := src.Store
	rep, err := report.Build(ctx, st, report.Filter{Org: org.Slug, Scope: store.AllScope}, src.Now)
	if err != nil {
		return nil, err
	}
	byName := map[string]report.Host{}
	for _, h := range rep.Hosts {
		byName[h.Name] = h
	}
	listed, err := st.ListHosts(ctx, org.Slug)
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	for _, h := range listed {
		env[h.Name] = h.EnvSlug
	}
	var changes map[int64]store.FindingChange
	if !since.IsZero() {
		if changes, err = st.FindingChanges(ctx, org.ID, since); err != nil {
			return nil, err
		}
	}
	reported, err := st.HostsWithSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	var out []hostData
	for _, h := range reported {
		if h.OrgID != org.ID || (only != 0 && h.ID != only) {
			continue
		}
		r, ok := byName[h.Name]
		if !ok {
			continue
		}
		d := hostData{host: h, env: env[h.Name], rep: r}
		if d.sum, err = st.LatestSnapshot(ctx, h.ID); err != nil {
			return nil, err
		}
		if d.inv, err = st.Inventory(ctx, h); err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		d.pm = packageManager(d.inv)
		if d.anoms, err = st.Anomalies(ctx, h.ID); err != nil {
			return nil, err
		}
		if d.news, err = st.HostNews(ctx, h.ID); err != nil {
			return nil, err
		}
		if d.inPlan, err = st.InOpenPlan(ctx, h.ID); err != nil {
			return nil, err
		}
		if changes != nil {
			c := changes[h.ID]
			d.changes = &c
		}
		out = append(out, d)
	}
	return out, nil
}

func packageManager(inv store.HostInventory) string {
	if inv.PackageManager != "" {
		return inv.PackageManager
	}
	if info, ok := findings.HostEcosystem(inv); ok {
		switch info.Scheme {
		case version.Dpkg:
			return "dpkg"
		case version.RPM:
			return "rpm"
		case version.APK:
			return "apk"
		}
	}
	return ""
}

// allowed is what a plan step for this host may suggest: the commands
// its facts carry (full: the host facts', else the brief's), and for a
// host run, the reboot step the plan must have when findings on the
// running kernel clear only by rebooting into the newer one.
func (d hostData) allowed(full bool) HostAllowed {
	cmds, u := d.commands(full)
	a := HostAllowed{PM: d.pm}
	for _, c := range cmds {
		a.Commands = append(a.Commands, c.Command)
	}
	if full && u.RebootFindings > 0 && d.rep.NewerKernel != "" {
		a.Required = []Action{{Title: clip("Reboot to run "+d.rep.NewerKernel, maxTitle), Command: RebootCommand,
			Why: cleanText(rebootWhy(d, u.RebootFindings), maxWhy)}}
		a.RequiredFirst = len(u.Metas) == 0
	}
	return a
}

func rebootWhy(d hostData, n int) string {
	kev := 0
	for _, f := range d.rep.Findings {
		if f.KernelStatus == kernel.StatusRebootPending && f.KEV {
			kev++
		}
	}
	s := fmt.Sprintf("%d finding%s", n, map[bool]string{true: "", false: "s"}[n == 1])
	if kev > 0 {
		s += fmt.Sprintf(" (%d known-exploited)", kev)
	}
	return fmt.Sprintf("%s %s on the running kernel %s. Kernel %s is already installed, so no package upgrade fixes %s: rebooting puts the newer kernel in use. "+
		"The newer kernel may still have findings of its own; check the host after it reports again.",
		s, map[bool]string{true: "is", false: "are"}[n == 1], clip(d.rep.Kernel, 100), clip(d.rep.NewerKernel, 100),
		map[bool]string{true: "it", false: "them"}[n == 1])
}

// osFindings are the host's OS findings (not its sites').
func (d hostData) osFindings() []report.Finding {
	var out []report.Finding
	for _, f := range d.rep.Findings {
		if f.Site == "" {
			out = append(out, f)
		}
	}
	return out
}

// commands are the host's suggested commands, in the order to run them,
// and the upgrade they come from. full adds the pending security updates
// and the sites' Composer updates (the brief leaves them out).
func (d hostData) commands(full bool) ([]commandFact, report.Upgrade) {
	reboot := d.sum.RebootRequired
	cmd, label, u := fixCommand(d.pm, d.osFindings(), report.PackagesOf(d.inv))
	var out []commandFact
	rebootFirst := u.RebootFindings > 0 && d.rep.NewerKernel != "" && len(u.Metas) == 0
	if rebootFirst {
		out = append(out, commandFact{Command: RebootCommand, Label: clip(fmt.Sprintf(
			"Reboot to run %s: it's already installed, and rebooting clears the %d findings with kernel_status reboot_pending on the running kernel %s (no upgrade does)",
			d.rep.NewerKernel, u.RebootFindings, d.rep.Kernel), 300)})
	}
	if cmd != "" {
		out = append(out, commandFact{Label: label, Command: cmd})
	}
	if full {
		var sec []string
		for _, p := range d.inv.Packages {
			if p.PendingSecurity && safePackage.MatchString(p.Name) && !kernel.ABIPackage(d.pm, p.Name) && !slices.Contains(sec, p.Name) {
				sec = append(sec, p.Name)
			}
		}
		if prefix := commandPrefixes[d.pm]; len(prefix) > 0 && len(sec) > 0 && len(sec) <= maxCommandPkgs {
			slices.Sort(sec)
			out = append(out, commandFact{Label: "Install pending security updates", Command: prefix[len(prefix)-1] + " " + strings.Join(sec, " ")})
		}
		composer := map[string]bool{}
		for _, s := range d.inv.Sites {
			for _, p := range s.Packages {
				composer[p.Name] = true
			}
		}
		for _, s := range d.rep.Sites {
			var names []string
			for _, f := range d.rep.Findings {
				if f.Site == s.Root && f.Fixed != "" && composerName.MatchString(f.Package) && composer[f.Package] && !slices.Contains(names, f.Package) {
					names = append(names, f.Package)
				}
			}
			if len(names) > 0 && len(names) <= maxCommandPkgs {
				slices.Sort(names)
				out = append(out, commandFact{Label: "In " + clip(s.Root, 200) + ": update the Composer packages with fixes",
					Command: "composer update " + strings.Join(names, " ") + " --with-dependencies"})
			}
		}
	}
	notRunning := 0
	for _, f := range d.rep.Findings {
		if f.NotRunning {
			notRunning++
		}
	}
	out = append(out, oldKernelCommand(d.pm, d.rep.OldKernels, notRunning)...)
	if !rebootFirst {
		out = append(out, rebootCommand(reboot, u.Kernel && cmd != "", u.RebootFindings > 0 && d.rep.NewerKernel != "")...)
	}
	return out, u
}

// fact summarizes one host at the given detail level.
func (src Sources) fact(d hostData, lv detail, top int, full bool) hostFact {
	reboot := d.sum.RebootRequired
	cmds, u := d.commands(full)
	hf := hostFact{
		Name: clip(d.host.Name, 253), Env: clip(d.env, 63), OS: clip(d.rep.OS, 80), OSLife: life(d.rep.OSLife),
		LastReport: d.sum.ReceivedAt.UTC().Format(time.RFC3339), RebootRequired: reboot, PackageManager: d.pm,
		PendingUpdates: d.sum.PendingUpdates, PendingSecurity: d.sum.PendingSecurity, Counts: d.rep.Counts,
		Attention: d.rep.Counts.Attention(), InOpenPlan: d.inPlan, Top: []findingFact{},
	}
	hf.Stale = src.StaleAfter > 0 && src.Now.Sub(d.sum.ReceivedAt) > src.StaleAfter
	hf.RunningKernel = clip(d.sum.Kernel, 100)
	inst := make([]kernel.Installed, 0, len(d.inv.Packages))
	for _, p := range d.inv.Packages {
		inst = append(inst, kernel.Installed{Name: p.Name, Version: p.Version, Arch: p.Arch})
	}
	hf.NewestKernel = clip(kernel.Newest(d.pm, inst), 100)
	hf.OldKernels = len(d.rep.OldKernels)
	hf.KernelState, hf.NewerKernel = d.rep.KernelState, clip(d.rep.NewerKernel, 100)
	hf.RebootPending, hf.NotInCache = u.RebootFindings, u.NotInCache
	hf.Commands = cmds
	if d.changes != nil {
		n, r := d.changes.New, d.changes.Resolved
		hf.NewFindings, hf.Resolved = &n, &r
	}
	var osf []report.Finding
	noFix := map[string]*noFixFact{}
	for _, f := range d.rep.Findings {
		if f.InNews {
			hf.InNews++
		}
		if f.Site != "" {
			continue
		}
		osf = append(osf, f)
		if f.NotRunning { // an old kernel's fix is removing it
			hf.NotRunning++
			continue
		}
		if f.KernelStatus == kernel.StatusUserland {
			hf.Userland++
		}
		if f.Fixed == "" {
			nf := noFix[f.Package]
			if nf == nil {
				nf = &noFixFact{Package: clip(f.Package, 100), Worst: f.Severity}
				noFix[f.Package] = nf
			}
			nf.Findings++
			if sevRank[f.Severity] > sevRank[nf.Worst] {
				nf.Worst = f.Severity
			}
		}
	}
	slices.SortFunc(osf, rank)
	for i, f := range osf {
		if i == top {
			break
		}
		hf.Top = append(hf.Top, finding(f, lv.summaries))
	}
	if !full {
		return hf
	}
	for _, nf := range noFix {
		hf.NoFix = append(hf.NoFix, *nf)
	}
	slices.SortFunc(hf.NoFix, func(a, b noFixFact) int { return cmp.Or(b.Findings-a.Findings, strings.Compare(a.Package, b.Package)) })
	if len(hf.NoFix) > 15 {
		hf.NoFix = hf.NoFix[:15]
	}
	for _, rt := range d.rep.Runtimes {
		hf.Runtimes = append(hf.Runtimes, runtimeFact{Name: clip(rt.Name, 40), Version: clip(rt.Version, 40), Life: life(rt.Life)})
	}
	for _, s := range d.rep.Sites {
		hf.Sites = append(hf.Sites, siteFactFor(s, d.rep.Findings, lv))
	}
	for i, a := range d.anoms {
		if i == lv.anomalies {
			break
		}
		hf.Anomalies = append(hf.Anomalies, anomalyFact{Rule: a.Rule, Severity: a.Severity, Summary: clip(a.Summary, 200),
			Detected: a.DetectedAt.UTC().Format(time.RFC3339)})
	}
	for i, n := range d.news {
		if i == 10 {
			break
		}
		hf.News = append(hf.News, newsFact{Title: clip(n.Title, 160), Severity: n.Severity, Status: n.Status})
	}
	return hf
}

const fixLabel = "Upgrade the packages that fix its OS findings"

// fixCommand is the host page's "upgrade the packages that fix these"
// command (see report.PlanUpgrade: only packages with a pending update),
// with its label and the upgrade it comes from. Past maxCommandPkgs it
// keeps the packages behind the highest-ranked findings. A kernel fix (see
// internal/kernel) goes through the installed kernel metapackages on
// Debian and Ubuntu when they have an update, or a full upgrade when
// there are none; findings a reboot clears add nothing.
func fixCommand(pm string, list []report.Finding, pkgs report.Pkgs) (cmd, label string, u report.Upgrade) {
	prefix := commandPrefixes[pm]
	if len(prefix) == 0 {
		return "", "", u
	}
	list = slices.Clone(list)
	slices.SortFunc(list, rank)
	u = report.PlanUpgrade(pm, list, pkgs)
	if u.FullUpgrade {
		return kernel.DpkgFullUpgrade, "Upgrade every package: its OS findings include a kernel fix, but no kernel metapackage " +
			"is installed, so apt won't install the new kernel by itself (installing the kernel's metapackage fixes that). Reboot afterwards", u
	}
	metas := u.Metas[:min(len(u.Metas), maxCommandPkgs)]
	names := slices.Clone(metas)
	for _, n := range u.Names {
		if len(names) >= maxCommandPkgs {
			break
		}
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return "", "", u
	}
	slices.Sort(names)
	label = fixLabel
	switch {
	case len(metas) > 0:
		label += ", including the kernel through its metapackage (" + strings.Join(metas, ", ") + "). Reboot afterwards to run the new kernel"
	case u.Kernel:
		label += ", including the kernel. Reboot afterwards to run the new kernel"
	}
	return prefix[0] + " " + strings.Join(names, " "), label + " (only packages with a pending update)", u
}

// oldKernelCommand removes the kernels older than the running one, when
// findings are on them: upgrading never clears those (see kernel.Older).
func oldKernelCommand(pm string, pkgs []string, findings int) []commandFact {
	var names []string
	for _, p := range pkgs {
		if safePackage.MatchString(p) && kernel.ABIPackage(pm, p) {
			names = append(names, p)
		}
	}
	if pm != "dpkg" || findings == 0 || len(names) == 0 || len(names) > maxCommandPkgs {
		return nil
	}
	return []commandFact{{Label: "Remove the older kernels that are installed but not running (their findings clear; no reboot needed, " +
		"but afterwards there's no older kernel to boot)", Command: kernel.PurgePrefix + " " + strings.Join(names, " ")}}
}

// rebootCommand is the reboot suggestion, when one is or will be needed.
func rebootCommand(reboot *bool, kernelFix, rebootFindings bool) []commandFact {
	switch {
	case kernelFix && rebootFindings:
		return []commandFact{{Label: "Reboot after the kernel update, to run the new kernel (this also clears the findings with kernel_status reboot_pending)", Command: RebootCommand}}
	case kernelFix:
		return []commandFact{{Label: "Reboot after the kernel update, to run the new kernel", Command: RebootCommand}}
	case reboot != nil && *reboot:
		return []commandFact{{Label: "Reboot (after updates)", Command: RebootCommand}}
	}
	return nil
}

func siteFactFor(s report.Site, all []report.Finding, lv detail) siteFact {
	name := s.Root
	if len(s.ServerNames) > 0 && s.ServerNames[0] != "_" && s.ServerNames[0] != "" {
		name = s.ServerNames[0]
	}
	sf := siteFact{Name: clip(name, 253), Root: clip(s.Root, 200), Framework: clip(s.Framework, 40),
		FrameworkVersion: clip(s.FrameworkVersion, 40), FrameworkLife: life(s.FrameworkLife), PHP: clip(s.PHPFPM, 20),
		PHPLife: life(s.PHPLife), PHPRequirement: clip(s.PHPRequirement, 60), PHPAllowed: s.PHPSatisfied, Counts: s.Counts}
	var fs []report.Finding
	for _, f := range all {
		if f.Site == s.Root && f.Fixed != "" {
			fs = append(fs, f)
		}
	}
	slices.SortFunc(fs, rank)
	for i, f := range fs {
		if i == lv.siteFix {
			break
		}
		sf.Fixable = append(sf.Fixable, finding(f, false))
	}
	return sf
}

func windowText(w store.Window) string {
	where := "whole org"
	switch {
	case w.Host != "":
		where = "host " + w.Host
	case w.EnvSlug != "":
		where = "env " + w.EnvSlug
	}
	name := ""
	if w.Name != "" {
		name = w.Name + ": "
	}
	if w.Weekly() {
		var days []string
		for i, d := range []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"} {
			if w.Weekdays&(1<<i) != 0 {
				days = append(days, d)
			}
		}
		return clip(fmt.Sprintf("%sweekly %s %s for %s (%s), %s", name, strings.Join(days, ","), w.StartTime, w.Duration, w.Timezone, where), 200)
	}
	return clip(fmt.Sprintf("%s%s to %s, %s", name, w.Starts.UTC().Format(time.RFC3339), w.Ends.UTC().Format(time.RFC3339), where), 200)
}

func (src Sources) windows(ctx context.Context, sc store.Scope, hostName string) ([]string, error) {
	ws, err := src.Store.Windows(ctx, sc)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, w := range ws {
		if w.Weekly() || w.Ends.After(src.Now) {
			if hostName == "" || w.Host == "" || w.Host == hostName {
				out = append(out, windowText(w))
			}
		}
		if len(out) == 10 {
			break
		}
	}
	return out, nil
}

func orgScope(orgID int64) store.Scope {
	return store.Scope{Orgs: map[int64]store.Role{orgID: store.RoleViewer}}
}

// fit marshals at the most detailed level that fits the budget (bytes/4
// estimates tokens), falling back to the least detailed one.
func fit(budgetTokens int, build func(detail) any) ([]byte, error) {
	var b []byte
	var err error
	for _, lv := range detailLevels {
		if b, err = json.Marshal(build(lv)); err != nil {
			return nil, err
		}
		if len(b)/4 <= budgetTokens {
			return b, nil
		}
	}
	if len(b)/4 > budgetTokens {
		return nil, fmt.Errorf("the facts don't fit max_input_tokens (%d, need about %d)", budgetTokens, len(b)/4)
	}
	return b, nil
}

// BuildHost gathers the facts for one host.
func (src Sources) BuildHost(ctx context.Context, org store.Org, host store.IngestHost, budget int) ([]byte, Allowed, error) {
	data, err := src.load(ctx, org, host.ID, time.Time{})
	if err != nil {
		return nil, Allowed{}, err
	}
	if len(data) == 0 {
		return nil, Allowed{}, store.ErrNotFound
	}
	d := data[0]
	wins, err := src.windows(ctx, orgScope(org.ID), host.Name)
	if err != nil {
		return nil, Allowed{}, err
	}
	b, err := fit(budget, func(lv detail) any {
		return HostFacts{Today: src.Now.Format("2006-01-02"), Host: src.fact(d, lv, lv.top, true), Windows: wins}
	})
	return b, Allowed{Hosts: map[string]HostAllowed{d.host.Name: d.allowed(true)}}, err
}

// BuildFleet gathers the facts for an org's brief, covering changes since
// since.
func (src Sources) BuildFleet(ctx context.Context, org store.Org, since time.Time, budget int) ([]byte, Allowed, int, error) {
	data, err := src.load(ctx, org, 0, since)
	if err != nil {
		return nil, Allowed{}, 0, err
	}
	sc := orgScope(org.ID)
	wins, err := src.windows(ctx, sc, "")
	if err != nil {
		return nil, Allowed{}, 0, err
	}
	anoms, err := src.Store.OpenAnomalies(ctx, sc)
	if err != nil {
		return nil, Allowed{}, 0, err
	}
	news, err := src.Store.News(ctx, sc)
	if err != nil {
		return nil, Allowed{}, 0, err
	}
	plans, err := src.Store.ListPlans(ctx, sc)
	if err != nil {
		return nil, Allowed{}, 0, err
	}
	// Most urgent hosts first, so trimming drops the quiet ones.
	slices.SortStableFunc(data, func(a, b hostData) int {
		ra, rb := a.rep.Counts, b.rep.Counts
		return cmp.Or(rb.KEV-ra.KEV, rb.Critical-ra.Critical, b.sum.PendingSecurity-a.sum.PendingSecurity,
			rb.High-ra.High, rb.Fixable-ra.Fixable, strings.Compare(a.host.Name, b.host.Name))
	})
	var totals fleetTotals
	allowed := Allowed{Hosts: map[string]HostAllowed{}}
	for _, d := range data {
		allowed.Hosts[d.host.Name] = d.allowed(false)
		totals.Hosts++
		totals.KEV += d.rep.Counts.KEV
		totals.Critical += d.rep.Counts.Critical
		totals.PendingSecurity += d.sum.PendingSecurity
		if d.rep.Counts.Fixable > 0 {
			totals.HostsFixable++
		}
		eolHost := d.rep.OSLife != nil && d.rep.OSLife.EOL
		for _, rt := range d.rep.Runtimes {
			eolHost = eolHost || (rt.Life != nil && rt.Life.EOL)
		}
		if eolHost {
			totals.HostsEOL++
		}
		if d.sum.RebootRequired != nil && *d.sum.RebootRequired {
			totals.Reboots++
		}
		if src.StaleAfter > 0 && src.Now.Sub(d.sum.ReceivedAt) > src.StaleAfter {
			totals.Stale++
		}
		if d.changes != nil {
			totals.NewFindings += d.changes.New
			totals.Resolved += d.changes.Resolved
		}
	}
	period := int(src.Now.Sub(since).Hours())
	b, err := fit(budget, func(lv detail) any {
		ff := FleetFacts{Today: src.Now.Format("2006-01-02"), Org: org.Slug, PeriodHours: period, Totals: totals, Hosts: []hostFact{}}
		for i, d := range data {
			if i == lv.hosts {
				ff.MoreHosts = len(data) - i
				break
			}
			hf := src.fact(d, lv, lv.perHost, false)
			for _, s := range d.rep.Sites {
				if (s.FrameworkLife != nil && s.FrameworkLife.EOL) || (s.PHPLife != nil && s.PHPLife.EOL) || s.Counts.Fixable > 0 ||
					(s.PHPSatisfied != nil && !*s.PHPSatisfied) {
					hf.Sites = append(hf.Sites, siteFactFor(s, d.rep.Findings, detail{siteFix: min(lv.siteFix, 2)}))
				}
			}
			ff.Hosts = append(ff.Hosts, hf)
		}
		for i, a := range anoms {
			if i == lv.anomalies {
				break
			}
			ff.Anomalies = append(ff.Anomalies, anomalyFact{Host: clip(a.Host.Name, 253), Rule: a.Rule, Severity: a.Severity,
				Summary: clip(a.Summary, 200), Detected: a.DetectedAt.UTC().Format(time.RFC3339)})
		}
		for _, n := range news {
			if len(n.Hosts) == 0 || len(ff.News) == 10 {
				continue
			}
			nf := newsFact{Title: clip(n.Title, 160), Severity: n.Severity, Status: n.Status}
			for _, h := range n.Hosts {
				nf.Hosts = append(nf.Hosts, clip(h.Name, 253))
			}
			ff.News = append(ff.News, nf)
		}
		ff.Windows = wins
		for _, p := range plans {
			if p.ClosedAt.IsZero() && p.OrgID == org.ID && len(ff.Plans) < 10 {
				ff.Plans = append(ff.Plans, planFact{Name: clip(p.Name, 100), Hosts: p.Hosts, Done: p.Done, Verified: p.Verified})
			}
		}
		return ff
	})
	return b, allowed, len(data), err
}
