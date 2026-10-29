// SPDX-License-Identifier: AGPL-3.0-or-later

// Package report assembles what the CLI (and later the UI) shows: per-host
// findings, OS and runtime lifecycle, and counts.
package report

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/clientonly"
	"github.com/realmwatch/heimdall/internal/composer"
	"github.com/realmwatch/heimdall/internal/feeds/eol"
	"github.com/realmwatch/heimdall/internal/findings"
	"github.com/realmwatch/heimdall/internal/kernel"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/version"
)

type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Hosts       []Host    `json:"hosts"`
}

type Host struct {
	Org        string      `json:"org"`
	Name       string      `json:"host"`
	OS         string      `json:"os"`
	LastSeen   time.Time   `json:"last_seen"`
	Ecosystem  string      `json:"ecosystem"` // "" if vulnerability matching isn't supported for this OS
	OSLife     *Lifecycle  `json:"os_lifecycle,omitempty"`
	Runtimes   []Runtime   `json:"runtimes"`
	Counts     Counts      `json:"counts"` // all findings, OS and sites
	Findings   []Finding   `json:"findings"`
	Sites      []Site      `json:"sites"`
	Containers []Container `json:"containers"`
	Lockfiles  []string    `json:"lockfiles"`        // allowlisted npm/PyPI manifests (findings carry the path as site)
	Kernel     string      `json:"kernel,omitempty"` // the running kernel release (uname -r)
	// OldKernels are installed Debian/Ubuntu kernel packages for releases
	// older than the running one: on disk, not in use (see kernel.Older).
	OldKernels []string `json:"old_kernels,omitempty"`
	// KernelState is kernel.State.Name: current, reboot_pending,
	// old_kernels or reboot_pending_and_old_kernels ("" if unknown).
	KernelState string `json:"kernel_state,omitempty"`
	// NewerKernel is the newer kernel that's installed but not running
	// yet, when a reboot is pending.
	NewerKernel string `json:"newer_kernel,omitempty"`
	// PHPKnown: the collector reported what uses PHP, so the PHP
	// runtimes' Use is set (php.go).
	PHPKnown bool `json:"php_known,omitempty"`
}

type Container struct {
	Name   string `json:"name"`
	Image  string `json:"image"`
	Tag    string `json:"tag"`
	Digest string `json:"digest,omitempty"`
	State  string `json:"state"`
}

// Site is a web app on the host, with its lifecycle and findings summary.
type Site struct {
	Root             string     `json:"root"`
	DocumentRoot     string     `json:"document_root"`
	ServerNames      []string   `json:"server_names"`
	WebServer        string     `json:"web_server"`
	Readable         bool       `json:"readable"`
	PHPFPM           string     `json:"php_fpm_version"`
	PHPLife          *Lifecycle `json:"php_lifecycle,omitempty"`
	PHPRequirement   string     `json:"php_requirement"`
	PHPSatisfied     *bool      `json:"php_requirement_met,omitempty"` // nil when unknown
	Framework        string     `json:"framework"`
	FrameworkVersion string     `json:"framework_version"`
	FrameworkLife    *Lifecycle `json:"framework_lifecycle,omitempty"`
	DeployedAt       *time.Time `json:"deployed_at,omitempty"`
	Packages         int        `json:"composer_packages"`
	NpmPackages      int        `json:"npm_packages"` // from package-lock.json (collector snapshot v4)
	NpmDev           int        `json:"npm_dev_packages"`
	Counts           Counts     `json:"counts"` // Composer and npm findings
}

type Lifecycle struct {
	Product  string     `json:"product"`
	Cycle    string     `json:"cycle"`
	Known    bool       `json:"known"` // false until endoflife.date data is synced
	EOL      bool       `json:"eol"`
	EOLDate  *time.Time `json:"eol_date,omitempty"`
	DaysLeft int        `json:"days_left,omitempty"`
}

type Runtime struct {
	Name    string     `json:"name"`
	Version string     `json:"version"`
	Package string     `json:"package"`
	Life    *Lifecycle `json:"lifecycle,omitempty"`
	// Use is what uses a PHP version, when the host's collector reports
	// it (see php.go).
	Use *PHPUse `json:"use,omitempty"`
}

type Counts struct {
	Total      int `json:"total"`
	KEV        int `json:"kev"`
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Unknown    int `json:"unknown"`
	Fixable    int `json:"fixable"`               // a fixed version exists
	FixPending int `json:"fix_pending"`           // ...and an already-pending update installs it
	NoFix      int `json:"no_fix"`                // affected, but no fix released yet
	FixUrgent  int `json:"fixable_critical_high"` // fixable, and critical or high
	InNews     int `json:"in_news"`               // named by a live threat-news incident
	// NotRunning are on old kernels that are installed but not running:
	// not live exposure, so they're left out of KEV, FixPending, Fixable,
	// FixUrgent and NoFix (Total = Fixable + NoFix + NotRunning).
	NotRunning int `json:"not_running"`
	// RebootPending are on the running kernel while a newer one is
	// installed: still live, and counted everywhere, until the reboot.
	RebootPending int `json:"reboot_pending"`
	// KernelUserland are only on packages built from a kernel source that
	// aren't a kernel (linux-tools-common, linux-libc-dev…): left out like
	// NotRunning (Total = Fixable + NoFix + NotRunning + KernelUserland).
	KernelUserland int `json:"kernel_userland"`
	// Watch are the NoFix findings still worth watching: known-exploited,
	// in the news, or with an EPSS score of at least store.WatchEPSS. On a
	// source installed only for its clients (Finding.ClientOnly), only
	// known-exploited ones.
	// Fixable + Watch is what needs attention (Attention).
	Watch int `json:"watch"`
	// Dev are on npm dev dependencies: needed to build or test a site, not
	// to run it. They're in Total and nothing else, not even the severity
	// counts (Total = Fixable + NoFix + NotRunning + KernelUserland + Dev).
	Dev int `json:"dev"`
}

// Attention is how many findings need attention: everything fixable, and
// the ones with no fix yet that are worth watching.
func (c Counts) Attention() int { return c.Fixable + c.Watch }

type Finding struct {
	Advisory      string    `json:"advisory"`
	CVEs          []string  `json:"cves"`
	Severity      string    `json:"severity"`
	CVSS          float64   `json:"cvss,omitempty"`
	KEV           bool      `json:"kev"`
	KEVRansomware bool      `json:"kev_ransomware,omitempty"`
	Package       string    `json:"package"`
	Version       string    `json:"installed"`
	Binaries      []string  `json:"binaries"`
	Fixed         string    `json:"fixed,omitempty"`
	FixPending    bool      `json:"fix_pending"`
	Summary       string    `json:"summary"`
	FirstSeen     time.Time `json:"first_seen"`
	Site          string    `json:"site,omitempty"`    // app root for Composer and npm findings
	Ecosystem     string    `json:"ecosystem"`         // OSV's: the distro's, "Packagist", "npm" or "PyPI"
	Dev           bool      `json:"dev,omitempty"`     // on an npm dev dependency (see Counts.Dev)
	EPSS          float64   `json:"epss,omitempty"`    // exploit probability (0-1), when known
	InNews        bool      `json:"in_news,omitempty"` // named by a live threat-news incident
	// NotRunning: every package is part of an older kernel that's
	// installed but not running, so removing it (not upgrading) clears it.
	NotRunning bool `json:"not_running,omitempty"`
	// KernelStatus is kernel.State.Status: running, not_running,
	// reboot_pending or newer_kernel, or "" when not on a kernel package.
	KernelStatus string `json:"kernel_status,omitempty"`
	// ClientOnly names the server package that isn't installed when the
	// finding's source is installed only for its clients and libraries
	// (bind9's dig without named): see internal/clientonly.
	ClientOnly string `json:"client_only,omitempty"`
}

// Filter narrows a report. Scope is required: hosts outside it are never
// included, whatever Org says.
type Filter struct {
	Org   string // org slug, or "" for every visible org
	Scope store.Scope
	Host  string // one host's name (in Org), or "" for all
	// CountsOnly leaves Findings empty and tallies Counts in SQL instead,
	// for pages that show counts across many hosts.
	CountsOnly bool
}

// Build reports on every visible host that has reported.
func Build(ctx context.Context, st *store.Store, f Filter, now time.Time) (*Report, error) {
	orgSlug := f.Org
	hosts, err := st.HostsWithSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	r := &Report{GeneratedAt: now.UTC(), Hosts: []Host{}}
	var tallies map[int64]map[string]store.FindingCounts
	if f.CountsOnly {
		if tallies, err = st.OpenFindingCounts(ctx); err != nil {
			return nil, err
		}
	}
	phps, err := st.HostPHPs(ctx)
	if err != nil {
		return nil, err
	}
	eolCache := map[string][]eol.Cycle{}
	cycles := func(product string) ([]eol.Cycle, error) {
		if c, ok := eolCache[product]; ok {
			return c, nil
		}
		rows, err := st.EOLCycles(ctx, product)
		if err != nil {
			return nil, err
		}
		out := make([]eol.Cycle, len(rows))
		for i, c := range rows {
			out[i] = eol.Cycle{Product: product, Cycle: c.Cycle, ReleaseDate: c.ReleaseDate,
				SupportUntil: c.SupportUntil, EOL: c.EOL, EOLReached: c.EOLReached, Latest: c.Latest}
		}
		eolCache[product] = out
		return out, nil
	}
	lifecycle := func(product, cycle string) (*Lifecycle, error) {
		cs, err := cycles(product)
		if err != nil {
			return nil, err
		}
		s := eol.Evaluate(cs, cycle, now)
		return &Lifecycle{Product: product, Cycle: cycle, Known: s.Known, EOL: s.EOL, EOLDate: s.EOLDate, DaysLeft: s.DaysLeft}, nil
	}

	for _, h := range hosts {
		if !f.Scope.CanView(h.OrgID) || (orgSlug != "" && h.OrgSlug != orgSlug) || (f.Host != "" && h.Name != f.Host) {
			continue
		}
		inv, err := st.Inventory(ctx, h)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		sum, err := st.LatestSnapshot(ctx, h.ID)
		if err != nil {
			return nil, err
		}
		host := Host{Org: h.OrgSlug, Name: h.Name, OS: inv.OSPretty, LastSeen: sum.ReceivedAt,
			Runtimes: []Runtime{}, Findings: []Finding{}, Sites: []Site{}, Containers: []Container{}, Lockfiles: []string{}}
		for _, c := range inv.Containers {
			host.Containers = append(host.Containers, Container(c))
		}
		for _, l := range inv.Lockfiles {
			host.Lockfiles = append(host.Lockfiles, l.Path)
		}
		if host.OS == "" {
			host.OS = strings.TrimSpace(inv.OSID + " " + inv.OSVersion)
		}
		host.Kernel = sum.Kernel
		pm := hostPM(inv)
		ks := kernel.HostState(pm, host.Kernel, InstalledKernels(inv))
		host.OldKernels, host.KernelState, host.NewerKernel = ks.Old, ks.Name(), ks.Newer

		if info, ok := findings.HostEcosystem(inv); ok {
			host.Ecosystem = info.OSV
		}
		if product, cycle, ok := eol.OSCycle(inv.OSID, inv.OSVersion, inv.OSIDLike); ok {
			if host.OSLife, err = lifecycle(product, cycle); err != nil {
				return nil, err
			}
		}
		for _, rt := range findings.HostRuntimes(inv) {
			out := Runtime{Name: rt.Name, Version: rt.Version, Package: rt.Package}
			if cycle, ok := eol.RuntimeCycle(rt.Name, rt.Version); ok {
				if out.Life, err = lifecycle(rt.Name, cycle); err != nil {
					return nil, err
				}
			}
			host.Runtimes = append(host.Runtimes, out)
		}

		siteCounts := map[string]Counts{}
		if f.CountsOnly {
			for root, c := range tallies[h.ID] {
				siteCounts[root] = countsFrom(c)
				host.Counts.merge(countsFrom(c))
			}
		} else {
			fs, err := st.OpenFindings(ctx, h.ID)
			if err != nil {
				return nil, err
			}
			co := clientOnly(inv)
			for _, f := range fs {
				status, server := "", ""
				if f.SiteRoot == "" {
					status, server = ks.Status(f.Binaries), co[f.Package]
				}
				host.Findings = append(host.Findings, Finding{
					Advisory: f.AdvisoryID, CVEs: nonNil(f.CVEs), Severity: f.Severity, CVSS: f.CVSS,
					KEV: f.KEV, KEVRansomware: f.KEVRansomware, Package: f.Package, Version: f.Version,
					Binaries: nonNil(f.Binaries), Fixed: f.FixedVersion, FixPending: f.FixPending,
					Summary: f.Summary, FirstSeen: f.FirstSeen, Site: f.SiteRoot, Ecosystem: f.Ecosystem, Dev: f.Dev,
					EPSS: f.EPSS, InNews: f.InNews,
					NotRunning: status == kernel.StatusNotRunning, KernelStatus: status, ClientOnly: server,
				})
				host.Counts.add(f, status, server != "")
				c := siteCounts[f.SiteRoot]
				c.add(f, status, server != "")
				siteCounts[f.SiteRoot] = c
			}
		}
		for _, s := range inv.Sites {
			site, err := buildSite(s, siteCounts[s.Root], lifecycle)
			if err != nil {
				return nil, err
			}
			host.Sites = append(host.Sites, site)
		}
		if p, ok := phps[h.ID]; ok && findings.PackageManager(inv) == "dpkg" {
			phpUse(&host, p, inv.Packages)
		}
		r.Hosts = append(r.Hosts, host)
	}
	return r, nil
}

// InstalledKernels is the inventory's packages as internal/kernel takes
// them.
func InstalledKernels(inv store.HostInventory) []kernel.Installed {
	out := make([]kernel.Installed, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		out = append(out, kernel.Installed{Name: p.Name, Version: p.Version, Arch: p.Arch})
	}
	return out
}

// hostPM is the host's package manager (dpkg, rpm, apk), or "".
func hostPM(inv store.HostInventory) string {
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

func buildSite(s store.InventorySite, counts Counts, lifecycle func(product, cycle string) (*Lifecycle, error)) (Site, error) {
	site := Site{
		Root: s.Root, DocumentRoot: s.DocumentRoot, ServerNames: nonNil(s.ServerNames), WebServer: s.WebServer,
		Readable: s.Readable, PHPFPM: s.PHPFPMVersion, PHPRequirement: s.PHPRequirement,
		Framework: s.Framework, FrameworkVersion: s.FrameworkVersion, Packages: len(s.Packages), Counts: counts,
		NpmPackages: len(s.NpmPackages),
	}
	for _, p := range s.NpmPackages {
		if p.Dev {
			site.NpmDev++
		}
	}
	if !s.DeployedAt.IsZero() {
		d := s.DeployedAt
		site.DeployedAt = &d
	}
	var err error
	if s.PHPFPMVersion != "" {
		if site.PHPLife, err = lifecycle(eol.ProductPHP, s.PHPFPMVersion); err != nil {
			return site, err
		}
		if s.PHPRequirement != "" {
			if c, perr := composer.Parse(s.PHPRequirement); perr == nil {
				ok := c.AllowsMinor(s.PHPFPMVersion)
				site.PHPSatisfied = &ok
			}
		}
	}
	if s.Framework == "laravel" && s.FrameworkVersion != "" {
		if cycle, ok := eol.RuntimeCycle(eol.ProductLaravel, s.FrameworkVersion); ok {
			if site.FrameworkLife, err = lifecycle(eol.ProductLaravel, cycle); err != nil {
				return site, err
			}
		}
	}
	return site, nil
}

// add counts one finding with its kernel status, and whether it's on a
// source installed only for its clients (Finding.ClientOnly). The store's
// recount (countsSQL in internal/store) counts the same way.
func (c *Counts) add(f store.ReportFinding, kernelStatus string, clientOnly bool) {
	c.Total++
	if f.Dev {
		c.Dev++
		return
	}
	switch {
	case kernelStatus == kernel.StatusNotRunning:
		c.NotRunning++
	case kernelStatus == kernel.StatusUserland:
		c.KernelUserland++
	case f.FixedVersion != "":
		c.Fixable++
		if f.Severity == "critical" || f.Severity == "high" {
			c.FixUrgent++
		}
	default:
		c.NoFix++
		if f.KEV || (!clientOnly && (f.InNews || f.EPSS >= store.WatchEPSS)) {
			c.Watch++
		}
	}
	if kernelStatus != kernel.StatusNotRunning && kernelStatus != kernel.StatusUserland {
		if f.KEV {
			c.KEV++
		}
		if f.FixPending {
			c.FixPending++
		}
	}
	if kernelStatus == kernel.StatusRebootPending {
		c.RebootPending++
	}
	if f.InNews {
		c.InNews++
	}
	switch f.Severity {
	case "critical":
		c.Critical++
	case "high":
		c.High++
	case "medium":
		c.Medium++
	case "low":
		c.Low++
	default:
		c.Unknown++
	}
}

// countsFrom converts the store's SQL tally.
func countsFrom(c store.FindingCounts) Counts {
	return Counts{Total: c.Total, KEV: c.KEV, Critical: c.Critical, High: c.High, Medium: c.Medium, Low: c.Low,
		Unknown: c.Unknown, Fixable: c.Fixable, FixPending: c.FixPending, NoFix: c.NoFix, FixUrgent: c.FixUrgent,
		InNews: c.InNews, NotRunning: c.NotRunning, RebootPending: c.RebootPending,
		KernelUserland: c.KernelUserland, Watch: c.Watch, Dev: c.Dev}
}

func (c *Counts) merge(o Counts) {
	c.Total += o.Total
	c.KEV += o.KEV
	c.Critical += o.Critical
	c.High += o.High
	c.Medium += o.Medium
	c.Low += o.Low
	c.Unknown += o.Unknown
	c.Fixable += o.Fixable
	c.FixPending += o.FixPending
	c.NoFix += o.NoFix
	c.FixUrgent += o.FixUrgent
	c.InNews += o.InNews
	c.NotRunning += o.NotRunning
	c.RebootPending += o.RebootPending
	c.KernelUserland += o.KernelUserland
	c.Watch += o.Watch
	c.Dev += o.Dev
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// WriteText renders a human summary, showing up to limit findings per host.
func WriteText(w io.Writer, r *Report, limit int) {
	if len(r.Hosts) == 0 {
		fmt.Fprintln(w, "No hosts have reported yet.")
		return
	}
	for i, h := range r.Hosts {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s (org %s): %s, last seen %s\n", h.Name, h.Org, h.OS, h.LastSeen.Local().Format("2006-01-02 15:04"))
		if h.OSLife != nil {
			fmt.Fprintf(w, "  OS lifecycle: %s\n", h.OSLife.describe())
		}
		for _, rt := range h.Runtimes {
			life := "lifecycle unknown"
			if rt.Life != nil {
				life = rt.Life.describe()
			}
			fmt.Fprintf(w, "  Runtime: %s %s (%s)\n", rt.Name, rt.Version, life)
		}
		if h.Ecosystem == "" {
			fmt.Fprintln(w, "  Findings: vulnerability matching isn't supported for this OS yet")
			continue
		}
		c := h.Counts
		fmt.Fprintf(w, "  Findings: %d open (%d KEV, %d critical, %d high, %d medium, %d low, %d unrated)\n",
			c.Total, c.KEV, c.Critical, c.High, c.Medium, c.Low, c.Unknown)
		fmt.Fprintf(w, "            %d fixable now (%d via updates already pending), %d with no fix released yet\n",
			c.Fixable, c.FixPending, c.NoFix)
		if c.NotRunning > 0 {
			fmt.Fprintf(w, "            %d on old kernels that are installed but not running\n", c.NotRunning)
		}
		if c.KernelUserland > 0 {
			fmt.Fprintf(w, "            %d on kernel userland packages (tools, headers), not the running kernel\n", c.KernelUserland)
		}
		if h.NewerKernel != "" {
			fmt.Fprintf(w, "  Kernel: %s installed but %s still running: reboot to run it (%d findings clear)\n",
				h.NewerKernel, h.Kernel, c.RebootPending)
		}
		for _, s := range h.Sites {
			fmt.Fprintf(w, "  Site: %s (%s)\n", s.Root, strings.Join(s.ServerNames, ", "))
			if s.Framework != "" {
				life := "lifecycle unknown"
				if s.FrameworkLife != nil {
					life = s.FrameworkLife.describe()
				}
				fmt.Fprintf(w, "    %s %s (%s)\n", s.Framework, s.FrameworkVersion, life)
			}
			if s.PHPFPM != "" {
				life := "lifecycle unknown"
				if s.PHPLife != nil {
					life = s.PHPLife.describe()
				}
				req := ""
				if s.PHPSatisfied != nil && !*s.PHPSatisfied {
					req = fmt.Sprintf("; DOES NOT satisfy composer.json php %s", s.PHPRequirement)
				}
				fmt.Fprintf(w, "    PHP-FPM %s (%s%s)\n", s.PHPFPM, life, req)
			}
			if !s.Readable {
				fmt.Fprintln(w, "    composer files not readable by the collector")
			} else if s.Packages > 0 {
				fmt.Fprintf(w, "    %d Composer and %d npm packages, %d findings (%d fixable)\n", s.Packages, s.NpmPackages, s.Counts.Total, s.Counts.Fixable)
			}
		}
		for j, f := range h.Findings {
			if j == limit {
				fmt.Fprintf(w, "    … and %d more (use --format json or --limit 0 for all)\n", len(h.Findings)-limit)
				break
			}
			tag := "   "
			if f.KEV {
				tag = "KEV"
			}
			id := f.Advisory
			if len(f.CVEs) > 0 {
				id = f.CVEs[0]
			}
			fix := "no fix yet"
			switch {
			case f.FixPending:
				fix = "fixed in " + f.Fixed + ", update pending"
			case f.Fixed != "":
				fix = "fixed in " + f.Fixed
			}
			where := ""
			if f.Site != "" {
				where = " in " + f.Site
			}
			fmt.Fprintf(w, "    %s %-8s %-16s %s %s%s (%s)\n", tag, f.Severity, id, f.Package, f.Version, where, fix)
		}
	}
}

func (l *Lifecycle) describe() string {
	name := l.Product + " " + l.Cycle
	switch {
	case !l.Known:
		return name + ": no lifecycle data (run `heimdall feeds sync`)"
	case l.EOL && l.EOLDate != nil:
		return fmt.Sprintf("%s: END OF LIFE since %s", name, l.EOLDate.Format(time.DateOnly))
	case l.EOL:
		return name + ": END OF LIFE"
	case l.EOLDate != nil:
		return fmt.Sprintf("%s: supported until %s (%d days)", name, l.EOLDate.Format(time.DateOnly), l.DaysLeft)
	}
	return name + ": supported, no end date announced"
}

// clientOnly is clientonly.Sources for a Debian/Ubuntu host's packages.
func clientOnly(inv store.HostInventory) map[string]string {
	if findings.PackageManager(inv) != "dpkg" {
		return nil
	}
	pkgs := make([]clientonly.Package, len(inv.Packages))
	for i, p := range inv.Packages {
		pkgs[i] = clientonly.Package{Name: p.Name, Source: p.SourceName}
	}
	return clientonly.Sources(pkgs)
}
