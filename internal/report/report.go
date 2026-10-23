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

	"github.com/chrisreedio/heimdall/internal/composer"
	"github.com/chrisreedio/heimdall/internal/feeds/eol"
	"github.com/chrisreedio/heimdall/internal/findings"
	"github.com/chrisreedio/heimdall/internal/store"
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
	Lockfiles  []string    `json:"lockfiles"` // allowlisted npm/PyPI manifests (findings carry the path as site)
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
	Counts           Counts     `json:"counts"`
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
}

type Counts struct {
	Total      int `json:"total"`
	KEV        int `json:"kev"`
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Unknown    int `json:"unknown"`
	Fixable    int `json:"fixable"`     // a fixed version exists
	FixPending int `json:"fix_pending"` // ...and an already-pending update installs it
	NoFix      int `json:"no_fix"`      // affected, but no fix released yet
}

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
	Site          string    `json:"site,omitempty"` // app root for Composer findings
	EPSS          float64   `json:"epss,omitempty"` // exploit probability (0-1), when known
}

// Filter narrows a report. Scope is required: hosts outside it are never
// included, whatever Org says.
type Filter struct {
	Org   string // org slug, or "" for every visible org
	Scope store.Scope
}

// Build reports on every visible host that has reported.
func Build(ctx context.Context, st *store.Store, f Filter, now time.Time) (*Report, error) {
	orgSlug := f.Org
	hosts, err := st.HostsWithSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	r := &Report{GeneratedAt: now.UTC(), Hosts: []Host{}}
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
		if !f.Scope.CanView(h.OrgID) || (orgSlug != "" && h.OrgSlug != orgSlug) {
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

		fs, err := st.OpenFindings(ctx, h.ID)
		if err != nil {
			return nil, err
		}
		for _, f := range fs {
			host.Findings = append(host.Findings, Finding{
				Advisory: f.AdvisoryID, CVEs: nonNil(f.CVEs), Severity: f.Severity, CVSS: f.CVSS,
				KEV: f.KEV, KEVRansomware: f.KEVRansomware, Package: f.Package, Version: f.Version,
				Binaries: nonNil(f.Binaries), Fixed: f.FixedVersion, FixPending: f.FixPending,
				Summary: f.Summary, FirstSeen: f.FirstSeen, Site: f.SiteRoot, EPSS: f.EPSS,
			})
			host.Counts.add(f)
		}
		for _, s := range inv.Sites {
			site, err := buildSite(s, fs, lifecycle)
			if err != nil {
				return nil, err
			}
			host.Sites = append(host.Sites, site)
		}
		r.Hosts = append(r.Hosts, host)
	}
	return r, nil
}

func buildSite(s store.InventorySite, fs []store.ReportFinding, lifecycle func(product, cycle string) (*Lifecycle, error)) (Site, error) {
	site := Site{
		Root: s.Root, DocumentRoot: s.DocumentRoot, ServerNames: nonNil(s.ServerNames), WebServer: s.WebServer,
		Readable: s.Readable, PHPFPM: s.PHPFPMVersion, PHPRequirement: s.PHPRequirement,
		Framework: s.Framework, FrameworkVersion: s.FrameworkVersion, Packages: len(s.Packages),
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
	for _, f := range fs {
		if f.SiteRoot == s.Root {
			site.Counts.add(f)
		}
	}
	return site, nil
}

func (c *Counts) add(f store.ReportFinding) {
	c.Total++
	if f.KEV {
		c.KEV++
	}
	if f.FixPending {
		c.FixPending++
	}
	if f.FixedVersion != "" {
		c.Fixable++
	} else {
		c.NoFix++
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
				fmt.Fprintf(w, "    %d Composer packages, %d findings (%d fixable)\n", s.Packages, s.Counts.Total, s.Counts.Fixable)
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
