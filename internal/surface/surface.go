// SPDX-License-Identifier: AGPL-3.0-or-later

// Package surface builds the attack-surface map: one row per public
// hostname, followed all the way through. Hostname → zone (and plan) →
// DNS record (proxied?) → Heimdall host → site on that host → the
// vulnerability findings there, worst first. Hostnames come from the
// synced Cloudflare zones and from the server names collectors report, so
// the map works (with less in it) without Cloudflare. See docs/surface.md.
package surface

import (
	"cmp"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/cloudflare"
	"github.com/realmwatch/heimdall/internal/store"
)

// Input is everything stored that the map joins. Zones and Records are
// empty when Cloudflare is off.
type Input struct {
	Zones    []store.CloudflareZone
	Records  []store.CloudflareRecord
	Settings map[string]store.SurfaceSettings // by zone ID
	CNAMEs   map[string]store.CNAMECheck      // by target
	Addrs    []store.ReportAddr               // hosts' report addresses
	Sites    []store.SiteNames                // sites' server names
	Hosts    []store.SurfaceHost
	Stacks   []store.SurfaceSite
	Counts   map[int64]map[string]store.FindingCounts // host ID → site root ("" = OS) → open findings
	Known    func(netip.Addr) bool                    // someone recognizes the address (cloudflare.Known)
	Probes   map[netip.Addr]store.DanglingProbe       // what answers at dangling records' addresses (cloudflare.Prober)
	Now      time.Time
}

// Sev is open findings by severity.
type Sev struct {
	KEV, Critical, High, Medium, Low int
}

func sevOf(c store.FindingCounts) Sev {
	return Sev{KEV: c.KEV, Critical: c.Critical, High: c.High, Medium: c.Medium, Low: c.Low}
}

func (s *Sev) add(o Sev) {
	s.KEV, s.Critical, s.High, s.Medium, s.Low = s.KEV+o.KEV, s.Critical+o.Critical, s.High+o.High, s.Medium+o.Medium, s.Low+o.Low
}

// Total counts every severity.
func (s Sev) Total() int { return s.Critical + s.High + s.Medium + s.Low }

// Host is a host a name leads to, with its OS findings.
type Host struct {
	OrgID  int64  `json:"-"`
	Org    string `json:"org"`
	Name   string `json:"host"`
	OS     string `json:"os,omitempty"`
	Counts Sev    `json:"counts"` // OS packages only; sites are counted on their own
}

// Site is a site serving the name, with its stack and findings.
type Site struct {
	OrgID    int64  `json:"-"`
	Org      string `json:"org"`
	Host     string `json:"host"`
	Root     string `json:"root"`
	Software string `json:"software,omitempty"` // "Laravel 11.31.0 · PHP 8.3 · nginx"
	Counts   Sev    `json:"counts"`
}

// Label is the site's last path element ("app.example.com" for
// /home/forge/app.example.com), what people call it.
func (s Site) Label() string {
	if l := path.Base(strings.TrimRight(s.Root, "/")); l != "." && l != "/" {
		return l
	}
	return s.Root
}

// Flag levels.
const (
	High   = "high"
	Medium = "medium"
	Info   = "info"
)

// Flag is something risky about a name or a zone.
type Flag struct {
	Kind  string `json:"kind"`  // wildcard, third-party, takeover, dangling, ssl-off, ...
	Level string `json:"level"` // High, Medium, Info
	Note  string `json:"note"`
}

// Row statuses.
const (
	Proxied   = "proxied"
	Unproxied = "unproxied"
	NoRecord  = "no-record" // in a synced zone that has no record for it
	OffCF     = "not-on-cloudflare"
)

// Row is one public hostname, followed through.
type Row struct {
	Name     string                   `json:"name"`
	Zone     string                   `json:"zone,omitempty"`
	ZoneID   string                   `json:"-"`
	Plan     string                   `json:"plan,omitempty"`
	Status   string                   `json:"status"`
	Records  []store.CloudflareRecord `json:"-"`
	Targets  []string                 `json:"targets,omitempty"`  // "A 203.0.113.10", "CNAME app.herokuapp.com"
	Wildcard bool                     `json:"wildcard,omitempty"` // a wildcard record, or a name only a wildcard covers
	// Exposed: not proxied, and leads straight to one of our hosts.
	Exposed bool   `json:"exposed"`
	Hosts   []Host `json:"hosts"`
	Sites   []Site `json:"sites"`
	Worst   Sev    `json:"worst"` // the hosts' OS findings plus the sites'
	Flags   []Flag `json:"flags,omitempty"`
	// ZoneFlags are the zone's (SSL mode and the like), repeated per row.
	ZoneFlags []Flag `json:"zone_flags,omitempty"`
}

// Vulnerable: a critical or high finding behind the name.
func (r Row) Vulnerable() bool { return r.Worst.Critical+r.Worst.High > 0 }

// ViaWildcard: only a wildcard record covers the name (the wildcard's own
// row carries a wildcard flag instead).
func (r Row) ViaWildcard() bool { return r.Wildcard && !strings.HasPrefix(r.Name, "*.") }

// LooseSites are the sites on none of the row's hosts.
func (r Row) LooseSites() []Site {
	var out []Site
	for _, s := range r.Sites {
		if !slices.ContainsFunc(r.Hosts, func(h Host) bool { return h.Name == s.Host && h.Org == s.Org }) {
			out = append(out, s)
		}
	}
	return out
}

// Unmatched: the name leads to none of our hosts or sites.
func (r Row) Unmatched() bool { return len(r.Hosts) == 0 && len(r.Sites) == 0 }

// HighFlag: a flag at High.
func (r Row) HighFlag() bool {
	return slices.ContainsFunc(r.Flags, func(f Flag) bool { return f.Level == High })
}

// Orgs are the orgs of the row's hosts and sites.
func (r Row) Orgs() []int64 {
	var out []int64
	for _, h := range r.Hosts {
		if !slices.Contains(out, h.OrgID) {
			out = append(out, h.OrgID)
		}
	}
	for _, s := range r.Sites {
		if !slices.Contains(out, s.OrgID) {
			out = append(out, s.OrgID)
		}
	}
	return out
}

// Zone is a synced zone: its settings and how much of it is proxied. The
// proxied coverage is where a later "ban rule deployed in this zone?"
// column goes: a rule at Cloudflare only protects proxied names.
type Zone struct {
	ID        string                `json:"-"`
	Name      string                `json:"name"`
	Plan      string                `json:"plan"`
	Status    string                `json:"status"`
	Settings  store.SurfaceSettings `json:"-"`
	Proxied   int                   `json:"proxied"`   // names behind Cloudflare
	Unproxied int                   `json:"unproxied"` // names that go around it
	Flags     []Flag                `json:"flags,omitempty"`
}

// Coverage is the share of the zone's names that are proxied, 0-100.
func (z Zone) Coverage() int {
	if n := z.Proxied + z.Unproxied; n > 0 {
		return z.Proxied * 100 / n
	}
	return 0
}

// Map is the surface, ranked.
type Map struct {
	Rows  []Row  `json:"rows"`
	Zones []Zone `json:"zones"`
}

// Build joins everything and ranks the rows (see Rank).
func Build(in Input) Map {
	cf := cloudflare.Build(in.Zones, in.Records, in.Addrs, in.Sites, in.Known)
	hostByKey := map[hkey]store.SurfaceHost{}
	for _, h := range in.Hosts {
		hostByKey[hostKey(h.OrgID, h.Name)] = h
	}
	stack := map[int64]map[string]store.SurfaceSite{}
	for _, s := range in.Stacks {
		if stack[s.HostID] == nil {
			stack[s.HostID] = map[string]store.SurfaceSite{}
		}
		stack[s.HostID][s.Root] = s
	}
	zoneByName, zoneByID := map[string]store.CloudflareZone{}, map[string]store.CloudflareZone{}
	for _, z := range in.Zones {
		zoneByName[z.Name], zoneByID[z.ID] = z, z
	}

	rows := map[string]*Row{}
	row := func(name string) *Row {
		r := rows[name]
		if r == nil {
			r = &Row{Name: name}
			rows[name] = r
		}
		return r
	}
	addHost := func(r *Row, orgID int64, org, name string) {
		if slices.ContainsFunc(r.Hosts, func(x Host) bool { return x.OrgID == orgID && x.Name == name }) {
			return
		}
		out := Host{OrgID: orgID, Org: org, Name: name}
		if h, ok := hostByKey[hostKey(orgID, name)]; ok { // it has reported: its OS and findings
			out.OS, out.Counts = h.OS, sevOf(in.Counts[h.ID][""])
		}
		r.Hosts = append(r.Hosts, out)
	}
	addSite := func(r *Row, s store.SiteNames) {
		if slices.ContainsFunc(r.Sites, func(x Site) bool { return x.OrgID == s.OrgID && x.Host == s.Host && x.Root == s.Root }) {
			return
		}
		out := Site{OrgID: s.OrgID, Org: s.Org, Host: s.Host, Root: s.Root}
		if h, ok := hostByKey[hostKey(s.OrgID, s.Host)]; ok {
			out.Software = software(stack[h.ID][s.Root])
			out.Counts = sevOf(in.Counts[h.ID][s.Root])
		}
		r.Sites = append(r.Sites, out)
		addHost(r, s.OrgID, s.Org, s.Host)
	}
	addRecord := func(r *Row, m cloudflare.Mapped) {
		r.Records = append(r.Records, m.CloudflareRecord)
		r.Exposed = r.Exposed || m.Exposed
		for _, h := range m.Hosts {
			addHost(r, h.OrgID, h.Org, h.Host)
		}
		for _, s := range m.Sites {
			addSite(r, s)
		}
		if m.Dangling {
			f := Flag{Kind: "dangling", Level: Medium, Note: m.Content + " is none of your hosts, not Cloudflare's and not labelled: a leftover, or someone else's now"}
			if a, err := netip.ParseAddr(m.Content); err == nil {
				switch p := in.Probes[a.Unmap()]; p.State {
				case store.ProbeAnswers:
					f.Note = m.Content + " is none of your hosts, not Cloudflare's and not labelled, and answers on port " + strconv.Itoa(p.Port) + ": a server you don't monitor, or someone else's serving this name"
				case store.ProbeRefused:
					f.Note = m.Content + " is none of your hosts, not Cloudflare's and not labelled; a machine is there but refuses 80 and 443: check whose before deleting"
				case store.ProbeSilent:
					f.Level, f.Note = Info, m.Content+" is none of your hosts and nothing answers on 80 or 443 from the hub: likely a leftover, safe to delete"
				}
			}
			addFlag(r, f)
		}
	}

	byRecord := map[string]cloudflare.Mapped{} // for names only a wildcard covers
	for _, m := range cf.Records {
		byRecord[recKey(m.CloudflareRecord)] = m
		r := row(m.Name)
		r.Zone, r.ZoneID = m.Zone, m.ZoneID
		addRecord(r, m)
	}
	for _, sd := range cf.Sites {
		r := row(sd.Name)
		addSite(r, sd.Site)
		switch sd.Status {
		case cloudflare.SiteNoZone:
			r.Status = OffCF
		case cloudflare.SiteNoRecord:
			r.Zone, r.Status = sd.Zone, NoRecord
		default:
			r.Zone = sd.Zone
			if len(r.Records) == 0 { // covered by a wildcard
				r.Wildcard = true
				for _, rec := range sd.Records {
					if m, ok := byRecord[recKey(rec)]; ok {
						r.ZoneID = m.ZoneID
						addRecord(r, m)
					}
				}
			}
		}
	}

	out := Map{}
	for _, r := range rows {
		if z, ok := zoneByName[r.Zone]; ok {
			r.ZoneID, r.Plan = z.ID, z.Plan
		} else if z, ok := zoneByID[r.ZoneID]; ok {
			r.Zone, r.Plan = z.Name, z.Plan
		}
		if len(r.Records) > 0 {
			r.Status = Unproxied
			if slices.ContainsFunc(r.Records, func(x store.CloudflareRecord) bool { return x.Proxied }) {
				r.Status = Proxied
			}
		}
		if strings.HasPrefix(r.Name, "*.") {
			r.Wildcard = true
			addFlag(r, Flag{Kind: "wildcard", Level: Medium, Note: "every name under " + r.Name[2:] + " without its own record resolves here"})
		}
		for _, rec := range r.Records {
			r.Targets = append(r.Targets, rec.Type+" "+rec.Content)
			if rec.Type != "CNAME" {
				continue
			}
			t := strings.TrimSuffix(strings.ToLower(rec.Content), ".")
			svc := cloudflare.ThirdParty(t)
			inZone := cloudflare.InZone(in.Zones, t) != ""
			if svc != "" {
				addFlag(r, Flag{Kind: "third-party", Level: Info, Note: "CNAME to " + svc + " (" + t + ")"})
			}
			switch c, ok := in.CNAMEs[t]; {
			case inZone && !hasName(in.Records, t):
				addFlag(r, Flag{Kind: "dangling-cname", Level: Medium, Note: "CNAME to " + t + ", which has no record in its zone"})
			case !inZone && ok && c.Status == store.CNAMEUnregistered:
				addFlag(r, Flag{Kind: "takeover", Level: High, Note: "CNAME target " + t + " doesn't exist and " + c.Note + ": anyone who registers it can serve " + r.Name})
			case !inZone && ok && c.Status == store.CNAMENXDomain && svc != "":
				addFlag(r, Flag{Kind: "takeover", Level: High, Note: "CNAME target " + t + " doesn't exist: anyone who creates it on " + svc + " can serve " + r.Name})
			case !inZone && ok && c.Status == store.CNAMENXDomain:
				// Its domain is someone's: only they can bring it back.
				addFlag(r, Flag{Kind: "dead-cname", Level: Info, Note: "CNAME target " + t + " doesn't exist; its domain is someone's, so it's no takeover. Remove the record if the service is gone (some publish theirs later: Microsoft 365's DKIM selector2 appears only when keys rotate)"})
			}
		}
		for _, h := range r.Hosts {
			r.Worst.add(h.Counts)
		}
		for _, s := range r.Sites {
			r.Worst.add(s.Counts)
		}
		out.Rows = append(out.Rows, *r)
	}

	for _, z := range in.Zones {
		zone := Zone{ID: z.ID, Name: z.Name, Plan: z.Plan, Status: z.Status, Settings: in.Settings[z.ID]}
		zone.Flags = zoneFlags(zone.Settings, in.Now)
		out.Zones = append(out.Zones, zone)
	}
	for i := range out.Rows {
		for _, z := range out.Zones {
			if z.ID == out.Rows[i].ZoneID {
				out.Rows[i].ZoneFlags = z.Flags
			}
		}
	}
	out.count()
	Rank(out.Rows)
	return out
}

// count fills each zone's proxied coverage from the rows.
func (m *Map) count() {
	for i := range m.Zones {
		z := &m.Zones[i]
		z.Proxied, z.Unproxied = 0, 0
		for _, r := range m.Rows {
			if r.ZoneID != z.ID {
				continue
			}
			switch r.Status {
			case Proxied:
				z.Proxied++
			case Unproxied:
				z.Unproxied++
			}
		}
	}
}

func addFlag(r *Row, f Flag) {
	if !slices.Contains(r.Flags, f) {
		r.Flags = append(r.Flags, f)
	}
}

func hasName(recs []store.CloudflareRecord, name string) bool {
	return slices.ContainsFunc(recs, func(r store.CloudflareRecord) bool { return r.Name == name })
}

type hkey struct {
	org  int64
	name string
}

func hostKey(org int64, name string) hkey { return hkey{org, name} }

func recKey(r store.CloudflareRecord) string {
	return r.ZoneID + "\x00" + r.Name + "\x00" + r.Type + "\x00" + r.Content
}

// software is a site's stack in a few words.
func software(s store.SurfaceSite) string {
	var parts []string
	if s.Framework != "" {
		fw := strings.ToUpper(s.Framework[:1]) + s.Framework[1:]
		parts = append(parts, strings.TrimSpace(fw+" "+s.FrameworkVersion))
	}
	if s.PHP != "" {
		parts = append(parts, "PHP "+s.PHP)
	}
	if s.WebServer != "" {
		parts = append(parts, s.WebServer)
	}
	return strings.Join(parts, " · ")
}

// certSoon is when an edge certificate's expiry is worth a flag.
const certSoon = 14 * 24 * time.Hour

// zoneFlags flags weak zone settings: SSL off or Flexible (Cloudflare to
// origin in plain HTTP), Always Use HTTPS off, TLS below 1.2 and an edge
// certificate about to expire.
func zoneFlags(s store.SurfaceSettings, now time.Time) []Flag {
	var out []Flag
	switch s.SSL {
	case "off":
		out = append(out, Flag{Kind: "ssl-off", Level: High, Note: "SSL/TLS is off: visitors can't use HTTPS through Cloudflare"})
	case "flexible":
		out = append(out, Flag{Kind: "ssl-flexible", Level: High, Note: "SSL/TLS is Flexible: Cloudflare talks to your servers in plain HTTP"})
	}
	if s.AlwaysHTTPS == "off" {
		out = append(out, Flag{Kind: "http-allowed", Level: Medium, Note: "Always Use HTTPS is off: plain HTTP is served"})
	}
	if s.MinTLS == "1.0" || s.MinTLS == "1.1" {
		out = append(out, Flag{Kind: "old-tls", Level: Medium, Note: "minimum TLS version is " + s.MinTLS + " (1.2 is the usual floor)"})
	}
	if !s.CertExpires.IsZero() && !now.IsZero() && s.CertExpires.Sub(now) < certSoon {
		lvl := Medium
		if !s.CertExpires.After(now) {
			lvl = High
		}
		out = append(out, Flag{Kind: "cert-expiry", Level: lvl, Note: "the edge certificate expires " + s.CertExpires.Format("Jan 2, 2006")})
	}
	return out
}

// Rank orders rows worst first: names that serve critical or high
// findings (known-exploited, then most critical, then most high), then
// names with a high flag or an exposed origin, then the rest by medium
// and low findings and flags. Ties go by name.
func Rank(rows []Row) {
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	slices.SortStableFunc(rows, func(x, y Row) int {
		for _, d := range [][2]int{
			{b(y.Vulnerable()), b(x.Vulnerable())},
			{y.Worst.KEV, x.Worst.KEV},
			{y.Worst.Critical, x.Worst.Critical},
			{y.Worst.High, x.Worst.High},
			{b(y.HighFlag()), b(x.HighFlag())},
			{b(y.Exposed), b(x.Exposed)},
			{len(y.Flags), len(x.Flags)},
			{y.Worst.Medium, x.Worst.Medium},
			{y.Worst.Low, x.Worst.Low},
		} {
			if c := cmp.Compare(d[0], d[1]); c != 0 {
				return c
			}
		}
		return strings.Compare(x.Name, y.Name)
	})
}

// For cuts the map down to what a viewer may see: rows that lead to a
// host or site in an org can passes, with other orgs' hosts and sites
// (and their findings) left out; zones with such a row. Rows that lead
// nowhere only an admin sees. Zone coverage is recounted from the rows
// kept.
func (m Map) For(admin bool, can func(int64) bool) Map {
	if admin {
		return m
	}
	var out Map
	zones := map[string]bool{}
	for _, r := range m.Rows {
		if !slices.ContainsFunc(r.Orgs(), can) {
			continue
		}
		r.Hosts = slices.DeleteFunc(slices.Clone(r.Hosts), func(h Host) bool { return !can(h.OrgID) })
		r.Sites = slices.DeleteFunc(slices.Clone(r.Sites), func(s Site) bool { return !can(s.OrgID) })
		r.Worst = Sev{}
		for _, h := range r.Hosts {
			r.Worst.add(h.Counts)
		}
		for _, s := range r.Sites {
			r.Worst.add(s.Counts)
		}
		out.Rows = append(out.Rows, r)
		zones[r.ZoneID] = true
	}
	for _, z := range m.Zones {
		if zones[z.ID] {
			out.Zones = append(out.Zones, z)
		}
	}
	out.count()
	Rank(out.Rows)
	return out
}

// Filter views.
const (
	ViewAll        = ""
	ViewExposed    = "exposed"
	ViewVulnerable = "vulnerable"
	ViewUnmatched  = "unmatched"
	ViewOffCF      = "off-cloudflare"
	ViewFlagged    = "flagged"
)

// Views lists the filter views in display order.
var Views = []string{ViewAll, ViewVulnerable, ViewExposed, ViewFlagged, ViewUnmatched, ViewOffCF}

// Match says whether a row is in a view and zone ("" = any).
func (r Row) Match(view, zone string) bool {
	if zone != "" && r.Zone != zone {
		return false
	}
	switch view {
	case ViewExposed:
		return r.Exposed
	case ViewVulnerable:
		return r.Vulnerable()
	case ViewUnmatched:
		return r.Unmatched()
	case ViewOffCF:
		return r.Status == OffCF
	case ViewFlagged:
		return len(r.Flags) > 0
	}
	return true
}
