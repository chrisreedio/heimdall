// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/store"
)

// Mapped is a DNS record joined to what Heimdall knows.
type Mapped struct {
	store.CloudflareRecord
	Zone  string             // the zone's name
	Hosts []store.ReportAddr // hosts whose report address the record resolves to
	Sites []store.SiteNames  // sites serving the record's name
	// Exposed: not proxied, and resolves straight to a host, so the
	// origin's address is public.
	Exposed bool
	// Dangling: an A/AAAA record whose address is no host's, not
	// Cloudflare's, not private and not labelled: a leftover, or a
	// takeover risk if the address now belongs to someone else.
	Dangling bool
}

// SiteDNS is how one of a site's names is served.
type SiteDNS struct {
	Site   store.SiteNames
	Name   string
	Zone   string // the visible zone it's in, if any
	Status string // SiteProxied, SiteUnproxied, SiteNoRecord, SiteNoZone
	// Records are the records for the name (or the wildcard that covers it).
	Records []store.CloudflareRecord
}

// SiteDNS statuses.
const (
	SiteProxied   = "proxied"
	SiteUnproxied = "unproxied" // in a zone, but grey-cloud: not behind Cloudflare
	SiteNoRecord  = "no-record" // the zone is visible but has no record for the name
	SiteNoZone    = "no-zone"   // no visible zone covers the name
)

// Map is the join of Cloudflare's DNS and Heimdall's hosts and sites.
type Map struct {
	Records []Mapped
	Sites   []SiteDNS
}

// Build joins records to hosts (by report address, following CNAMEs
// within the zones) and to sites (by server name). known says whether an
// address has a label that says something (Cloudflare's edge is one).
func Build(zones []store.CloudflareZone, recs []store.CloudflareRecord, hosts []store.ReportAddr, sites []store.SiteNames, known func(netip.Addr) bool) Map {
	zoneName := map[string]string{}
	for _, z := range zones {
		zoneName[z.ID] = z.Name
	}
	byName := map[string][]store.CloudflareRecord{}
	for _, r := range recs {
		byName[r.Name] = append(byName[r.Name], r)
	}
	hostsAt := map[netip.Addr][]store.ReportAddr{}
	for _, h := range hosts {
		hostsAt[h.Addr] = append(hostsAt[h.Addr], h)
	}
	sitesNamed := map[string][]store.SiteNames{}
	for _, s := range sites {
		for _, n := range s.Names {
			if n = siteName(n); n != "" && !slices.ContainsFunc(sitesNamed[n], func(x store.SiteNames) bool { return sameSite(x, s) }) {
				sitesNamed[n] = append(sitesNamed[n], s)
			}
		}
	}

	var m Map
	for _, r := range recs {
		mr := Mapped{CloudflareRecord: r, Zone: zoneName[r.ZoneID], Sites: sitesNamed[r.Name]}
		for _, a := range resolve(byName, r, false, 0) {
			for _, h := range hostsAt[a] {
				if !slices.Contains(mr.Hosts, h) {
					mr.Hosts = append(mr.Hosts, h)
				}
			}
		}
		for _, a := range resolve(byName, r, true, 0) {
			if len(hostsAt[a]) > 0 {
				mr.Exposed = true
			}
		}
		if r.Type != "CNAME" {
			if a, err := netip.ParseAddr(r.Content); err == nil {
				a = a.Unmap()
				mr.Dangling = len(hostsAt[a]) == 0 && public(a) && (known == nil || !known(a))
			}
		}
		m.Records = append(m.Records, mr)
	}

	for _, s := range sites {
		seen := map[string]bool{}
		for _, raw := range s.Names {
			n := siteName(raw)
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			d := SiteDNS{Site: s, Name: n, Zone: zoneFor(zones, n)}
			switch {
			case d.Zone == "":
				d.Status = SiteNoZone
			default:
				d.Records = byName[n]
				if len(d.Records) == 0 {
					if i := strings.IndexByte(n, '.'); i > 0 && strings.HasSuffix(n[i+1:], d.Zone) {
						d.Records = byName["*."+n[i+1:]]
					}
				}
				d.Status = SiteNoRecord
				if len(d.Records) > 0 {
					d.Status = SiteUnproxied
					if slices.ContainsFunc(d.Records, func(r store.CloudflareRecord) bool { return r.Proxied }) {
						d.Status = SiteProxied
					}
				}
			}
			m.Sites = append(m.Sites, d)
		}
	}
	return m
}

func sameSite(a, b store.SiteNames) bool {
	return a.OrgID == b.OrgID && a.Host == b.Host && a.Root == b.Root
}

// resolve returns the addresses a record leads to, following CNAMEs to
// other synced records (a few hops). With exposed, a proxied record leads
// nowhere: the public sees Cloudflare's addresses there.
func resolve(byName map[string][]store.CloudflareRecord, r store.CloudflareRecord, exposed bool, depth int) []netip.Addr {
	if exposed && r.Proxied || depth > 3 {
		return nil
	}
	if r.Type != "CNAME" {
		if a, err := netip.ParseAddr(r.Content); err == nil {
			return []netip.Addr{a.Unmap()}
		}
		return nil
	}
	var out []netip.Addr
	for _, t := range byName[strings.TrimSuffix(strings.ToLower(r.Content), ".")] {
		out = append(out, resolve(byName, t, exposed, depth+1)...)
	}
	return out
}

// public: an address on the internet (not private, loopback, link-local
// or the tailnet).
func public(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !ipinfo.Tailnet.Contains(a) && !ipinfo.Tailnet6.Contains(a)
}

// siteName normalizes a server name, or returns "" for one that isn't a
// DNS name (nginx's "_", regexes, wildcards, addresses, localhost).
func siteName(n string) string {
	n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
	if n == "" || !strings.Contains(n, ".") || strings.ContainsAny(n, "*~^$ /\\:") || n == "localhost" || strings.HasSuffix(n, ".localhost") {
		return ""
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return ""
	}
	return n
}

// zoneFor returns the most specific zone that contains name.
func zoneFor(zones []store.CloudflareZone, name string) string {
	best := ""
	for _, z := range zones {
		if (name == z.Name || strings.HasSuffix(name, "."+z.Name)) && len(z.Name) > len(best) {
			best = z.Name
		}
	}
	return best
}

// Known builds the "does someone know this address" check for Build from
// the stored labels' ranges and the edge.
func Known(prefixes []netip.Prefix, edge *Edge) func(netip.Addr) bool {
	return func(a netip.Addr) bool {
		if edge.Contains(a) {
			return true
		}
		for _, p := range prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
}
