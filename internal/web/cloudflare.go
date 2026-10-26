// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/cloudflare"
	"github.com/realmwatch/heimdall/internal/store"
)

// Cloudflare (internal/cloudflare): the /cloudflare overview and a card on
// the site page. Zones are hub-wide, so what a viewer sees is cut down to
// what points at hosts and sites they can see: a record is shown when it
// leads to a host or site in one of their orgs, a zone's security counts
// only when everything in the zone Heimdall knows is theirs, and records
// that lead nowhere (dangling) only to global admins.

// cfData is everything stored, joined once per request.
type cfData struct {
	zones  []store.CloudflareZone
	m      cloudflare.Map
	syncs  map[string]store.CloudflareSync
	orgsOf map[string]map[int64]bool // zone ID → orgs of the hosts and sites its records lead to
}

func (s *server) cloudflareData(ctx context.Context) (*cfData, error) {
	zones, err := s.st.CloudflareZones(ctx)
	if err != nil || len(zones) == 0 {
		return nil, err
	}
	recs, err := s.st.CloudflareRecords(ctx)
	if err != nil {
		return nil, err
	}
	hosts, err := s.st.ReportAddrs(ctx)
	if err != nil {
		return nil, err
	}
	sites, err := s.st.AllSiteNames(ctx)
	if err != nil {
		return nil, err
	}
	known, err := s.st.KnownIPPrefixes(ctx)
	if err != nil {
		return nil, err
	}
	syncs, err := s.st.CloudflareSyncs(ctx)
	if err != nil {
		return nil, err
	}
	d := &cfData{zones: zones, syncs: syncs, orgsOf: map[string]map[int64]bool{},
		m: cloudflare.Build(zones, recs, hosts, sites, cloudflare.Known(known, cloudflare.NewEdge()))}
	for _, r := range d.m.Records {
		for _, org := range recordOrgs(r) {
			if d.orgsOf[r.ZoneID] == nil {
				d.orgsOf[r.ZoneID] = map[int64]bool{}
			}
			d.orgsOf[r.ZoneID][org] = true
		}
	}
	return d, nil
}

func recordOrgs(r cloudflare.Mapped) []int64 {
	var out []int64
	for _, h := range r.Hosts {
		out = append(out, h.OrgID)
	}
	for _, s := range r.Sites {
		out = append(out, s.OrgID)
	}
	return out
}

// zoneVisible: a global admin, or every org the zone's records lead to
// (at least one) passes can.
func (d *cfData) zoneVisible(zoneID string, admin bool, can func(int64) bool) bool {
	if admin {
		return true
	}
	orgs := d.orgsOf[zoneID]
	if len(orgs) == 0 {
		return false
	}
	for o := range orgs {
		if !can(o) {
			return false
		}
	}
	return true
}

// cfSummary is a zone's security events, ready to show.
type cfSummary struct {
	cloudflare.Summary
	State, Note string
	Month       int // events in the stored days (up to 30)
	MonthDays   int
	Show        bool // the viewer may see the zone's counts
}

func (s *server) cfSummary(ctx context.Context, z store.CloudflareZone, show bool) cfSummary {
	out := cfSummary{State: z.Security, Note: z.SecurityNote, Show: show}
	if !show {
		return out
	}
	out.Summary = cloudflare.ParseSummary(z.Last24)
	since := s.now().UTC().AddDate(0, 0, -store.CloudflareKeepDays).Format(time.DateOnly)
	if days, err := s.st.CloudflareDailyCounts(ctx, z.ID, since); err == nil {
		seen := map[string]bool{}
		for _, d := range days {
			if d.Dim == "total" {
				out.Month += int(d.Count)
				if !seen[d.Day] {
					seen[d.Day], out.MonthDays = true, out.MonthDays+1
				}
			}
		}
	}
	return out
}

type cfZoneRow struct {
	store.CloudflareZone
	Records  int // records the viewer may see
	Security cfSummary
}

type cloudflareBody struct {
	Admin     bool
	Zones     []cfZoneRow
	Exposed   []cloudflare.Mapped
	Sites     []cloudflare.SiteDNS // names not behind Cloudflare
	SitesOK   int                  // names that are
	Dangling  []cloudflare.Mapped  // admins only
	Records   int
	LastSync  time.Time
	SyncError string
	EdgeSync  time.Time
	TokenURL  string       // admins: the pre-filled read-only token form
	TokenHand string       // what the form can't pre-fill
	Lists     *cfListsView // admins: which IP lists become labels (cflists.go)
}

// cloudflarePage is the overview: zones and their security events, origin
// addresses exposed by grey-cloud records, sites not behind Cloudflare and
// (admins) dangling records. Operators and admins only.
func (s *server) cloudflarePage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	can := v.Scope.CanOperate
	if !v.Scope.Admin && !slices.ContainsFunc(mapsKeys(v.Scope.Orgs), can) {
		s.notFound(w, r, v)
		return
	}
	ctx := r.Context()
	d, err := s.cloudflareData(ctx)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := cloudflareBody{Admin: v.Scope.Admin}
	if body.Admin {
		body.TokenURL, body.TokenHand = cloudflare.TokenURL("Heimdall (read-only)", cloudflare.ReadPerms), cloudflare.ReadManual
		if body.Lists, err = s.cfLists(ctx); err != nil {
			s.fail(w, r, v, err)
			return
		}
	}
	if d == nil {
		s.render(w, r, http.StatusOK, "cloudflare", v, "Cloudflare", "cloudflare", body)
		return
	}
	body.LastSync, body.SyncError, body.EdgeSync = d.syncs["zones"].At, d.syncs["zones"].Error, d.syncs["edge"].At
	if !v.Scope.Admin {
		body.SyncError = "" // may name zones of other orgs
	}
	perZone := map[string]int{}
	for _, rec := range d.m.Records {
		orgs := recordOrgs(rec)
		if len(orgs) > 0 && (v.Scope.Admin || slices.ContainsFunc(orgs, can)) {
			perZone[rec.ZoneID]++
			body.Records++
			if rec.Exposed {
				body.Exposed = append(body.Exposed, visibleTo(rec, v.Scope.Admin, can))
			}
		}
		if rec.Dangling && v.Scope.Admin {
			body.Dangling = append(body.Dangling, rec)
		}
	}
	for _, z := range d.zones {
		if !v.Scope.Admin && perZone[z.ID] == 0 {
			continue
		}
		body.Zones = append(body.Zones, cfZoneRow{CloudflareZone: z, Records: perZone[z.ID],
			Security: s.cfSummary(ctx, z, d.zoneVisible(z.ID, v.Scope.Admin, can))})
	}
	for _, sd := range d.m.Sites {
		if !v.Scope.Admin && !can(sd.Site.OrgID) {
			continue
		}
		if sd.Status == cloudflare.SiteProxied {
			body.SitesOK++
		} else {
			body.Sites = append(body.Sites, sd)
		}
	}
	s.render(w, r, http.StatusOK, "cloudflare", v, "Cloudflare", "cloudflare", body)
}

// visibleTo drops the hosts and sites of orgs the viewer can't see.
func visibleTo(m cloudflare.Mapped, admin bool, can func(int64) bool) cloudflare.Mapped {
	if admin {
		return m
	}
	var hs []store.ReportAddr
	for _, h := range m.Hosts {
		if can(h.OrgID) {
			hs = append(hs, h)
		}
	}
	var ss []store.SiteNames
	for _, x := range m.Sites {
		if can(x.OrgID) {
			ss = append(ss, x)
		}
	}
	m.Hosts, m.Sites = hs, ss
	return m
}

func mapsKeys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// cloudflareHTML is the rendered card the site page includes.
type cloudflareHTML = template.HTML

// cfCardBody is the site page's Cloudflare card.
type cfCardBody struct {
	Names    []cloudflare.SiteDNS
	Zone     string
	Security *cfSummary
	Overview bool // link to /cloudflare
}

var cfCard struct {
	once sync.Once
	t    *template.Template
	err  error
}

func cloudflareCardTemplate() (*template.Template, error) {
	parse := func() (*template.Template, error) {
		return template.New("cloudflare_card.html").Funcs(funcs).ParseFS(templatesFS, "templates/cloudflare_card.html")
	}
	if devMode {
		return parse()
	}
	cfCard.once.Do(func() { cfCard.t, cfCard.err = parse() })
	return cfCard.t, cfCard.err
}

// cloudflareCard renders the site page's card: how each of the site's
// names is served by Cloudflare, and its zone's security events. Empty
// when nothing is synced (or on any error: the page never fails for it).
func (s *server) cloudflareCard(ctx context.Context, v *auth.Viewer, orgID int64, host, root string) cloudflareHTML {
	d, err := s.cloudflareData(ctx)
	if err != nil {
		s.log.Warn("Cloudflare card failed", "err", err)
		return ""
	}
	if d == nil {
		return ""
	}
	var body cfCardBody
	for _, sd := range d.m.Sites {
		if sd.Site.OrgID == orgID && sd.Site.Host == host && sd.Site.Root == root {
			body.Names = append(body.Names, sd)
		}
	}
	if len(body.Names) == 0 {
		return ""
	}
	body.Overview = v.Scope.Admin || v.Scope.CanOperate(orgID)
	for _, sd := range body.Names {
		if sd.Zone == "" {
			continue
		}
		for _, z := range d.zones {
			if z.Name == sd.Zone && body.Security == nil {
				sum := s.cfSummary(ctx, z, d.zoneVisible(z.ID, v.Scope.Admin, v.Scope.CanView))
				body.Zone, body.Security = z.Name, &sum
			}
		}
	}
	t, err := cloudflareCardTemplate()
	if err != nil {
		s.log.Error("Cloudflare card template", "err", err)
		return ""
	}
	var b strings.Builder
	if err := t.Execute(&b, body); err != nil {
		s.log.Error("Cloudflare card render", "err", err)
		return ""
	}
	return template.HTML(b.String()) // html/template output, already escaped
}
