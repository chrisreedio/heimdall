// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"cmp"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/feeds/eol"
	"github.com/chrisreedio/heimdall/internal/report"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/triggers"
	"github.com/chrisreedio/heimdall/internal/updates"
)

// ── Fleet: one row per visible host, for the dashboard and host list ─────

// fleetHost is a host with everything the list pages act on. Counts come
// from SQL (report.Filter.CountsOnly): a busy host has tens of thousands
// of findings, and these pages never list them.
type fleetHost struct {
	store.Host
	Reported        bool
	R               report.Host // counts, lifecycles and sites; zero until the first report
	Stale           bool
	Reboot          bool
	Pending         int // pending package updates
	PendingSecurity int
	Collector       string
	CollectorBehind bool
	ChangeWatch     string // "on", "off", or "" when the collector doesn't say
	News            int    // threat-news incidents confirmed on the host
	Anomalies       int    // open (unacknowledged)
	AnomalyWorst    string // high, medium or low
	EOL, EOLSoon    bool   // software past, or within 90 days of, end of life
	Life            []lifeItem
	SitesAttention  int
}

// lifeItem is one lifecycle on a host: its OS, a runtime, or a site's PHP
// or Laravel.
type lifeItem struct {
	Label string // "Ubuntu 22.04", "PHP 8.1"
	State string // eol, soon, ok (lifeState; unknown ones are left out)
	Life  *report.Lifecycle
	OS    bool
	Site  bool
}

// Attention reports whether there's anything to do on the host.
func (h fleetHost) Attention() bool {
	c := h.R.Counts
	return h.Reported && (c.KEV > 0 || h.News > 0 || c.Fixable > 0 || c.Watch > 0 || h.EOL || h.EOLSoon || h.Stale ||
		h.Anomalies > 0 || h.Reboot || c.RebootPending > 0 || h.PendingSecurity > 0 || h.SitesAttention > 0 || h.CollectorBehind ||
		h.ChangeWatch == "off")
}

// tagCap is how many tags a host list row shows before "+N".
const tagCap = 3

// ShownTags and MoreTags split the tags a row shows from those it folds.
func (h fleetHost) ShownTags() []string { return h.Tags[:min(len(h.Tags), tagCap)] }
func (h fleetHost) MoreTags() int       { return max(len(h.Tags)-tagCap, 0) }

// EOLLabels names the end-of-life (or soon) software, for a tooltip.
func (h fleetHost) EOLLabels(state string) string {
	var out []string
	for _, l := range h.Life {
		if l.State == state && !slices.Contains(out, l.Label) {
			out = append(out, l.Label)
		}
	}
	return strings.Join(out, ", ")
}

// NonOSEOL lists the end-of-life (or soon) software other than the OS,
// deduplicated, for pills beside the OS.
func (h fleetHost) NonOSEOL() []lifeItem {
	var out []lifeItem
	for _, l := range h.Life {
		if l.OS || (l.State != "eol" && l.State != "soon") {
			continue
		}
		if !slices.ContainsFunc(out, func(o lifeItem) bool { return o.Label == l.Label }) {
			out = append(out, l)
		}
	}
	return out
}

var productNames = map[string]string{
	eol.ProductUbuntu: "Ubuntu", eol.ProductDebian: "Debian", eol.ProductRocky: "Rocky Linux",
	eol.ProductAlma: "AlmaLinux", eol.ProductAlpine: "Alpine", eol.ProductRHEL: "RHEL",
	eol.ProductPHP: "PHP", eol.ProductNodeJS: "Node.js", eol.ProductPython: "Python",
	eol.ProductLaravel: "Laravel", eol.ProductWindowsServer: "Windows Server",
}

func productLabel(product, cycle string) string {
	name, ok := productNames[product]
	if !ok {
		name = product
	}
	return strings.TrimSpace(name + " " + cycle)
}

// fleet builds a row for every host the viewer can see in org ("" = all).
func (s *server) fleet(r *http.Request, v *auth.Viewer, org string) ([]fleetHost, error) {
	ctx := r.Context()
	rep, err := report.Build(ctx, s.st, report.Filter{Org: org, Scope: v.Scope, CountsOnly: true}, s.now())
	if err != nil {
		return nil, err
	}
	hosts, err := s.visibleHosts(r, v, org)
	if err != nil {
		return nil, err
	}
	states, err := s.st.HostStates(ctx)
	if err != nil {
		return nil, err
	}
	anomalies, err := s.st.OpenAnomalies(ctx, v.Scope)
	if err != nil {
		return nil, err
	}
	reported := make(map[string]report.Host, len(rep.Hosts))
	for _, h := range rep.Hosts {
		reported[h.Org+"/"+h.Name] = h
	}
	now := s.now()
	release := releaseTag.MatchString(s.cfg.Version)
	out := make([]fleetHost, 0, len(hosts))
	byID := map[int64]int{}
	for _, h := range hosts {
		row := fleetHost{Host: h}
		rh, ok := reported[h.OrgSlug+"/"+h.Name]
		if ok {
			row.Reported, row.R = true, rh
			row.Stale = s.cfg.StaleAfter > 0 && now.Sub(rh.LastSeen) > s.cfg.StaleAfter
			st := states[h.ID]
			row.Reboot = st.RebootRequired != nil && *st.RebootRequired
			row.Pending, row.PendingSecurity, row.News = st.PendingUpdates, st.PendingSecurity, st.News
			row.Collector = strings.TrimSpace(st.CollectorVersion)
			if row.Collector != "" && release {
				row.CollectorBehind = updates.Newer(s.cfg.Version, "v"+strings.TrimPrefix(row.Collector, "v"))
			}
			if t, err := triggers.Parse(st.Triggers); err == nil {
				row.ChangeWatch = t.ChangeWatch()
			}
			row.addLife(rh)
		}
		byID[h.ID] = len(out)
		out = append(out, row)
	}
	rank := map[string]int{"high": 3, "medium": 2, "low": 1}
	for _, a := range anomalies {
		i, ok := byID[a.Host.ID]
		if !ok {
			continue
		}
		out[i].Anomalies++
		if rank[a.Severity] > rank[out[i].AnomalyWorst] {
			out[i].AnomalyWorst = a.Severity
		}
	}
	return out, nil
}

func (row *fleetHost) addLife(h report.Host) {
	add := func(l *report.Lifecycle, os, site bool) {
		st := lifeState(l)
		if st == "unknown" {
			return
		}
		row.Life = append(row.Life, lifeItem{Label: productLabel(l.Product, l.Cycle), State: st, Life: l, OS: os, Site: site})
		row.EOL = row.EOL || st == "eol"
		row.EOLSoon = row.EOLSoon || st == "soon"
	}
	add(h.OSLife, true, false)
	for _, rt := range h.Runtimes {
		add(rt.Life, false, false)
	}
	for _, site := range h.Sites {
		add(site.PHPLife, false, true)
		add(site.FrameworkLife, false, true)
		if needsAttention(site) {
			row.SitesAttention++
		}
	}
}

// comparePriority orders hosts for attention, like patch priorities:
// known-exploited first, then what's in the news, fixable critical and
// high, end of life, and so on down to what can wait.
func comparePriority(a, b fleetHost) int {
	b2i := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	ac, bc := a.R.Counts, b.R.Counts
	for _, d := range [][2]int{
		{b2i(a.Reported), b2i(b.Reported)},
		{ac.KEV, bc.KEV}, {a.News, b.News}, {ac.FixUrgent, bc.FixUrgent},
		{b2i(a.EOL), b2i(b.EOL)}, {b2i(a.Stale), b2i(b.Stale)},
		{b2i(a.AnomalyWorst == "high"), b2i(b.AnomalyWorst == "high")},
		{b2i(a.Reboot), b2i(b.Reboot)}, {a.PendingSecurity, b.PendingSecurity},
		{ac.Fixable, bc.Fixable}, {ac.Watch, bc.Watch}, {a.Anomalies, b.Anomalies}, {a.SitesAttention, b.SitesAttention},
		{b2i(a.EOLSoon), b2i(b.EOLSoon)}, {b2i(a.CollectorBehind), b2i(b.CollectorBehind)},
	} {
		if d[0] != d[1] {
			return d[1] - d[0]
		}
	}
	return strings.Compare(a.OrgSlug+"/"+a.Name, b.OrgSlug+"/"+b.Name)
}

// ── Dashboard ──────────────────────────────────────────────────────────────

type dashBody struct {
	Org        string
	Orgs       []store.Org
	ShowOrgs   bool
	News       int // incidents in the news affecting a visible host
	Tiles      []tile
	Attention  []fleetHost // the most urgent hosts
	MoreAttn   int         // hosts needing attention past the list
	Quiet      int         // reported hosts with nothing to act on
	Plans      []store.Plan
	EOL        []eolGroup
	MoreEOL    int
	NextEOL    *eolGroup // the next end of life, when nothing is close
	Anomalies  []store.AnomalyView
	AnomalyAll int
	Fleet      fleetSummary
	Hosts      int       // visible hosts, reported or not
	AIBrief    *aiBriefs // AI fleet brief (nil when [ai] is off); see ai.go
}

// tile is one dashboard number. Every tile links to where it's acted on;
// there are always eight (a 4 x 2 grid, 2 x 4 on phones).
type tile struct {
	N           int
	Label, Sub  string
	Href, Class string
}

// eolGroup is one product version past or near end of life, with where it runs.
type eolGroup struct {
	Label  string
	Life   *report.Lifecycle
	State  string
	Hosts  []fleetHost
	Sites  int
	OnSite bool // it's a site's PHP or Laravel
}

// Href is the host when there's one, else the filtered host list.
func (g eolGroup) Href() string {
	if len(g.Hosts) == 1 {
		return "/hosts/" + url.PathEscape(g.Hosts[0].OrgSlug) + "/" + url.PathEscape(g.Hosts[0].Name)
	}
	return "/hosts?only=eol&sort=priority"
}

type fleetSummary struct {
	Reported, Waiting int
	WaitingHosts      []fleetHost
	Newest, Oldest    *fleetHost // by last report
	Behind, WatchOff  int
	Version           string // this hub's release, when it is one
	Open, NoFix       int    // findings
	NotRunning        int    // ...on old kernels that aren't running
	KernelUserland    int    // ...on kernel userland packages
	Fixable           int
	Watch             int // ...with no fix yet, but worth watching
}

// attentionCap is how many hosts the dashboard's attention list shows.
const attentionCap = 8

func (s *server) dashboard(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	org, orgs, err := s.orgFilter(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	fleet, err := s.fleet(r, v, org)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := dashBody{Org: org, Orgs: orgs, ShowOrgs: len(orgs) > 1, Hosts: len(fleet)}
	if body.News, err = s.newsAffecting(r, v, org); err != nil {
		s.fail(w, r, v, err)
		return
	}
	var t struct {
		kev, kevHosts, urgent, fixable, secHosts, secPkgs, eol, soon, reboot, stale, sites, siteTotal int
	}
	anomHosts := 0
	f := &body.Fleet
	if releaseTag.MatchString(s.cfg.Version) {
		f.Version = s.cfg.Version
	}
	for i := range fleet {
		h := &fleet[i]
		if !h.Reported {
			f.Waiting++
			f.WaitingHosts = append(f.WaitingHosts, *h)
			continue
		}
		c := h.R.Counts
		f.Reported++
		f.Open += c.Total
		f.NoFix += c.NoFix
		f.NotRunning += c.NotRunning
		f.KernelUserland += c.KernelUserland
		f.Fixable += c.Fixable
		f.Watch += c.Watch
		t.kev += c.KEV
		t.urgent += c.FixUrgent
		t.fixable += c.Fixable
		t.siteTotal += len(h.R.Sites)
		t.sites += h.SitesAttention
		if c.KEV > 0 {
			t.kevHosts++
		}
		if h.PendingSecurity > 0 {
			t.secHosts++
			t.secPkgs += h.PendingSecurity
		}
		if h.EOL {
			t.eol++
		} else if h.EOLSoon {
			t.soon++
		}
		if h.Reboot {
			t.reboot++
		}
		if h.Stale {
			t.stale++
		}
		if h.Anomalies > 0 {
			anomHosts++
		}
		if h.CollectorBehind {
			f.Behind++
		}
		if h.ChangeWatch == "off" {
			f.WatchOff++
		}
		if f.Newest == nil || h.R.LastSeen.After(f.Newest.R.LastSeen) {
			f.Newest = h
		}
		if f.Oldest == nil || h.R.LastSeen.Before(f.Oldest.R.LastSeen) {
			f.Oldest = h
		}
	}

	anoms, err := s.st.OpenAnomalies(r.Context(), v.Scope)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	high := 0
	for _, a := range anoms {
		if org != "" && a.Host.OrgSlug != org {
			continue
		}
		body.AnomalyAll++
		if a.Severity == "high" {
			high++
		}
		body.Anomalies = append(body.Anomalies, a)
	}
	slices.SortStableFunc(body.Anomalies, func(a, b store.AnomalyView) int { return b.DetectedAt.Compare(a.DetectedAt) })
	body.Anomalies = body.Anomalies[:min(len(body.Anomalies), 5)]

	hostsWord := func(n int) string { return plural(n, "host", "hosts") }
	body.Tiles = []tile{
		{N: t.kev, Label: "known-exploited findings", Href: "/hosts?only=kev&sort=priority", Class: classIf(t.kev > 0, "bad"),
			Sub: ifElse(t.kev > 0, "on "+hostsWord(t.kevHosts), "none on your hosts")},
		{N: t.urgent, Label: "critical & high with a fix", Href: "/hosts?only=fixable&sort=priority", Class: classIf(t.urgent > 0, "bad"),
			Sub: "of " + commas(t.fixable) + " fixable now"},
		{N: t.secHosts, Label: plural0(t.secHosts, "host with security updates", "hosts with security updates"), Href: "/hosts?only=updates&sort=priority",
			Class: classIf(t.secHosts > 0, "warn"), Sub: ifElse(t.secPkgs > 0, plural(t.secPkgs, "package", "packages")+" to install", "nothing waiting")},
		{N: t.eol, Label: plural0(t.eol, "host on end-of-life software", "hosts on end-of-life software"), Href: "/hosts?only=eol&sort=priority",
			Class: classIf(t.eol > 0, "bad", t.soon > 0, "warn"), Sub: ifElse(t.soon > 0, "+"+plural(t.soon, "host", "hosts")+" within 90 days", "none ending within 90 days")},
		{N: t.reboot, Label: plural0(t.reboot, "reboot required", "reboots required"), Href: "/hosts?only=reboot&sort=priority",
			Class: classIf(t.reboot > 0, "warn"), Sub: "to finish installed updates"},
		{N: t.stale, Label: plural0(t.stale, "stale host", "stale hosts"), Href: "/hosts?only=stale&sort=seen",
			Class: classIf(t.stale > 0, "warn"), Sub: "no report in " + days(s.cfg.StaleAfter)},
		{N: body.AnomalyAll, Label: plural0(body.AnomalyAll, "open anomaly", "open anomalies"), Href: "/anomalies",
			Class: classIf(high > 0, "bad", body.AnomalyAll > 0, "warn"),
			Sub:   ifElse(body.AnomalyAll > 0, "on "+hostsWord(anomHosts)+ifElse(high > 0, fmt.Sprintf(" · %d high", high), ""), "no tripwires firing")},
		{N: t.sites, Label: plural0(t.sites, "site needing attention", "sites needing attention"), Href: "/sites",
			Class: classIf(t.sites > 0, "warn"), Sub: "of " + plural(t.siteTotal, "site", "sites")},
	}

	ranked := slices.Clone(fleet)
	slices.SortStableFunc(ranked, comparePriority)
	for _, h := range ranked {
		switch {
		case !h.Attention():
			if h.Reported {
				body.Quiet++
			}
		case len(body.Attention) < attentionCap:
			body.Attention = append(body.Attention, h)
		default:
			body.MoreAttn++
		}
	}

	body.EOL, body.NextEOL = eolGroups(fleet)
	if len(body.EOL) > 6 {
		body.MoreEOL = len(body.EOL) - 6
		body.EOL = body.EOL[:6]
	}

	plans, err := s.st.ListPlans(r.Context(), v.Scope)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	for _, p := range plans {
		if p.ClosedAt.IsZero() && (org == "" || p.OrgSlug == org || p.OrgSlug == "") {
			body.Plans = append(body.Plans, p)
		}
	}
	if len(body.Plans) > 4 {
		body.Plans = body.Plans[:4]
	}
	if body.AIBrief, err = s.aiBriefsFor(r, v, org, orgs); err != nil {
		s.fail(w, r, v, err)
		return
	}
	s.render(w, r, http.StatusOK, "dashboard", v, "Dashboard", "dashboard", body)
}

// eolGroups gathers software past or within 90 days of end of life across
// the fleet, already-ended first, then by date. With nothing close, next is
// the soonest end of life still ahead.
func eolGroups(fleet []fleetHost) (groups []eolGroup, next *eolGroup) {
	idx := map[string]int{}
	for _, h := range fleet {
		for _, l := range h.Life {
			if l.State == "ok" {
				if l.Life.EOLDate != nil && (next == nil || l.Life.EOLDate.Before(*next.Life.EOLDate)) {
					next = &eolGroup{Label: l.Label, Life: l.Life, State: l.State, Hosts: []fleetHost{h}}
				}
				continue
			}
			i, ok := idx[l.Label]
			if !ok {
				i = len(groups)
				idx[l.Label] = i
				groups = append(groups, eolGroup{Label: l.Label, Life: l.Life, State: l.State, OnSite: l.Site})
			}
			g := &groups[i]
			if !slices.ContainsFunc(g.Hosts, func(o fleetHost) bool { return o.ID == h.ID }) {
				g.Hosts = append(g.Hosts, h)
			}
			if l.Site {
				g.Sites++
			} else {
				g.OnSite = false
			}
		}
	}
	date := func(g eolGroup) time.Time {
		if g.Life.EOLDate == nil {
			return time.Time{}
		}
		return *g.Life.EOLDate
	}
	slices.SortStableFunc(groups, func(a, b eolGroup) int {
		if a.State != b.State {
			return strings.Compare(a.State, b.State) // "eol" < "soon"
		}
		return cmp.Or(date(a).Compare(date(b)), strings.Compare(a.Label, b.Label))
	})
	if len(groups) > 0 {
		next = nil
	}
	return groups, next
}

// ── Hosts ──────────────────────────────────────────────────────────────────

type hostsBody struct {
	Org      string
	Orgs     []store.Org
	ShowOrgs bool
	Hosts    []fleetHost
	Env      string // filters
	Tag      string
	Only     string
	Sort     string
	EnvChips []chip
	Onlys    []chip
	Sorts    []chip
	ClearTag string // the list without the tag filter
	Shown    int    // hosts in env/tag, before the "only" filter
	Total    int    // every visible host
}

type chip struct {
	Label, Value, Href string
	Count              int
	Current            bool
}

// hostsQuery is the host list's filter state; link builds its URLs.
type hostsQuery struct{ org, env, tag, only, sort string }

func (q hostsQuery) link() string {
	v := url.Values{}
	for k, val := range map[string]string{"org": q.org, "env": q.env, "tag": q.tag, "only": q.only, "sort": q.sort} {
		if val != "" {
			v.Set(k, val)
		}
	}
	if len(v) == 0 {
		return "/hosts"
	}
	return "/hosts?" + v.Encode()
}

// hostFilters are the host list's "only" filters, in display order.
var hostFilters = []struct {
	Value, Label string
	Match        func(fleetHost) bool
}{
	{"kev", "Known-exploited", func(h fleetHost) bool { return h.R.Counts.KEV > 0 }},
	{"news", "In the news", func(h fleetHost) bool { return h.News > 0 }},
	{"fixable", "Critical & high fixable", func(h fleetHost) bool { return h.R.Counts.FixUrgent > 0 }},
	{"watch", "To watch", func(h fleetHost) bool { return h.R.Counts.Watch > 0 }},
	{"updates", "Security updates", func(h fleetHost) bool { return h.PendingSecurity > 0 }},
	{"eol", "End of life", func(h fleetHost) bool { return h.EOL || h.EOLSoon }},
	{"reboot", "Needs reboot", func(h fleetHost) bool { return h.Reboot }},
	{"stale", "Stale", func(h fleetHost) bool { return h.Stale }},
	{"anomalies", "Anomalies", func(h fleetHost) bool { return h.Anomalies > 0 }},
	{"collector", "Collector", func(h fleetHost) bool { return h.CollectorBehind || h.ChangeWatch == "off" }},
	{"waiting", "Waiting", func(h fleetHost) bool { return !h.Reported }},
}

var hostSorts = []struct{ Value, Label string }{{"", "Name"}, {"priority", "Priority"}, {"seen", "Last seen"}}

func (s *server) hostsPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	org, orgs, err := s.orgFilter(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	fleet, err := s.fleet(r, v, org)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	qv := r.URL.Query()
	q := hostsQuery{org: org, env: qv.Get("env"), tag: qv.Get("tag")}
	for _, f := range hostFilters {
		if f.Value == qv.Get("only") {
			q.only = f.Value
		}
	}
	for _, o := range hostSorts {
		if o.Value == qv.Get("sort") {
			q.sort = o.Value
		}
	}
	body := hostsBody{Org: org, Orgs: orgs, ShowOrgs: len(orgs) > 1, Env: q.env, Tag: q.tag, Only: q.only,
		Sort: q.sort, Total: len(fleet)}

	// Environments: counted before the other filters, like before.
	envCount := map[string]int{}
	var envs []string
	for _, h := range fleet {
		if envCount[h.EnvSlug] == 0 {
			envs = append(envs, h.EnvSlug)
		}
		envCount[h.EnvSlug]++
	}
	slices.Sort(envs)
	if len(envs) > 1 {
		all := q
		all.env = ""
		body.EnvChips = append(body.EnvChips, chip{Label: "All", Href: all.link(), Count: len(fleet), Current: q.env == ""})
		for _, e := range envs {
			c := q
			c.env = e
			body.EnvChips = append(body.EnvChips, chip{Label: e, Value: e, Href: c.link(), Count: envCount[e], Current: e == q.env})
		}
	}
	if q.tag != "" {
		c := q
		c.tag = ""
		body.ClearTag = c.link()
	}

	var inScope []fleetHost
	for _, h := range fleet {
		if (q.env == "" || h.EnvSlug == q.env) && (q.tag == "" || slices.Contains(h.Tags, q.tag)) {
			inScope = append(inScope, h)
		}
	}
	body.Shown = len(inScope)
	{
		c := q
		c.only = ""
		body.Onlys = append(body.Onlys, chip{Label: "All", Href: c.link(), Count: len(inScope), Current: q.only == ""})
	}
	var match func(fleetHost) bool
	for _, f := range hostFilters {
		n := 0
		for _, h := range inScope {
			if f.Match(h) {
				n++
			}
		}
		if f.Value == q.only {
			match = f.Match
		}
		if n > 0 || f.Value == q.only {
			c := q
			c.only = f.Value
			body.Onlys = append(body.Onlys, chip{Label: f.Label, Value: f.Value, Href: c.link(), Count: n, Current: f.Value == q.only})
		}
	}
	for _, o := range hostSorts {
		c := q
		c.sort = o.Value
		body.Sorts = append(body.Sorts, chip{Label: o.Label, Value: o.Value, Href: c.link(), Current: o.Value == q.sort})
	}
	for _, h := range inScope {
		if match == nil || match(h) {
			body.Hosts = append(body.Hosts, h)
		}
	}
	switch q.sort {
	case "priority":
		slices.SortStableFunc(body.Hosts, comparePriority)
	case "seen": // longest silent first; never-reported last
		slices.SortStableFunc(body.Hosts, func(a, b fleetHost) int {
			if a.LastSeenAt.IsZero() != b.LastSeenAt.IsZero() {
				if a.LastSeenAt.IsZero() {
					return 1
				}
				return -1
			}
			return a.LastSeenAt.Compare(b.LastSeenAt)
		})
	}
	s.render(w, r, http.StatusOK, "hosts", v, "Hosts", "hosts", body)
}

// ── Small text helpers ────────────────────────────────────────────────────

// commas formats n with thousands separators: 14766 -> "14,766".
func commas(n int) string {
	s := fmt.Sprint(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	if neg {
		return "-" + s
	}
	return s
}

// plural is "1 host" or "3 hosts", with separators.
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return commas(n) + " " + many
}

// plural0 picks the word alone (the tile shows the number).
func plural0(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func ifElse(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

// classIf returns the first class whose condition holds: classIf(c1, "bad", c2, "warn").
func classIf(pairs ...any) string {
	for i := 0; i+1 < len(pairs); i += 2 {
		if c, _ := pairs[i].(bool); c {
			s, _ := pairs[i+1].(string)
			return s
		}
	}
	return ""
}

// days renders a duration in whole days ("3 days"), or hours under two days.
func days(d time.Duration) string {
	if d < 48*time.Hour {
		return plural(int(d.Hours()), "hour", "hours")
	}
	return plural(int(d.Hours()/24), "day", "days")
}

// anomalyRules are plain names for anomaly signals.
var anomalyRules = map[string]string{
	"silence": "stopped reporting", "replay": "replayed report", "clock_skew": "clock skew",
	"package_change": "packages changed", "package_downgrade": "package downgraded",
	"kernel_no_reboot": "kernel not rebooted", "unexpected_reboot": "unexpected reboot",
	"collector_changed": "collector changed", "peer_outlier": "unlike its peers",
	"trigger_disabled": "change watch disabled", "privileged_access": "privileged access",
	"privilege_watch_disabled": "privilege watch disabled", "uptime_inconsistent": "uptime doesn't add up",
	"inventory_reverted": "inventory reverted", "package_drop": "packages dropped",
	"collector_downgrade": "collector downgraded", "os_changed": "OS changed",
}

func ruleLabel(rule string) string {
	if l, ok := anomalyRules[rule]; ok {
		return l
	}
	return strings.ReplaceAll(rule, "_", " ")
}
