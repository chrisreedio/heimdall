// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/logins"
	"github.com/realmwatch/heimdall/internal/store"
)

// The phone layout (docs/mobile.md): on narrow screens a bottom tab bar
// (Home, Hosts, Alerts, Defense, More) replaces the sidebar. Home is the
// dashboard as attention cards; Alerts, Defense and More are the pages
// below, built from what the other pages already show. They work on any
// screen; only the tab bar is phone-only.

// tabs maps a page's nav name to its tab; pages not listed are under More.
var tabs = map[string]string{
	"dashboard": "home",
	"hosts":     "hosts",
	"alerts":    "alerts", "anomalies": "alerts", "news": "alerts",
	"defense": "defense", "offenders": "defense", "bans": "defense",
}

// Tab is the bottom tab bar's current tab ("" when signed out).
func (p page) Tab() string {
	if t, ok := tabs[p.Nav]; ok {
		return t
	}
	return "more"
}

// homeCard is one of the phone dashboard's attention cards.
type homeCard struct {
	N          int
	Label, Sub string
	Href       string
	Class      string // "bad" or "warn"
}

// homeCards are the phone dashboard's cards, most urgent first ("bad"
// before "warn", otherwise in this order). None means all clear.
func homeCards(kev, kevHosts, news, banWaiting, anomalies, high int, unknown *unknownIPs, stale int, staleAfter string) []homeCard {
	var cards []homeCard
	add := func(c bool, card homeCard) {
		if c {
			cards = append(cards, card)
		}
	}
	add(kev > 0, homeCard{N: kev, Label: plural0(kev, "known-exploited finding", "known-exploited findings"),
		Sub: "on " + plural(kevHosts, "host", "hosts"), Href: "/hosts?only=kev&sort=priority", Class: "bad"})
	add(news > 0, homeCard{N: news, Label: plural0(news, "incident in the news", "incidents in the news"),
		Sub: "affecting your hosts", Href: "/news?affects=me", Class: "bad"})
	add(banWaiting > 0, homeCard{N: banWaiting, Label: plural0(banWaiting, "ban proposal waiting", "ban proposals waiting"),
		Sub: "for an operator's decision", Href: "/bans", Class: "warn"})
	if anomalies > 0 {
		c := homeCard{N: anomalies, Label: plural0(anomalies, "open anomaly", "open anomalies"), Sub: "tripwires that fired", Href: "/alerts", Class: "warn"}
		if high > 0 {
			c.Class, c.Sub = "bad", strconv.Itoa(high)+" high severity"
		}
		cards = append(cards, c)
	}
	if unknown != nil {
		cards = append(cards, homeCard{N: unknown.Sessions, Label: plural0(unknown.Sessions, "privileged session from an unknown address", "privileged sessions from unknown addresses"),
			Sub: "in the last 7 days", Href: "/alerts", Class: "warn"})
	}
	add(stale > 0, homeCard{N: stale, Label: plural0(stale, "host not reporting", "hosts not reporting"),
		Sub: "no report in " + staleAfter, Href: "/hosts?only=stale&sort=seen", Class: "warn"})
	slices.SortStableFunc(cards, func(a, b homeCard) int { return classRank(a.Class) - classRank(b.Class) })
	return cards
}

func classRank(c string) int {
	if c == "bad" {
		return 0
	}
	return 1
}

// banProposals counts ban proposals waiting for the viewer (an operator
// of an org the ban touches); 0 for everyone else.
func (s *server) banProposals(ctx context.Context, v *auth.Viewer) (int, error) {
	if !canOperateAny(v) {
		return 0, nil
	}
	bs, err := s.st.Bans(ctx, store.BanQuery{Statuses: []string{store.BanProposed}, Limit: 1000})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, b := range bs {
		if banVisible(v, b.Orgs) {
			n++
		}
	}
	return n, nil
}

// ── Alerts ─────────────────────────────────────────────────────────────────

// alertItem is one line of /alerts: an open anomaly, privileged sessions
// from an address nobody knows, or an incident in the news that affects a
// host.
type alertItem struct {
	At       time.Time
	Kind     string // "anomaly", "privilege", "news"
	Severity string // a sev class for anomalies and news
	Title    string
	Detail   string
	Hosts    []store.IngestHost
	Href     string
	// An anomaly's, for Acknowledge and Mute: its ID and signal, and
	// whether the viewer may triage it (operator in the host's org).
	ID         int64
	Rule       string
	CanOperate bool
}

type alertsBody struct {
	Items    []alertItem
	More     int
	News     bool // threat news is on
	ShowOrgs bool
	Notice   string
}

var alertNotices = map[string]string{"ack": "Acknowledged.", "suppress": "Muted and acknowledged."}

const maxAlerts = 200

func (s *server) alertsPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ctx := r.Context()
	var items []alertItem
	anoms, err := s.st.OpenAnomalies(ctx, v.Scope)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	for _, a := range anoms {
		items = append(items, alertItem{At: a.DetectedAt, Kind: "anomaly", Severity: a.Severity, Title: ruleLabel(a.Rule),
			Detail: a.Summary, Hosts: []store.IngestHost{a.Host}, Href: hostURL(a.Host.OrgSlug, a.Host.Name),
			ID: a.ID, Rule: a.Rule, CanOperate: v.Scope.CanOperate(a.Host.OrgID)})
	}

	srcs, err := s.st.PrivilegeSourcesSince(ctx, v.Scope, 0, s.now().Add(-7*24*time.Hour))
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	resolvers := map[int64]func(ip, user string, at time.Time) ipinfo.Verdict{}
	for i, src := range srcs {
		if i == maxDashSources {
			break
		}
		resolve := resolvers[src.Host.OrgID]
		if resolve == nil {
			resolve = s.ips().Batch(ctx, src.Host.OrgID)
			resolvers[src.Host.OrgID] = resolve
		}
		if _, ok := unknownSource(resolve, src); !ok {
			continue
		}
		detail := plural(src.Count, "session", "sessions") + " from " + src.Source
		if len(src.Users) > 0 {
			detail += " as " + strings.Join(src.Users, ", ")
		}
		items = append(items, alertItem{At: src.Last, Kind: "privilege", Severity: "medium",
			Title: "Privileged access from an unknown address", Detail: detail, Hosts: []store.IngestHost{src.Host},
			Href: hostURL(src.Host.OrgSlug, src.Host.Name) + "#privilege"})
	}

	if s.cfg.News {
		entries, err := s.st.News(ctx, v.Scope)
		if err != nil {
			s.fail(w, r, v, err)
			return
		}
		for _, e := range entries {
			if len(e.Hosts) == 0 {
				continue
			}
			it := alertItem{At: e.UpdatedAt, Kind: "news", Severity: e.Severity, Title: e.Title, Href: "/news?affects=me"}
			for _, h := range e.Hosts {
				it.Hosts = append(it.Hosts, store.IngestHost{ID: h.HostID, OrgID: h.OrgID, OrgSlug: h.OrgSlug, Name: h.Name})
			}
			items = append(items, it)
		}
	}
	slices.SortStableFunc(items, func(a, b alertItem) int { return b.At.Compare(a.At) })
	_, orgs, err := s.orgFilter(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := alertsBody{News: s.cfg.News, ShowOrgs: len(orgs) > 1, Notice: alertNotices[r.URL.Query().Get("done")]}
	if len(items) > maxAlerts {
		body.More, items = len(items)-maxAlerts, items[:maxAlerts]
	}
	body.Items = items
	s.render(w, r, http.StatusOK, "alerts", v, "Alerts", "alerts", body)
}

// ── Defense ────────────────────────────────────────────────────────────────

type defenseBody struct {
	Operator  bool     // may see bans
	Proposals []banRow // ban proposals waiting, to approve or dismiss here
	Active    []banRow // bans in force or on their way
	Writes    bool     // [bans] mode writes to Cloudflare, so approving is possible
	Offenders []offenderRow
	More      int
	Failures  int // failed logins in the last 24 hours
	CF        bool
	Flash     string
}

const defenseOffenders = 8

// defensePage gathers failed logins, repeat offenders and bans: the
// top of /offenders and /bans, which it links to.
func (s *server) defensePage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ctx := r.Context()
	body := defenseBody{Operator: canOperateAny(v), CF: s.cfg.Cloudflare, Writes: s.bansConfig().Writes(),
		Flash: flashText[r.URL.Query().Get("done")]}
	if r.URL.Query().Get("done") == "reject" {
		body.Flash = "Dismissed." // the button here says Dismiss
	}
	rk := s.ranker()
	rep, err := rk.Rank(ctx, logins.Query{Scope: v.Scope, Since: s.now().Add(-24 * time.Hour)})
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body.Failures = rep.Failures
	body.Offenders, body.More = s.offenderRows(rep.Offenders, defenseOffenders)
	if body.Operator {
		open, err := s.st.Bans(ctx, store.BanQuery{Statuses: store.BanOpen, Limit: 100000})
		if err != nil {
			s.fail(w, r, v, err)
			return
		}
		for _, b := range open {
			if !banVisible(v, b.Orgs) {
				continue
			}
			switch b.Status {
			case store.BanProposed:
				body.Proposals = append(body.Proposals, s.banRow(v, b))
			case store.BanPending, store.BanActive, store.BanLifting:
				body.Active = append(body.Active, s.banRow(v, b))
			}
		}
	}
	s.render(w, r, http.StatusOK, "defense", v, "Defense", "defense", body)
}

// ── More ───────────────────────────────────────────────────────────────────

// morePage lists every page the tab bar doesn't, as the sidebar does.
func (s *server) morePage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	s.render(w, r, http.StatusOK, "more", v, "More", "more", nil)
}
