// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/privilege"
	"github.com/realmwatch/heimdall/internal/store"
)

// IP awareness (docs/ip-awareness.md): what Heimdall knows about an
// address, shown wherever one appears. /ips is where org admins label
// addresses and set the SSH source policy; /ips/{addr} is everything about
// one address in the orgs the viewer can see.

// ips is the resolver, or one that knows only the built-in ranges.
func (s *server) ips() *ipinfo.Resolver {
	if s.cfg.IPs != nil {
		return s.cfg.IPs
	}
	return &ipinfo.Resolver{}
}

// ipBadge is a compact verdict: who an address is, as a pill.
type ipBadge struct {
	Kind  string // store.IPKind*
	Text  string // "alice", "probably alice", "Laravel Forge", "unknown address"
	Title string // every label, for the tooltip
	Class string // pill classes
	Href  string // the address's IP page ("" if it isn't an address)
}

var badgeClass = map[string]string{store.IPKindStaff: "ok", store.IPKindTailnet: "ok", store.IPKindAutomation: "info",
	store.IPKindInfra: "info", store.IPKindPrivate: "muted", store.IPKindUnknown: "warn"}

func badgeFor(v ipinfo.Verdict) ipBadge {
	b := ipBadge{Kind: v.Kind(), Class: badgeClass[v.Kind()], Href: ipURL(v), Text: privilege.LabelText(v)}
	if v.Unknown() {
		b.Text = "unknown address"
		b.Title = "Nothing is known about this address. If it's yours, label it on the IP addresses page."
		return b
	}
	if v.UnknownAddress() {
		// Only the account is recognized (a deploy service's user), not
		// the address: say so, rather than vouch for it.
		b.Kind, b.Class = store.IPKindUnknown, badgeClass[store.IPKindUnknown]
		b.Text = "unknown address, " + v.Best().Name + " account"
		b.Title = "The account belongs to " + v.Best().Name + ", but the address isn't one of its known ranges."
		return b
	}
	if v.Best().Guess {
		b.Class += " guess"
	}
	var lines []string
	for _, l := range v.Labels {
		lines = append(lines, labelLine(l))
	}
	b.Title = strings.Join(lines, "\n")
	return b
}

// labelLine describes a label in a line: "staff: Office (alice), manual".
func labelLine(l ipinfo.Label) string {
	s := l.Kind + ": " + l.Name
	if l.Person != "" {
		s += " (" + l.Person + ")"
	}
	if l.Guess {
		s += ", a guess"
	}
	return s + ", from " + sourceName(l.Source)
}

// sourceName names where a label came from, for people.
func sourceName(src string) string {
	switch src {
	case store.IPSourceManual:
		return "a manual label"
	case "builtin":
		return "the built-in ranges"
	case "hosts":
		return "your hosts' reports"
	case "signin":
		return "Heimdall sign-ins"
	}
	return src
}

func ipURL(v ipinfo.Verdict) string {
	if !v.Addr.IsValid() {
		return ""
	}
	return "/ips/" + url.PathEscape(v.Addr.String())
}

// ipLink is an address and its IP page.
type ipLink struct{ Addr, Href string }

// unknownSource resolves a source's sessions (each user, for user hints)
// and reports whether any came from an unknown address.
func unknownSource(resolve func(ip, user string, at time.Time) ipinfo.Verdict, src store.PrivilegeSource) (ipinfo.Verdict, bool) {
	users := src.Users
	if len(users) == 0 {
		users = []string{""}
	}
	var v ipinfo.Verdict
	for _, u := range users {
		if v = resolve(src.Source, u, src.Last); v.UnknownAddress() {
			return v, true
		}
	}
	return v, false
}

// ── /ips: labels and policy ───────────────────────────────────────────────

type ipsBody struct {
	Orgs     []ipsOrg
	Global   []store.IPLabel // labels for every org
	AllOrgs  bool            // global admin: may add and remove labels for every org
	Admin    []store.Org     // orgs the viewer can label
	Kinds    []string
	Prefill  string // ?addr=, from an IP page
	Error    string
	ShowOrgs bool
}

type ipsOrg struct {
	Org    store.Org
	Policy store.IPPolicy
	Manual []store.IPLabel
	Synced []ipSourceGroup
}

// ipSourceGroup is one synced source's labels.
type ipSourceGroup struct {
	Source  string
	Updated time.Time
	Labels  []store.IPLabel
}

// labelKinds are the kinds a person can give a label.
var labelKinds = []string{store.IPKindStaff, store.IPKindAutomation, store.IPKindInfra, store.IPKindTailnet, store.IPKindPrivate}

// labelOrgs are the orgs the viewer administers (may label).
func (s *server) labelOrgs(r *http.Request, v *auth.Viewer) ([]store.Org, error) {
	all, err := s.st.ListOrgs(r.Context())
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(all, func(o store.Org) bool { return !v.Scope.CanAdmin(o.ID) }), nil
}

func (s *server) ipsPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	s.renderIPs(w, r, v, http.StatusOK, "")
}

func (s *server) renderIPs(w http.ResponseWriter, r *http.Request, v *auth.Viewer, status int, errMsg string) {
	ctx := r.Context()
	orgs, err := s.labelOrgs(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if len(orgs) == 0 && !v.IsAdmin {
		s.notFound(w, r, v)
		return
	}
	body := ipsBody{AllOrgs: v.IsAdmin, Admin: orgs, Kinds: labelKinds, Error: errMsg, ShowOrgs: len(orgs) > 1}
	if a, err := store.ParseIPPrefix(r.URL.Query().Get("addr")); err == nil {
		body.Prefill = a.String()
		if a.IsSingleIP() {
			body.Prefill = a.Addr().String()
		}
	}
	if body.Global, err = s.st.IPLabels(ctx, 0); err != nil {
		s.fail(w, r, v, err)
		return
	}
	for _, o := range orgs {
		io := ipsOrg{Org: o}
		if io.Policy, err = s.st.IPPolicy(ctx, o.ID); err != nil {
			s.fail(w, r, v, err)
			return
		}
		ls, err := s.st.IPLabels(ctx, o.ID)
		if err != nil {
			s.fail(w, r, v, err)
			return
		}
		for _, l := range ls {
			if l.OrgID != o.ID {
				continue // every org's: listed once, below
			}
			if l.Source == store.IPSourceManual {
				io.Manual = append(io.Manual, l)
				continue
			}
			i := slices.IndexFunc(io.Synced, func(g ipSourceGroup) bool { return g.Source == l.Source })
			if i < 0 {
				io.Synced = append(io.Synced, ipSourceGroup{Source: l.Source})
				i = len(io.Synced) - 1
			}
			g := &io.Synced[i]
			g.Labels = append(g.Labels, l)
			if l.UpdatedAt.After(g.Updated) {
				g.Updated = l.UpdatedAt
			}
		}
		body.Orgs = append(body.Orgs, io)
	}
	s.render(w, r, status, "ips", v, "IP addresses", "ips", body)
}

// labelOrg resolves the org a label form is for ("" is every org) and
// checks the viewer may change its labels.
func (s *server) labelOrg(r *http.Request, v *auth.Viewer) (int64, bool) {
	slug := strings.TrimSpace(r.PostForm.Get("org"))
	if slug == "" {
		return 0, v.IsAdmin
	}
	o, err := s.orgBySlug(r, slug)
	if err != nil || !v.Scope.CanAdmin(o.ID) {
		return 0, false
	}
	return o.ID, true
}

func (s *server) ipLabelAdd(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	orgID, ok := s.labelOrg(r, v)
	if !ok {
		s.renderIPs(w, r, v, http.StatusForbidden, "You can't label addresses in that org.")
		return
	}
	f := r.PostForm
	p, err := store.ParseIPPrefix(f.Get("prefix"))
	if err == nil && !slices.Contains(labelKinds, f.Get("kind")) {
		err = &store.ValidationError{Field: "kind", Msg: "pick a kind"}
	}
	if err == nil {
		_, err = s.st.AddIPLabel(r.Context(), actorOf(v), store.IPLabel{OrgID: orgID, Prefix: p, Kind: f.Get("kind"),
			Name: f.Get("name"), Person: f.Get("person"), Note: f.Get("note")})
	}
	if err != nil {
		s.renderIPs(w, r, v, http.StatusBadRequest, userError(err))
		return
	}
	http.Redirect(w, r, "/ips", http.StatusSeeOther)
}

func (s *server) ipLabelRemove(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	orgID, ok := s.labelOrg(r, v)
	if !ok {
		s.renderIPs(w, r, v, http.StatusForbidden, "You can't remove labels in that org.")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		err = s.st.RemoveIPLabel(r.Context(), actorOf(v), orgID, id)
	}
	switch {
	case errors.Is(err, store.ErrNotFound) || id == 0:
		s.renderIPs(w, r, v, http.StatusNotFound, "That label is gone already, or was kept in sync by a source (those can't be removed here).")
	case err != nil:
		s.renderIPs(w, r, v, http.StatusBadRequest, userError(err))
	default:
		http.Redirect(w, r, "/ips", http.StatusSeeOther)
	}
}

func (s *server) ipPolicySet(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	orgID, ok := s.labelOrg(r, v)
	if !ok || orgID == 0 {
		s.renderIPs(w, r, v, http.StatusForbidden, "You can't change that org's policy.")
		return
	}
	p := store.IPPolicy{OrgID: orgID, TailnetOnly: r.PostForm.Get("tailnet_only") == "on",
		AllowServices: r.PostForm.Get("allow_services") == "on", CountServices: r.PostForm.Get("count_services") == "on"}
	if err := s.st.SetIPPolicy(r.Context(), actorOf(v), p, s.now()); err != nil {
		s.fail(w, r, v, err)
		return
	}
	http.Redirect(w, r, "/ips", http.StatusSeeOther)
}

// ── /ips/{addr}: one address ───────────────────────────────────────────────

type ipBody struct {
	Addr     string
	Verdicts []ipVerdict // one per distinct verdict across the viewer's orgs
	Events   []ipEvent
	Hosts    []store.IngestHost // hosts whose reports come from it
	SignIns  []store.SignIn
	Audit    []store.AuditRow
	Logins   []store.HostLoginFailure // failed logins from it (logins.go)
	// What the viewer may see: sign-ins (admins), audit entries (admins of
	// an org), and whether they can label it.
	ShowSignIns, ShowAudit, CanLabel bool
	ShowOrgs                         bool
}

type ipVerdict struct {
	Orgs   []string // the orgs it holds in
	Badge  ipBadge
	Labels []ipinfo.Label
}

type ipEvent struct {
	store.HostPrivilegeEvent
	Kind string
}

// ipPageLimit caps each list on the IP page.
const ipPageLimit = 50

func (s *server) ipPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ctx := r.Context()
	a, err := netip.ParseAddr(r.PathValue("addr"))
	if err != nil || a.Zone() != "" {
		s.notFound(w, r, v)
		return
	}
	a = a.Unmap()
	addr := a.String()
	_, orgs, err := s.orgFilter(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := ipBody{Addr: addr, ShowOrgs: len(orgs) > 1, ShowSignIns: v.IsAdmin}
	var adminOrgs []int64
	for _, o := range orgs {
		vd := s.ips().Resolve(ctx, o.ID, addr, "", s.now())
		if i := slices.IndexFunc(body.Verdicts, func(iv ipVerdict) bool { return fmt.Sprint(iv.Labels) == fmt.Sprint(vd.Labels) }); i >= 0 {
			body.Verdicts[i].Orgs = append(body.Verdicts[i].Orgs, o.Slug)
		} else {
			body.Verdicts = append(body.Verdicts, ipVerdict{Orgs: []string{o.Slug}, Badge: badgeFor(vd), Labels: vd.Labels})
		}
		hs, err := s.st.HostsByReportIP(ctx, o.ID, addr)
		if err != nil {
			s.fail(w, r, v, err)
			return
		}
		for _, h := range hs {
			body.Hosts = append(body.Hosts, store.IngestHost{OrgID: o.ID, OrgSlug: o.Slug, Name: h})
		}
		if v.Scope.CanAdmin(o.ID) {
			adminOrgs = append(adminOrgs, o.ID)
		}
	}
	body.CanLabel, body.ShowAudit = len(adminOrgs) > 0 || v.IsAdmin, len(adminOrgs) > 0 || v.IsAdmin
	evs, err := s.st.PrivilegeFrom(ctx, v.Scope, addr, ipPageLimit)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	for _, ev := range evs {
		body.Events = append(body.Events, ipEvent{HostPrivilegeEvent: ev, Kind: privilege.KindLabel(ev.PrivilegeEvent.Kind)})
	}
	if body.Logins, err = s.ipLogins(ctx, v, addr); err != nil {
		s.fail(w, r, v, err)
		return
	}
	if body.ShowSignIns {
		if body.SignIns, err = s.st.SignInsFrom(ctx, addr, ipPageLimit); err != nil {
			s.fail(w, r, v, err)
			return
		}
	}
	if body.ShowAudit {
		if body.Audit, err = s.st.AuditFrom(ctx, addr, v.IsAdmin, adminOrgs, ipPageLimit); err != nil {
			s.fail(w, r, v, err)
			return
		}
	}
	s.render(w, r, http.StatusOK, "ip", v, addr, "", body)
}

// ── Dashboard ──────────────────────────────────────────────────────────────

// unknownIPs is the dashboard's line about privileged sessions from
// unknown addresses in the last week.
type unknownIPs struct {
	Sessions int
	Hosts    []store.IngestHost
}

// maxDashSources caps how many sources the dashboard resolves.
const maxDashSources = 500

func (s *server) unknownSources(ctx context.Context, v *auth.Viewer, org string) (*unknownIPs, error) {
	srcs, err := s.st.PrivilegeSourcesSince(ctx, v.Scope, 0, s.now().Add(-7*24*time.Hour))
	if err != nil {
		return nil, err
	}
	var out unknownIPs
	resolvers := map[int64]func(ip, user string, at time.Time) ipinfo.Verdict{}
	for i, src := range srcs {
		if i == maxDashSources {
			break
		}
		if org != "" && src.Host.OrgSlug != org {
			continue
		}
		resolve := resolvers[src.Host.OrgID]
		if resolve == nil {
			resolve = s.ips().Batch(ctx, src.Host.OrgID)
			resolvers[src.Host.OrgID] = resolve
		}
		if _, ok := unknownSource(resolve, src); !ok {
			continue
		}
		out.Sessions += src.Count
		if !slices.ContainsFunc(out.Hosts, func(h store.IngestHost) bool { return h.ID == src.Host.ID }) {
			out.Hosts = append(out.Hosts, src.Host)
		}
	}
	if out.Sessions == 0 {
		return nil, nil
	}
	return &out, nil
}
