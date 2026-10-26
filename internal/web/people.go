// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"cmp"
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/privilege"
	"github.com/realmwatch/heimdall/internal/store"
)

// People (docs/ip-awareness.md#people): /ips/person/{person} is one
// person's addresses in one place. A person is whatever labels name in
// Person (an email, usually), plus the Heimdall user it is, if any: their
// email and display name name them too, so sign-in guesses ("Alice") and
// labels ("alice@example.com") meet on one page.
//
// It shows what the viewer could see on each address's IP page: labels
// from the orgs they can view and every org's, privileged sessions on
// their hosts, and sign-ins only for global admins.

// ── The label form (partials.html), on /ips and person pages ──────────────

type labelForm struct {
	CSRF    string
	Kinds   []string
	Prefill labelPrefill
	People  []string    // known people, for the Person field's suggestions
	Admin   []store.Org // orgs the viewer can label
	AllOrgs bool        // and every org
	Back    string      // where to go after adding ("" is /ips)
}

// labelPrefill fills the form: ?addr=, and ?person= (a person page) or
// ?me=1 ("It's me": staff, the viewer).
type labelPrefill struct {
	Addr, Kind, Name, Person string
	Me                       bool // the viewer has a name to label with, so offer "It's me"
}

// labelKinds are the kinds a person can give a label.
var labelKinds = []string{store.IPKindStaff, store.IPKindOffice, store.IPKindAutomation, store.IPKindInfra, store.IPKindTailnet, store.IPKindPrivate}

// prefillFor reads the form's prefill from the query.
func prefillFor(r *http.Request, v *auth.Viewer) labelPrefill {
	q := r.URL.Query()
	var p labelPrefill
	if a, err := store.ParseIPPrefix(q.Get("addr")); err == nil {
		p.Addr = a.String()
		if a.IsSingleIP() {
			p.Addr = a.Addr().String()
		}
	}
	me := cmp.Or(v.Email, v.DisplayName)
	p.Me = me != ""
	switch {
	case q.Get("me") == "1" && me != "":
		local, _, _ := strings.Cut(v.Email, "@")
		p.Kind, p.Person, p.Name = store.IPKindStaff, me, possessive(cmp.Or(v.DisplayName, local))+" address"
	case strings.TrimSpace(q.Get("person")) != "":
		p.Kind, p.Person = store.IPKindStaff, clipRunes(strings.TrimSpace(q.Get("person")), 200)
	}
	return p
}

func (s *server) labelFormFor(r *http.Request, v *auth.Viewer, admin []store.Org, p labelPrefill, back string) (labelForm, error) {
	people, err := s.knownPeople(r.Context(), v)
	return labelForm{CSRF: auth.CSRFToken(v.SessionToken), Kinds: labelKinds, Prefill: p, People: people,
		Admin: admin, AllOrgs: v.IsAdmin, Back: back}, err
}

// possessive is "Alice's", "James'".
func possessive(name string) string {
	if strings.HasSuffix(name, "s") {
		return name + "'"
	}
	return name + "'s"
}

func clipRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// ── Who the viewer may know about ─────────────────────────────────────────

// visibleUsers are the Heimdall users the viewer may see: everyone, for a
// global admin; else the users with a role in an org the viewer can view.
func (s *server) visibleUsers(ctx context.Context, v *auth.Viewer) ([]store.User, error) {
	users, err := s.st.ListUsers(ctx)
	if err != nil || v.IsAdmin {
		return users, err
	}
	orgs, err := s.st.ListOrgs(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, o := range orgs {
		seen[o.Slug] = v.Scope.CanView(o.ID)
	}
	var out []store.User
	for _, u := range users {
		ms, err := s.st.Memberships(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		if u.ID == v.UserID || slices.ContainsFunc(ms, func(m store.Membership) bool { return seen[m.OrgSlug] }) {
			out = append(out, u)
		}
	}
	return out, nil
}

// visibleLabels are the labels in the orgs the viewer can view, and every
// org's, each once, with the org's slug ("" for every org).
func (s *server) visibleLabels(ctx context.Context, v *auth.Viewer) ([]personLabel, error) {
	orgs, err := s.st.ListOrgs(ctx)
	if err != nil {
		return nil, err
	}
	slugs := map[int64]string{}
	ids := []int64{0}
	for _, o := range orgs {
		if v.Scope.CanView(o.ID) {
			slugs[o.ID] = o.Slug
			ids = append(ids, o.ID)
		}
	}
	var out []personLabel
	seen := map[int64]bool{}
	for _, id := range ids {
		ls, err := s.st.IPLabels(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, l := range ls {
			if !seen[l.ID] {
				seen[l.ID] = true
				pl := personLabel{IPLabel: l, Org: slugs[l.OrgID]}
				if l.Prefix.IsSingleIP() {
					pl.Href = "/ips/" + url.PathEscape(l.Prefix.Addr().String())
				}
				out = append(out, pl)
			}
		}
	}
	return out, nil
}

// knownPeople suggests people for the label form: the users the viewer
// may see and the people labels name, emails first.
func (s *server) knownPeople(ctx context.Context, v *auth.Viewer) ([]string, error) {
	users, err := s.visibleUsers(ctx, v)
	if err != nil {
		return nil, err
	}
	labels, err := s.visibleLabels(ctx, v)
	if err != nil {
		return nil, err
	}
	var out []string
	add := func(p string) {
		if p = strings.TrimSpace(p); p != "" && !slices.ContainsFunc(out, func(o string) bool { return strings.EqualFold(o, p) }) {
			out = append(out, p)
		}
	}
	for _, u := range users {
		if !u.Disabled {
			add(u.Email)
		}
	}
	for _, l := range labels {
		add(l.Person)
	}
	slices.SortStableFunc(out, func(a, b string) int {
		return cmp.Or(cmp.Compare(boolInt(!strings.Contains(a, "@")), boolInt(!strings.Contains(b, "@"))), strings.Compare(a, b))
	})
	return out[:min(len(out), 500)], nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ── /ips/person/{person} ───────────────────────────────────────────────────

type personBody struct {
	Person   string
	User     *store.User // the Heimdall user it is, if the viewer may see them
	Names    []string    // every name it goes by
	Labels   []personLabel
	SignedIn []personAddr // addresses they signed in to Heimdall from (global admins)
	Sessions []personSession
	SignIns  []store.SignIn
	// ShowSignIns: global admins only, as on the IP page.
	ShowSignIns, CanLabel, ShowOrgs bool
	Form                            labelForm
}

type personLabel struct {
	store.IPLabel
	Org  string // its org's slug, "" for every org
	Href string // the IP page, for a single address
}

// personAddr is an address someone signed in to Heimdall from.
type personAddr struct {
	Addr, Href string
	Last       time.Time
	Count      int
}

// personSession is a host's privileged sessions from one of the person's
// addresses.
type personSession struct {
	store.PrivilegeSource
	Href  string
	Badge ipBadge
	Kinds string // "2 sudo, 1 root SSH"
}

// personLookback is how far back the person page looks for sessions and
// sign-ins; personLimit caps each list.
const (
	personLookback = 30 * 24 * time.Hour
	personLimit    = 50
	personSignIns  = 15 // newest sign-ins listed
)

func (s *server) personPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ctx := r.Context()
	person := strings.TrimSpace(r.PathValue("person"))
	if person == "" || len([]rune(person)) > 200 {
		s.notFound(w, r, v)
		return
	}
	_, orgs, err := s.orgFilter(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := personBody{Person: person, Names: []string{person}, ShowSignIns: v.IsAdmin, ShowOrgs: len(orgs) > 1}
	users, err := s.visibleUsers(ctx, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	for _, u := range users {
		if strings.EqualFold(u.Email, person) || (u.DisplayName != "" && strings.EqualFold(u.DisplayName, person)) {
			body.User = &u
			for _, n := range []string{u.Email, u.DisplayName} {
				if n != "" && !slices.ContainsFunc(body.Names, func(o string) bool { return strings.EqualFold(o, n) }) {
					body.Names = append(body.Names, n)
				}
			}
			break
		}
	}
	names := func(p string) bool {
		return p != "" && slices.ContainsFunc(body.Names, func(n string) bool { return strings.EqualFold(n, strings.TrimSpace(p)) })
	}

	labels, err := s.visibleLabels(ctx, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	for _, l := range labels {
		if names(l.Person) {
			body.Labels = append(body.Labels, l)
		}
	}
	slices.SortStableFunc(body.Labels, func(a, b personLabel) int {
		return cmp.Or(cmp.Compare(boolInt(a.Source != store.IPSourceManual), boolInt(b.Source != store.IPSourceManual)),
			strings.Compare(a.Source, b.Source), strings.Compare(a.Prefix.String(), b.Prefix.String()))
	})

	// Their sign-ins, and the addresses they came from: what sign-in
	// guesses go by.
	if body.ShowSignIns && body.User != nil {
		ins, err := s.st.SignInsBy(ctx, body.User.ID, 200)
		if err != nil {
			s.fail(w, r, v, err)
			return
		}
		cutoff := s.now().Add(-personLookback)
		for _, si := range ins {
			// Loopback (behind a proxy) says nothing about where they were.
			a, err := netip.ParseAddr(si.IP)
			if err != nil || a.IsLoopback() || a.IsUnspecified() {
				continue
			}
			if len(body.SignIns) < personSignIns {
				body.SignIns = append(body.SignIns, si)
			}
			if si.Until.Before(cutoff) {
				continue
			}
			i := slices.IndexFunc(body.SignedIn, func(p personAddr) bool { return p.Addr == si.IP })
			if i < 0 {
				body.SignedIn = append(body.SignedIn, personAddr{Addr: si.IP, Href: "/ips/" + url.PathEscape(a.Unmap().String())})
				i = len(body.SignedIn) - 1
			}
			p := &body.SignedIn[i]
			p.Count++
			if si.Until.After(p.Last) {
				p.Last = si.Until
			}
		}
	}

	// Privileged sessions from an address that names them, on hosts the
	// viewer can see: any label about the address, guesses included.
	srcs, err := s.st.PrivilegeSourcesSince(ctx, v.Scope, 0, s.now().Add(-personLookback))
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
		vd := resolve(src.Source, "", src.Last)
		if !slices.ContainsFunc(vd.Labels, func(l ipinfo.Label) bool {
			return names(l.Person) && l.Prefix.IsValid() && l.Prefix.Contains(vd.Addr)
		}) {
			continue
		}
		body.Sessions = append(body.Sessions, personSession{PrivilegeSource: src, Href: ipURL(vd), Badge: badgeFor(vd),
			Kinds: privilege.Counts(src.Kinds)})
	}
	slices.SortStableFunc(body.Sessions, func(a, b personSession) int { return b.Last.Compare(a.Last) })
	body.Sessions = body.Sessions[:min(len(body.Sessions), personLimit)]

	admin, err := s.labelOrgs(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if body.CanLabel = len(admin) > 0 || v.IsAdmin; body.CanLabel {
		pre := labelPrefill{Kind: store.IPKindStaff, Person: person}
		if body.User != nil && body.User.Email != "" {
			pre.Person = body.User.Email
		}
		if body.Form, err = s.labelFormFor(r, v, admin, pre, personURL(person)); err != nil {
			s.fail(w, r, v, err)
			return
		}
	}
	title := person
	if body.User != nil && body.User.DisplayName != "" && !strings.EqualFold(body.User.DisplayName, person) {
		title = body.User.DisplayName
	}
	s.render(w, r, http.StatusOK, "person", v, title, "ips", body)
}
