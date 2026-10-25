// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/logins"
	"github.com/chrisreedio/heimdall/internal/store"
)

// Failed logins (docs/failed-logins.md): what the opt-in login watch
// counted. /offenders ranks the addresses nothing vouches for across the
// viewer's hosts; the host page gets a line with its top sources, and the
// IP page a table of where an address failed. Every count covers only
// hosts the viewer can see.

func (s *server) ranker() *logins.Ranker { return &logins.Ranker{Store: s.st, IPs: s.cfg.IPs} }

// loginWindows are the /offenders windows.
var loginWindows = []struct {
	Key   string
	Label string
	D     time.Duration
}{{"24h", "24 hours", 24 * time.Hour}, {"7d", "7 days", 7 * 24 * time.Hour}}

const (
	maxOffenderRows = 200 // rows /offenders lists
	maxKnownRows    = 50
	hostsShown      = 4 // hosts named per row; the rest are counted
)

type offendersBody struct {
	Window, WindowLabel string
	Windows             []windowLink
	Org                 string
	Orgs                []store.Org
	ShowOrgs            bool
	Offenders           []offenderRow
	MoreOffenders       int
	Known               []offenderRow
	MoreKnown           int
	Failures            int // every failure in the window's days, listed or not
	Repeat              int // offenders on more than one host
	GotIn               int // offenders a login from then succeeded
}

type windowLink struct {
	Key, Label, Href string
	Current          bool
}

type offenderRow struct {
	logins.Address
	Badge     ipBadge
	Href      string
	Shown     []store.IngestHost // the first hostsShown hosts
	HostsMore int                // and how many more
}

func (s *server) offenderRows(as []logins.Address, limit int) (rows []offenderRow, more int) {
	for i, a := range as {
		if i == limit {
			return rows, len(as) - limit
		}
		r := offenderRow{Address: a, Badge: badgeFor(a.Verdict), Href: ipURL(a.Verdict), Shown: a.Hosts}
		if n := len(a.Hosts); n > hostsShown {
			r.Shown, r.HostsMore = a.Hosts[:hostsShown], n-hostsShown
		}
		rows = append(rows, r)
	}
	return rows, 0
}

func (s *server) offendersPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ctx := r.Context()
	org, orgs, err := s.orgFilter(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	win := loginWindows[0]
	for _, lw := range loginWindows {
		if r.URL.Query().Get("since") == lw.Key {
			win = lw
		}
	}
	body := offendersBody{Window: win.Key, WindowLabel: win.Label, Org: org, Orgs: orgs, ShowOrgs: len(orgs) > 1}
	for _, lw := range loginWindows {
		q := url.Values{"since": {lw.Key}}
		if org != "" {
			q.Set("org", org)
		}
		body.Windows = append(body.Windows, windowLink{Key: lw.Key, Label: lw.Label, Href: "/offenders?" + q.Encode(), Current: lw.Key == win.Key})
	}
	rk := s.ranker()
	rep, err := rk.Rank(ctx, logins.Query{Scope: v.Scope, Org: org, Since: s.now().Add(-win.D)})
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if err := rk.Networks(ctx, rep.Offenders, maxOffenderRows); err != nil {
		s.fail(w, r, v, err)
		return
	}
	for _, a := range rep.Offenders {
		if len(a.Hosts) > 1 {
			body.Repeat++
		}
		if len(a.Succeeded) > 0 {
			body.GotIn++
		}
	}
	body.Failures = rep.Failures
	body.Offenders, body.MoreOffenders = s.offenderRows(rep.Offenders, maxOffenderRows)
	body.Known, body.MoreKnown = s.offenderRows(rep.Known, maxKnownRows)
	s.render(w, r, http.StatusOK, "offenders", v, "Repeat offenders", "offenders", body)
}

// ── The host page ──────────────────────────────────────────────────────────

// loginsView is the host page's "Failed logins" line. nil on Windows (no
// login watch there yet).
type loginsView struct {
	Watched   bool   // the host reports its login watch
	Source    string // where it reads failures, for people
	Problem   string // why it can't count, if it can't
	Counted   *time.Time
	Failures  int // in the last 24 hours
	Addresses int
	Top       []loginTop
	Fix       string // the command that turns it on
}

type loginTop struct {
	IP, Href   string
	Badge      ipBadge
	Known      bool // IP awareness vouches for it
	Failures   int
	Usernames  int
	Last       time.Time
	Succeeded  bool
	OtherHosts int // other hosts the viewer can see it failed on
	Network    string
}

const (
	loginTopN       = 5
	watchLoginsCmd  = "sudo heimdall-collect upgrade --watch-logins"
	loginsPerWindow = 24 * time.Hour
)

var loginSourceNames = map[string]string{"journal": "the journal", "auth.log": "/var/log/auth.log",
	"secure": "/var/log/secure", "messages": "/var/log/messages"}

func (s *server) loginsFor(ctx context.Context, v *auth.Viewer, host store.IngestHost, pm string) (*loginsView, error) {
	if pm == "windows" {
		return nil, nil
	}
	w, err := s.st.LoginWatchOf(ctx, host.ID)
	if err != nil {
		return nil, err
	}
	lv := &loginsView{Watched: w.Source != "", Source: loginSourceNames[w.Source], Fix: watchLoginsCmd}
	switch w.Source {
	case "none":
		lv.Problem = "No sshd log found (no journal entries, /var/log/auth.log, secure or messages)."
	case "unreadable":
		lv.Problem = "The collector can't read the counts; re-run: " + watchLoginsCmd
	}
	if !w.CountedAt.IsZero() {
		lv.Counted = &w.CountedAt
	}
	if !lv.Watched {
		return lv, nil
	}
	since := s.now().Add(-loginsPerWindow)
	rk := s.ranker()
	rep, err := rk.Rank(ctx, logins.Query{Scope: store.AllScope, HostID: host.ID, Since: since})
	if err != nil {
		return nil, err
	}
	lv.Failures, lv.Addresses = rep.Failures, len(rep.Offenders)+len(rep.Known)
	// Offenders first: they're what the line is for.
	all := append(append([]logins.Address{}, rep.Offenders...), rep.Known...)
	if len(all) > loginTopN {
		all = all[:loginTopN]
	}
	if err := rk.Networks(ctx, all, 0); err != nil {
		return nil, err
	}
	for i, a := range all {
		known := i >= len(rep.Offenders)
		t := loginTop{IP: a.IP, Href: ipURL(a.Verdict), Badge: badgeFor(a.Verdict), Known: known, Failures: a.Failures,
			Usernames: a.Usernames, Last: a.Last, Succeeded: len(a.Succeeded) > 0, Network: a.Network}
		if !known {
			// Where else it failed, on the viewer's hosts only (and only
			// where it's an offender: another org may know it).
			fr, err := rk.Rank(ctx, logins.Query{Scope: v.Scope, IP: a.IP, Since: since})
			if err != nil {
				return nil, err
			}
			for _, o := range fr.Offenders {
				t.OtherHosts += len(o.Hosts)
			}
			t.OtherHosts = max(t.OtherHosts-1, 0)
		}
		lv.Top = append(lv.Top, t)
	}
	return lv, nil
}

// ── The IP page ────────────────────────────────────────────────────────────

// ipLogins is where an address failed to log in, on the viewer's hosts,
// in the last 30 days (how long counts are kept).
func (s *server) ipLogins(ctx context.Context, v *auth.Viewer, addr string) ([]store.HostLoginFailure, error) {
	rows, err := s.st.LoginFailuresSince(ctx, v.Scope, 0, addr, s.now().Add(-store.LoginRetention))
	if len(rows) > ipPageLimit {
		rows = rows[:ipPageLimit]
	}
	return rows, err
}

// parseLoginsTemplates adds the host page's card and the IP page's table.
func parseLoginsTemplates(pages map[string]*template.Template) error {
	for _, p := range []string{"host", "ip"} {
		if _, err := pages[p].ParseFS(templatesFS, "templates/logins.html"); err != nil {
			return err
		}
	}
	return nil
}
