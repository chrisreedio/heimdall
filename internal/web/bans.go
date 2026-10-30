// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/bans"
	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/store"
)

// Bans (internal/bans, docs/bans.md): /bans is where operators approve,
// reject and lift bans, turn the ban rules on per zone and pause every
// Cloudflare write. Bans are hub-wide at Cloudflare, so admins see them
// all; an operator sees the bans and candidates that touched hosts in an
// org they operate, with other orgs' hosts left out (the counts are the
// fleet's). Every action is a POST with the CSRF token; the Discord card
// only links here.

const (
	banCandidateRows = 50
	banRecentDays    = 30
	banAuditRows     = 100
)

// canOperateAny: an admin, or an operator somewhere.
func canOperateAny(v *auth.Viewer) bool {
	return v.Scope.Admin || slices.ContainsFunc(mapsKeys(v.Scope.Orgs), v.Scope.CanOperate)
}

// banVisible: the viewer operates an org whose hosts the ban touched.
func banVisible(v *auth.Viewer, orgs []int64) bool {
	return v.Scope.Admin || slices.ContainsFunc(orgs, v.Scope.CanOperate)
}

type banFactor struct {
	Label  string
	Value  float64
	Points float64
}

type banRow struct {
	store.Ban
	Ev        bans.Evidence
	Factors   []banFactor
	Hosts     []bans.Host // the viewer's
	HostsMore int         // other orgs' hosts, counted only
	Days      int
	Until     template.HTML // "Nov 1, 2026", in the viewer's time zone
	Left      string        // "in 3 days"
}

func (s *server) banRow(v *auth.Viewer, b store.Ban) banRow {
	fs, ev := bans.Decode(b)
	r := banRow{Ban: b, Ev: ev, Days: int(b.Duration.Hours() / 24)}
	for _, f := range fs {
		r.Factors = append(r.Factors, banFactor{Label: bans.FactorLabels[f.Name], Value: f.Value, Points: f.Points})
	}
	r.Hosts, r.HostsMore = visibleHosts(v, ev.Hosts)
	if !b.ExpiresAt.IsZero() {
		r.Until = dateHTML(b.ExpiresAt)
		r.Left = untilText(b.ExpiresAt.Sub(s.now()))
	}
	return r
}

func visibleHosts(v *auth.Viewer, hs []bans.Host) (mine []bans.Host, others int) {
	for _, h := range hs {
		if v.Scope.CanView(h.OrgID) {
			mine = append(mine, h)
		} else {
			others++
		}
	}
	return mine, others
}

// untilText is how long is left: "in 3 days", "in 5 hours", "now".
func untilText(d time.Duration) string {
	switch {
	case d <= 0:
		return "now"
	case d < 2*time.Hour:
		return "in " + plural(int(d.Minutes())+1, "minute", "minutes")
	case d < 48*time.Hour:
		return "in " + plural(int(d.Hours()), "hour", "hours")
	}
	return "in " + plural(int(d.Hours()/24), "day", "days")
}

type banCandidateRow struct {
	bans.Candidate
	TargetText string
	Factors    []banFactor
	Hosts      []bans.Host
	HostsMore  int
	State      string // what happened to it: "proposed", "would ban", ...
}

type banZoneRow struct {
	ID, Name, Plan string
	Proxied        int
	Enabled        bool
	State, Note    string
	Applied        time.Time
}

type bansBody struct {
	Admin                 bool
	Mode, ModeText        string
	Writes                bool
	Paused                store.BanPause
	CF                    bool
	Token                 bool
	TokenNote             string
	TokenURL, TokenManual string
	Lists                 bans.ListsState
	Sync                  bans.SyncState
	ProposeAt             float64
	Proposals             []banRow
	Active                []banRow
	Shadow                []banRow
	Recent                []banRow
	Candidates            []banCandidateRow
	MoreCandidates        int
	Zones                 []banZoneRow
	ZonesOn               int
	Audit                 []store.BanAudit
	Flash                 string
}

var banModeText = map[string]string{
	config.BansOff:     "Off: nothing is scored. Set [bans] mode in heimdall.toml (start with \"shadow\").",
	config.BansShadow:  "Shadow: Heimdall scores and records what it would ban. Nothing is written to Cloudflare and nobody is notified.",
	config.BansPropose: "Propose: each ban waits for an operator's approval here, then goes to Cloudflare.",
	config.BansAuto:    "Auto: bans go to Cloudflare without approval, within the caps; over them, they wait for approval.",
}

func (s *server) bansConfig() config.Bans {
	if s.cfg.Bans != nil {
		return s.cfg.Bans.Cfg
	}
	return config.BansDefaults
}

func (s *server) bansPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if !canOperateAny(v) {
		s.notFound(w, r, v)
		return
	}
	ctx := r.Context()
	cfg := s.bansConfig()
	body := bansBody{Admin: v.Scope.Admin, Mode: cfg.Mode, ModeText: banModeText[cfg.Mode], Writes: cfg.Writes(),
		CF: s.cfg.Cloudflare, TokenURL: bans.TokenURL(), TokenManual: bans.TokenManualStep, ProposeAt: cfg.ProposeAt,
		Flash: flashText[r.URL.Query().Get("done")]}
	if svc := s.cfg.Bans; svc != nil {
		body.Token, body.TokenNote = svc.TokenNote == "", svc.TokenNote
	} else {
		body.TokenNote = "bans are off"
	}
	var err error
	if body.Paused, err = s.st.BanPaused(ctx); err != nil {
		s.fail(w, r, v, err)
		return
	}
	body.Lists, _ = bans.Lists(ctx, s.st)
	body.Sync, _ = bans.LastSync(ctx, s.st)

	all, err := s.st.Bans(ctx, store.BanQuery{Since: s.now().AddDate(0, 0, -banRecentDays), Limit: 2000})
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	open, err := s.st.Bans(ctx, store.BanQuery{Statuses: store.BanOpen, Limit: 100000})
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	seen := map[int64]bool{}
	for _, b := range append(open, all...) {
		if seen[b.ID] || !banVisible(v, b.Orgs) {
			continue
		}
		seen[b.ID] = true
		row := s.banRow(v, b)
		switch b.Status {
		case store.BanProposed:
			body.Proposals = append(body.Proposals, row)
		case store.BanPending, store.BanActive, store.BanLifting:
			body.Active = append(body.Active, row)
		case store.BanShadow:
			body.Shadow = append(body.Shadow, row)
		default:
			if len(body.Recent) < 50 {
				body.Recent = append(body.Recent, row)
			}
		}
	}

	if s.cfg.Bans != nil && s.cfg.Bans.Engine != nil && cfg.On() {
		cands, err := s.cfg.Bans.Engine.Candidates(ctx)
		if err != nil {
			s.fail(w, r, v, err)
			return
		}
		state := map[string]string{}
		for _, b := range open {
			state[b.Target] = b.Status
		}
		for _, b := range body.Shadow {
			if state[b.Target] == "" && b.ExpiresAt.After(s.now()) {
				state[b.Target] = "would ban"
			}
		}
		for _, c := range cands {
			if !banVisible(v, c.Orgs) {
				continue
			}
			if len(body.Candidates) == banCandidateRows {
				body.MoreCandidates++
				continue
			}
			row := banCandidateRow{Candidate: c, TargetText: bans.TargetString(c.Target), State: state[bans.TargetString(c.Target)]}
			for _, f := range c.Factors {
				row.Factors = append(row.Factors, banFactor{Label: bans.FactorLabels[f.Name], Value: f.Value, Points: f.Points})
			}
			row.Hosts, row.HostsMore = visibleHosts(v, c.Evidence.Hosts)
			body.Candidates = append(body.Candidates, row)
		}
	}

	if body.Zones, err = s.banZones(ctx, v); err != nil {
		s.fail(w, r, v, err)
		return
	}
	for _, z := range body.Zones {
		if z.Enabled {
			body.ZonesOn++
		}
	}
	if v.Scope.Admin {
		if body.Audit, err = s.st.BanAudits(ctx, banAuditRows); err != nil {
			s.fail(w, r, v, err)
			return
		}
	} else {
		audits, err := s.st.BanAudits(ctx, banAuditRows*5)
		if err != nil {
			s.fail(w, r, v, err)
			return
		}
		for _, a := range audits {
			if (a.BanID != 0 && seen[a.BanID]) || (a.BanID == 0 && a.ZoneID == "" && a.Target == "") {
				body.Audit = append(body.Audit, a)
			}
		}
		body.Audit = body.Audit[:min(len(body.Audit), banAuditRows)]
	}
	s.render(w, r, http.StatusOK, "bans", v, "Bans", "bans", body)
}

var flashText = map[string]string{
	"approve": "Approved: it goes to Cloudflare within a minute.", "reject": "Rejected.",
	"unban": "Unbanned: it comes off Cloudflare within a minute.", "pause": "Paused: Heimdall writes nothing to Cloudflare.",
	"resume": "Resumed.", "zone": "Saved: the rule is written (or removed) within a minute.",
}

// banZones are the synced zones the viewer may see (as on /surface), with
// their opt-in.
func (s *server) banZones(ctx context.Context, v *auth.Viewer) ([]banZoneRow, error) {
	if !s.cfg.Cloudflare {
		return nil, nil
	}
	m, err := s.surfaceMap(ctx)
	if err != nil {
		return nil, err
	}
	m = m.For(v.Scope.Admin, v.Scope.CanOperate)
	opted, err := s.st.BanZones(ctx)
	if err != nil {
		return nil, err
	}
	var out []banZoneRow
	for _, z := range m.Zones {
		bz := opted[z.ID]
		out = append(out, banZoneRow{ID: z.ID, Name: z.Name, Plan: z.Plan, Proxied: z.Proxied, Enabled: bz.Enabled,
			State: bz.State, Note: bz.Note, Applied: bz.AppliedAt})
	}
	return out, nil
}

// banAction approves, rejects or unbans one ban.
func (s *server) banAction(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	action := r.PathValue("action")
	if err != nil || !canOperateAny(v) || !slices.Contains([]string{"approve", "reject", "unban"}, action) {
		s.notFound(w, r, v)
		return
	}
	ctx := r.Context()
	b, err := s.st.BanByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !banVisible(v, b.Orgs)) {
		s.notFound(w, r, v)
		return
	}
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	note := strings.TrimSpace(r.PostForm.Get("note"))
	switch action {
	case "approve", "reject":
		if !s.bansConfig().Writes() && action == "approve" {
			http.Error(w, "[bans] mode doesn't write to Cloudflare; set mode = \"propose\" first", http.StatusConflict)
			return
		}
		err = s.st.DecideBan(ctx, id, action == "approve", actorOf(v), note, s.now())
	case "unban":
		err = s.st.Unban(ctx, id, actorOf(v), s.now())
	}
	back := backTo(r, "/bans", "/defense")
	if store.IsBanState(err) {
		http.Redirect(w, r, fmt.Sprintf("%s#ban-%d", back, id), http.StatusSeeOther) // decided meanwhile: show it
		return
	}
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	s.log.Info("ban decided", "ban", id, "target", b.Target, "action", action, "by", v.UserID)
	s.cfg.Bans.Kick()
	http.Redirect(w, r, fmt.Sprintf("%s?done=%s#ban-%d", back, action, id), http.StatusSeeOther)
}

// backTo is where an action's redirect goes: the page the form was on,
// when its "back" field names one of pages (the phone tabs that act too),
// else def.
func backTo(r *http.Request, def string, pages ...string) string {
	if b := r.PostForm.Get("back"); slices.Contains(pages, b) {
		return b
	}
	return def
}

// banPause flips the "pause all" switch: any operator may pull it.
func (s *server) banPause(paused bool) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
		if !canOperateAny(v) {
			s.notFound(w, r, v)
			return
		}
		if err := s.st.SetBanPaused(r.Context(), paused, actorOf(v), strings.TrimSpace(r.PostForm.Get("note")), s.now()); err != nil {
			s.fail(w, r, v, err)
			return
		}
		done := "resume"
		if paused {
			done = "pause"
		} else {
			s.cfg.Bans.Kick()
		}
		http.Redirect(w, r, "/bans?done="+done, http.StatusSeeOther)
	}
}

// banZone turns the ban rules on or off for one zone the viewer may see.
func (s *server) banZone(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if !canOperateAny(v) {
		s.notFound(w, r, v)
		return
	}
	ctx := r.Context()
	zs, err := s.banZones(ctx, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	id := r.PostForm.Get("zone")
	i := slices.IndexFunc(zs, func(z banZoneRow) bool { return z.ID == id })
	if i < 0 {
		s.notFound(w, r, v)
		return
	}
	on := r.PostForm.Get("on") == "1"
	if err := s.st.SetBanZone(ctx, id, zs[i].Name, on, actorOf(v), s.now()); err != nil {
		s.fail(w, r, v, err)
		return
	}
	s.cfg.Bans.Kick()
	http.Redirect(w, r, "/bans?done=zone#zones", http.StatusSeeOther)
}

// surfaceBanZones is the /surface zones table's "ban rule" column, by
// zone ID; nil (no column) unless [bans] is on.
func (s *server) surfaceBanZones(ctx context.Context) map[string]store.BanZone {
	if !s.bansConfig().On() {
		return nil
	}
	m, err := s.st.BanZones(ctx)
	if err != nil {
		s.log.Warn("ban zones", "err", err)
		return nil
	}
	if m == nil {
		m = map[string]store.BanZone{}
	}
	return m
}

func init() {
	// dict builds a map for a sub-template: dict "Row" . "CSRF" $csrf.
	funcs["dict"] = func(kv ...any) map[string]any {
		m := make(map[string]any, len(kv)/2)
		for i := 0; i+1 < len(kv); i += 2 {
			if k, ok := kv[i].(string); ok {
				m[k] = kv[i+1]
			}
		}
		return m
	}
}
