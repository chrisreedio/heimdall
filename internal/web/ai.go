// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/realmwatch/heimdall/internal/ai"
	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

// AIService is the optional AI analysis (internal/ai.Service). nil = off.
// Runs happen in the background; the pages show the last result.
type AIService interface {
	Deployment() string
	Stale() time.Duration
	StartHost(ctx context.Context, actor string, org store.Org, host store.IngestHost) error
	StartBrief(ctx context.Context, actor string, org store.Org) error
}

// aiNotices are the fixed messages a regenerate redirect can carry.
var aiNotices = map[string]string{
	"started": "Working on it. This takes up to a minute or two.",
	"busy":    "An analysis is already running.",
	"soon":    "An analysis started less than a minute ago. Try again shortly.",
	"denied":  "You need the operator role to run an analysis.",
}

// aiView is one brief or host explanation, as the templates see it.
type aiView struct {
	ai.View
	At, ErrorAt *time.Time
	Org         store.Org
	Host        string // the host page's host ("" for briefs)
	CanRun      bool   // operator or admin in the org
	Action      string // the regenerate form's path
	Notice      string
	CSRF        string
	// Handoffs are "Hand off to agent" buttons per action index, on
	// Composer steps only (see aiHandoffs).
	Handoffs map[int][]handoffLink
	Links    *aiLinker // links the org's hosts and sites in the text
}

// aiBriefs is the dashboard's brief card: one brief per visible org.
type aiBriefs struct {
	Briefs  []aiView
	ShowOrg bool
}

func (s *server) aiView(ctx context.Context, r *http.Request, v *auth.Viewer, org store.Org, hostID int64) (aiView, error) {
	runs, err := s.st.AIRuns(ctx, org.ID, hostID, 5)
	if err != nil {
		return aiView{}, err
	}
	view := aiView{View: ai.ViewOf(runs, s.now(), s.cfg.AI.Stale()), Org: org, CanRun: v.Scope.CanOperate(org.ID),
		CSRF: auth.CSRFToken(v.SessionToken), Notice: aiNotices[r.URL.Query().Get("ai")]}
	if view.Result != nil {
		rep, err := report.Build(ctx, s.st, report.Filter{Org: org.Slug, Scope: v.Scope, CountsOnly: true}, s.now())
		if err != nil {
			return aiView{}, err
		}
		view.Links = newAILinker(org.Slug, rep.Hosts)
	}
	if view.Running && view.Notice == aiNotices["started"] {
		view.Notice = "" // the running line says it
	}
	if !view.View.At.IsZero() {
		t := view.View.At
		view.At = &t
	}
	if !view.View.ErrorAt.IsZero() {
		t := view.View.ErrorAt
		view.ErrorAt = &t
	}
	return view, nil
}

// aiBriefsFor builds the dashboard card: the selected org's brief, or one
// per org the viewer can see. nil when AI is off.
func (s *server) aiBriefsFor(r *http.Request, v *auth.Viewer, org string, orgs []store.Org) (*aiBriefs, error) {
	if s.cfg.AI == nil {
		return nil, nil
	}
	out := &aiBriefs{}
	for _, o := range orgs {
		if (org != "" && o.Slug != org) || !v.Scope.CanView(o.ID) {
			continue
		}
		view, err := s.aiView(r.Context(), r, v, o, 0)
		if err != nil {
			return nil, err
		}
		view.Action = "/ai/brief/" + url.PathEscape(o.Slug)
		out.Briefs = append(out.Briefs, view)
	}
	out.ShowOrg = len(out.Briefs) > 1
	if len(out.Briefs) == 0 {
		return nil, nil
	}
	return out, nil
}

// aiHostFor builds the host page's triage card. nil when AI is off.
func (s *server) aiHostFor(r *http.Request, v *auth.Viewer, host store.IngestHost) (*aiView, error) {
	if s.cfg.AI == nil {
		return nil, nil
	}
	org, err := s.orgByID(r.Context(), host.OrgID)
	if err != nil {
		return nil, err
	}
	view, err := s.aiView(r.Context(), r, v, org, host.ID)
	if err != nil {
		return nil, err
	}
	view.Host = host.Name
	view.Action = "/hosts/" + url.PathEscape(host.OrgSlug) + "/" + url.PathEscape(host.Name) + "/ai"
	return &view, nil
}

func (s *server) orgByID(ctx context.Context, id int64) (store.Org, error) {
	orgs, err := s.st.ListOrgs(ctx)
	if err != nil {
		return store.Org{}, err
	}
	for _, o := range orgs {
		if o.ID == id {
			return o, nil
		}
	}
	return store.Org{}, store.ErrNotFound
}

func aiNoticeFor(err error) string {
	switch {
	case err == nil:
		return "started"
	case errors.Is(err, store.ErrAIBusy):
		return "busy"
	case errors.Is(err, store.ErrAITooSoon):
		return "soon"
	}
	return ""
}

// aiBriefRun regenerates an org's brief (operator or admin).
func (s *server) aiBriefRun(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	orgs, err := s.st.ListOrgs(r.Context())
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	var org store.Org
	for _, o := range orgs {
		if o.Slug == r.PathValue("org") && v.Scope.CanView(o.ID) {
			org = o
		}
	}
	if org.ID == 0 {
		s.notFound(w, r, v)
		return
	}
	notice := "denied"
	if v.Scope.CanOperate(org.ID) {
		err := s.cfg.AI.StartBrief(r.Context(), actorOf(v), org)
		if notice = aiNoticeFor(err); notice == "" {
			s.fail(w, r, v, err)
			return
		}
	}
	http.Redirect(w, r, "/?ai="+notice+"#ai-brief-"+url.PathEscape(org.Slug), http.StatusSeeOther)
}

// aiHostRun starts "explain this host" (operator or admin).
func (s *server) aiHostRun(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	host, err := s.st.HostByName(r.Context(), r.PathValue("org"), r.PathValue("host"))
	var verr *store.ValidationError
	if errors.Is(err, store.ErrNotFound) || errors.As(err, &verr) || (err == nil && !v.Scope.CanView(host.OrgID)) {
		s.notFound(w, r, v)
		return
	}
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	notice := "denied"
	if v.Scope.CanOperate(host.OrgID) {
		org, err := s.orgByID(r.Context(), host.OrgID)
		if err == nil {
			err = s.cfg.AI.StartHost(r.Context(), actorOf(v), org, host)
		}
		if notice = aiNoticeFor(err); notice == "" {
			s.fail(w, r, v, err)
			return
		}
	}
	http.Redirect(w, r, "/hosts/"+url.PathEscape(host.OrgSlug)+"/"+url.PathEscape(host.Name)+"?ai="+notice+"#ai-triage", http.StatusSeeOther)
}
