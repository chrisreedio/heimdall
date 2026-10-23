// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/store"
)

type plansBody struct {
	Plans      []store.Plan
	Orgs       []store.Org // orgs the viewer can create plans in
	CanAllOrgs bool
	Error      string
}

type planBody struct {
	Plan       store.Plan
	Items      []store.PlanItem
	Candidates []store.Host // visible hosts not yet in the plan
	CanOperate bool         // and the plan is open
	CanReopen  bool
	Error      string
}

func (s *server) plansPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	s.renderPlans(w, r, v, http.StatusOK, "")
}

func (s *server) renderPlans(w http.ResponseWriter, r *http.Request, v *auth.Viewer, status int, errMsg string) {
	plans, err := s.st.ListPlans(r.Context(), v.Scope)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	orgs, err := s.st.ListOrgs(r.Context())
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := plansBody{Plans: plans, CanAllOrgs: v.Scope.Admin, Error: errMsg}
	for _, o := range orgs {
		if v.Scope.CanOperate(o.ID) {
			body.Orgs = append(body.Orgs, o)
		}
	}
	s.render(w, r, status, "plans", v, "Patch plans", "plans", body)
}

func (s *server) planCreate(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	org := strings.TrimSpace(r.PostForm.Get("org"))
	if org != "" {
		host, err := s.orgBySlug(r, org)
		if err != nil || !v.Scope.CanOperate(host.ID) {
			s.renderPlans(w, r, v, http.StatusForbidden, "You can't create plans in that org.")
			return
		}
	} else if !v.Scope.Admin {
		s.renderPlans(w, r, v, http.StatusForbidden, "Only admins can create fleet-wide plans.")
		return
	}
	p, err := s.st.CreatePlan(r.Context(), actorOf(v), v.UserID, org, r.PostForm.Get("name"))
	if err != nil {
		s.renderPlans(w, r, v, http.StatusBadRequest, userError(err))
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/plans/%d", p.ID), http.StatusSeeOther)
}

// plan loads a plan the viewer can see, or responds 404.
func (s *server) plan(w http.ResponseWriter, r *http.Request, v *auth.Viewer) (store.Plan, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		p, err := s.st.PlanByID(r.Context(), id)
		if err == nil && v.Scope.CanViewPlan(p) {
			return p, true
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, v, err)
			return store.Plan{}, false
		}
	}
	s.notFound(w, r, v)
	return store.Plan{}, false
}

func (s *server) planPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if p, ok := s.plan(w, r, v); ok {
		s.renderPlan(w, r, v, p, http.StatusOK, "")
	}
}

func (s *server) renderPlan(w http.ResponseWriter, r *http.Request, v *auth.Viewer, p store.Plan, status int, errMsg string) {
	items, err := s.st.PlanItems(r.Context(), p.ID)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	in := map[int64]bool{}
	for _, it := range items {
		in[it.Host.ID] = true
	}
	hosts, err := s.visibleHosts(r, v, p.OrgSlug)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := planBody{Plan: p, Items: items, Error: errMsg,
		CanOperate: v.Scope.CanOperatePlan(p) && p.ClosedAt.IsZero(),
		CanReopen:  v.Scope.CanOperatePlan(p) && !p.ClosedAt.IsZero()}
	for _, h := range hosts {
		if !in[h.ID] {
			body.Candidates = append(body.Candidates, h)
		}
	}
	s.render(w, r, status, "plan", v, p.Name, "plans", body)
}

// planAction handles add, remove, done, undo and close.
func (s *server) planAction(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	p, ok := s.plan(w, r, v)
	if !ok {
		return
	}
	if !v.Scope.CanOperatePlan(p) {
		s.renderPlan(w, r, v, p, http.StatusForbidden, "You need the operator role to change this plan.")
		return
	}
	ctx, actor := r.Context(), actorOf(v)
	var err error
	if action := r.PathValue("action"); action == "close" || action == "reopen" {
		err = s.st.ClosePlan(ctx, actor, p.ID, action == "close", s.now())
	} else {
		org, name := r.PostForm.Get("org"), r.PostForm.Get("host")
		if ref := r.PostForm.Get("hostref"); ref != "" { // the add form's "org/host" select
			org, name, _ = strings.Cut(ref, "/")
		}
		var host store.IngestHost
		host, err = s.st.HostByName(ctx, org, name)
		if err == nil && !v.Scope.CanOperate(host.OrgID) {
			err = store.ErrNotFound
		}
		if err == nil {
			switch action {
			case "add":
				batch, _ := strconv.Atoi(r.PostForm.Get("batch"))
				err = s.st.AddToPlan(ctx, actor, p.ID, host, max(batch, 1))
			case "remove":
				err = s.st.RemoveFromPlan(ctx, actor, p.ID, host)
			case "done", "undo":
				err = s.st.SetPlanItemDone(ctx, actor, v.UserID, p.ID, host, action == "done", s.now())
			default:
				s.notFound(w, r, v)
				return
			}
		}
	}
	if err != nil {
		p, _ = s.st.PlanByID(ctx, p.ID)
		s.renderPlan(w, r, v, p, http.StatusBadRequest, userError(err))
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/plans/%d", p.ID), http.StatusSeeOther)
}

func (s *server) orgBySlug(r *http.Request, slug string) (store.Org, error) {
	orgs, err := s.st.ListOrgs(r.Context())
	if err != nil {
		return store.Org{}, err
	}
	for _, o := range orgs {
		if o.Slug == slug {
			return o, nil
		}
	}
	return store.Org{}, store.ErrNotFound
}

func actorOf(v *auth.Viewer) string { return fmt.Sprintf("user:%d", v.UserID) }

// userError shows validation and not-found errors; anything else is generic.
func userError(err error) string {
	var ve *store.ValidationError
	switch {
	case errors.As(err, &ve):
		return ve.Error()
	case errors.Is(err, store.ErrNotFound):
		return "Not found."
	case strings.Contains(err.Error(), "is closed"):
		return "This plan is closed."
	}
	return "Something went wrong; see the server log."
}
