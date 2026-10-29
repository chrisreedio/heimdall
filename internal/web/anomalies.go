// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

type anomaliesBody struct {
	Items  []anomalyItem
	Closed []store.ClosedAnomaly // the last 30 days', auto-resolved ones marked
	Rules  []string
	Error  string
	Notice string
	// CanBulk: some listed anomaly can be triaged, so the page shows the
	// select-several form.
	CanBulk bool
	MaxBulk int
}

type anomalyItem struct {
	store.AnomalyView
	CanOperate bool
}

func (s *server) anomaliesPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	s.renderAnomaliesNotice(w, r, v, http.StatusOK, bulkNotice(r.URL.Query()), "")
}

func (s *server) renderAnomalies(w http.ResponseWriter, r *http.Request, v *auth.Viewer, status int, errMsg string) {
	s.renderAnomaliesNotice(w, r, v, status, "", errMsg)
}

func (s *server) renderAnomaliesNotice(w http.ResponseWriter, r *http.Request, v *auth.Viewer, status int, notice, errMsg string) {
	list, err := s.st.OpenAnomalies(r.Context(), v.Scope)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := anomaliesBody{Rules: store.AnomalyRules, Error: errMsg, Notice: notice, MaxBulk: maxBulkAnomalies}
	for _, a := range list {
		it := anomalyItem{AnomalyView: a, CanOperate: v.Scope.CanOperate(a.Host.OrgID)}
		body.CanBulk = body.CanBulk || it.CanOperate
		body.Items = append(body.Items, it)
	}
	if body.Closed, err = s.st.ClosedAnomalies(r.Context(), v.Scope, s.now().Add(-30*24*time.Hour), 100); err != nil {
		s.fail(w, r, v, err)
		return
	}
	s.render(w, r, status, "anomalies", v, "Anomalies", "anomalies", body)
}

// anomalyAction handles ack (with a note) and suppress (mute the rule on
// that host for N days). Both need the operator role in the host's org.
func (s *server) anomalyAction(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	host, err := s.st.AnomalyHost(r.Context(), id)
	if err != nil || !v.Scope.CanView(host.OrgID) {
		s.notFound(w, r, v)
		return
	}
	if !v.Scope.CanOperate(host.OrgID) {
		s.renderAnomalies(w, r, v, http.StatusForbidden, "You need the operator role to triage anomalies.")
		return
	}
	note, now := r.PostForm.Get("note"), s.now()
	switch r.PathValue("action") {
	case "ack":
		err = s.st.AckAnomaly(r.Context(), actorOf(v), v.UserID, id, note, now)
	case "suppress":
		days, _ := strconv.Atoi(r.PostForm.Get("days"))
		err = s.st.Suppress(r.Context(), actorOf(v), v.UserID, host, r.PostForm.Get("rule"),
			now.Add(time.Duration(max(days, 1))*24*time.Hour), note, now)
		if err == nil {
			err = s.st.AckAnomaly(r.Context(), actorOf(v), v.UserID, id, "suppressed: "+note, now)
		}
	default:
		s.notFound(w, r, v)
		return
	}
	if err != nil {
		s.renderAnomalies(w, r, v, http.StatusBadRequest, userError(err))
		return
	}
	s.nav.forget(v.UserID) // its badge counts this anomaly
	http.Redirect(w, r, "/anomalies", http.StatusSeeOther)
}

// maxBulkAnomalies is how many anomalies one bulk action takes.
const maxBulkAnomalies = 500

// bulkNotice is the line a bulk action's redirect asks the page to show.
// Only numbers come from the query string, never text.
func bulkNotice(q url.Values) string {
	n, err := strconv.Atoi(q.Get("n"))
	if err != nil || n < 0 || n > maxBulkAnomalies {
		return ""
	}
	var msg string
	switch q.Get("done") {
	case "ack":
		msg = "Acknowledged " + plural(n, "anomaly", "anomalies") + "."
	case "suppress":
		msg = "Muted and acknowledged " + plural(n, "anomaly", "anomalies") + "."
	default:
		return ""
	}
	if skipped, err := strconv.Atoi(q.Get("skipped")); err == nil && skipped > 0 && skipped <= maxBulkAnomalies {
		msg += fmt.Sprintf(" %s already closed.", plural(skipped, "was", "were"))
	}
	return msg
}

// anomalyBulk acknowledges, or mutes and acknowledges, every anomaly
// ticked on the anomalies page (the form's "id" values) with one note.
// It's all or nothing on access: the operator role is needed in every
// selected anomaly's org, and an id the viewer can't see fails the whole
// request as not found, so nothing is changed.
func (s *server) anomalyBulk(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	var ids []int64
	for _, raw := range r.PostForm["id"] {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id <= 0 {
			s.renderAnomalies(w, r, v, http.StatusBadRequest, "That selection isn't valid; reload the page and try again.")
			return
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
		if len(ids) > maxBulkAnomalies {
			s.renderAnomalies(w, r, v, http.StatusBadRequest,
				fmt.Sprintf("Select at most %d anomalies at a time.", maxBulkAnomalies))
			return
		}
	}
	if len(ids) == 0 {
		s.renderAnomalies(w, r, v, http.StatusBadRequest, "Select the anomalies to triage first.")
		return
	}
	targets, err := s.st.AnomalyTargets(r.Context(), ids)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if len(targets) != len(ids) || slices.ContainsFunc(targets, func(t store.AnomalyTarget) bool { return !v.Scope.CanView(t.Host.OrgID) }) {
		s.notFound(w, r, v)
		return
	}
	if slices.ContainsFunc(targets, func(t store.AnomalyTarget) bool { return !v.Scope.CanOperate(t.Host.OrgID) }) {
		s.renderAnomalies(w, r, v, http.StatusForbidden, "You need the operator role in every selected anomaly's org to triage them.")
		return
	}
	var open []int64
	for _, t := range targets {
		if t.Open {
			open = append(open, t.ID)
		}
	}
	note, now, action := r.PostForm.Get("note"), s.now(), r.PostForm.Get("action")
	ackNote := note
	switch action {
	case "ack":
	case "suppress":
		// Mute each (host, signal) once, then acknowledge, as the
		// single-row Mute does.
		days, _ := strconv.Atoi(r.PostForm.Get("days"))
		type muted struct {
			host int64
			rule string
		}
		done := map[muted]bool{}
		for _, t := range targets {
			if !t.Open || done[muted{t.Host.ID, t.Rule}] {
				continue
			}
			done[muted{t.Host.ID, t.Rule}] = true
			if err := s.st.Suppress(r.Context(), actorOf(v), v.UserID, t.Host, t.Rule,
				now.Add(time.Duration(max(days, 1))*24*time.Hour), note, now); err != nil {
				s.renderAnomalies(w, r, v, http.StatusBadRequest, userError(err))
				return
			}
		}
		ackNote = "suppressed: " + note
	default:
		s.notFound(w, r, v)
		return
	}
	n, err := s.st.AckAnomalies(r.Context(), actorOf(v), v.UserID, open, ackNote, now)
	if err != nil {
		s.renderAnomalies(w, r, v, http.StatusBadRequest, userError(err))
		return
	}
	s.nav.forget(v.UserID)
	q := url.Values{"done": {action}, "n": {strconv.Itoa(n)}}
	if skipped := len(ids) - n; skipped > 0 {
		q.Set("skipped", strconv.Itoa(skipped))
	}
	http.Redirect(w, r, "/anomalies?"+q.Encode(), http.StatusSeeOther)
}
