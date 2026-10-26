// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"strconv"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

type anomaliesBody struct {
	Items []anomalyItem
	Rules []string
	Error string
}

type anomalyItem struct {
	store.AnomalyView
	CanOperate bool
}

func (s *server) anomaliesPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	s.renderAnomalies(w, r, v, http.StatusOK, "")
}

func (s *server) renderAnomalies(w http.ResponseWriter, r *http.Request, v *auth.Viewer, status int, errMsg string) {
	list, err := s.st.OpenAnomalies(r.Context(), v.Scope)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := anomaliesBody{Rules: store.AnomalyRules, Error: errMsg}
	for _, a := range list {
		body.Items = append(body.Items, anomalyItem{AnomalyView: a, CanOperate: v.Scope.CanOperate(a.Host.OrgID)})
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
	http.Redirect(w, r, "/anomalies", http.StatusSeeOther)
}
