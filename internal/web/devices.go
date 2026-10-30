// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

// Devices: the signed-in user's sessions, one per browser or installed
// app, with the one in use marked, and Revoke for each. Admins see and
// revoke anyone's on the Users page. Revoking deletes the session, so its
// next request is signed out.

type deviceRow struct {
	store.SessionInfo
	Current bool          // the session this page was loaded with
	Until   template.HTML // when it ends unless used again (kept) or at the latest
}

type devicesBody struct {
	Devices []deviceRow
	Idle    string // ui.session_idle, in words
	Notice  string
	Error   string
}

var deviceNotices = map[string]string{"revoked": "Signed out on that device."}

func (s *server) devicesPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	rows, err := s.liveSessions(r, v, v.UserID)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := devicesBody{Devices: rows, Idle: idleText(s.cfg.SessionIdle), Notice: deviceNotices[r.URL.Query().Get("ok")]}
	s.render(w, r, http.StatusOK, "devices", v, "Devices", "devices", body)
}

// liveSessions lists a user's sessions that can still be used: before
// their expiry and, for normal sessions, not idle past ui.session_idle.
func (s *server) liveSessions(r *http.Request, v *auth.Viewer, userID int64) ([]deviceRow, error) {
	now := s.now()
	all, err := s.st.UserSessions(r.Context(), userID, now)
	if err != nil {
		return nil, err
	}
	current := store.SessionRef(sha256.Sum256([]byte(v.SessionToken)))
	var rows []deviceRow
	for _, si := range all {
		if !si.Kept && s.cfg.SessionIdle > 0 && now.Sub(si.LastSeenAt) > s.cfg.SessionIdle {
			continue
		}
		rows = append(rows, deviceRow{SessionInfo: si, Current: userID == v.UserID && si.Ref == current,
			Until: expiresIn(si.ExpiresAt, now)})
	}
	return rows, nil
}

// deviceRevoke ends one of the viewer's own sessions. Revoking the one in
// use signs out here too.
func (s *server) deviceRevoke(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ref := r.PostForm.Get("ref")
	err := s.st.RevokeSession(r.Context(), fmt.Sprintf("user:%d", v.UserID), v.UserID, ref, clientIP(r))
	if errors.Is(err, store.ErrNotFound) {
		http.Redirect(w, r, "/account/devices", http.StatusSeeOther) // already gone
		return
	}
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if ref == store.SessionRef(sha256.Sum256([]byte(v.SessionToken))) {
		s.setSession(w, "", -1)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/account/devices?ok=revoked", http.StatusSeeOther)
}

// adminSessionRevoke ends any user's session from the Users page.
func (s *server) adminSessionRevoke(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	uid, err := strconv.ParseInt(r.PostForm.Get("user"), 10, 64)
	if err != nil || uid <= 0 {
		s.renderAdmin(w, r, v, http.StatusBadRequest, "", "missing or bad user ID")
		return
	}
	err = s.st.RevokeSession(r.Context(), fmt.Sprintf("user:%d", v.UserID), uid, r.PostForm.Get("ref"), clientIP(r))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, v, err)
		return
	}
	if uid == v.UserID && r.PostForm.Get("ref") == store.SessionRef(sha256.Sum256([]byte(v.SessionToken))) {
		s.setSession(w, "", -1)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/users?ok=session-revoked", http.StatusSeeOther)
}

// idleText is a session idle limit in words: "30 minutes", "2 hours".
func idleText(d time.Duration) string {
	if d >= time.Hour && d%time.Hour == 0 {
		return plural(int(d.Hours()), "hour", "hours")
	}
	return plural(int(d.Minutes()), "minute", "minutes")
}
