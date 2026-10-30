// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/auth/entra"
	"github.com/realmwatch/heimdall/internal/store"
)

// ssoRequestTTL bounds how long a user may spend at Microsoft's sign-in.
const ssoRequestTTL = 10 * time.Minute

// Fixed messages: nothing from the identity provider is shown verbatim.
const (
	msgSSOExpired = "Sign-in expired, try again."
	msgSSOFailed  = "Sign-in failed. Try again, or ask an admin to check the server log."
	msgSSODown    = "Single sign-on is unavailable right now. Try again shortly."
)

// ssoLogin starts an Entra ID sign-in. The state, nonce and PKCE verifier
// stay server-side (only the state's hash is stored, and it's single use).
func (s *server) ssoLogin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.SSO == nil {
		s.notFound(w, r, nil)
		return
	}
	next := safeNext(r.URL.Query().Get("next"))
	req, err := s.cfg.SSO.Begin(r.Context())
	if err != nil {
		s.log.Warn("sso: begin failed", "err", err)
		s.loginError(w, r, http.StatusBadGateway, next, msgSSODown)
		return
	}
	err = s.st.PutAuthRequest(r.Context(), sha256.Sum256([]byte(req.State)), store.AuthRequest{
		Nonce: req.Nonce, Verifier: req.Verifier, ReturnTo: next, Keep: r.URL.Query().Get("keep") == "on", CreatedAt: s.now(),
	})
	if err != nil {
		s.fail(w, r, nil, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, req.URL, http.StatusSeeOther)
}

// ssoCallback finishes a sign-in. Microsoft redirects here cross-site, so
// a SameSite=Strict cookie set now wouldn't accompany a further redirect;
// instead a small same-site page hands off with a meta refresh.
func (s *server) ssoCallback(w http.ResponseWriter, r *http.Request) {
	if s.cfg.SSO == nil {
		s.notFound(w, r, nil)
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" || len(state) > 512 {
		s.loginError(w, r, http.StatusBadRequest, "/", msgSSOExpired)
		return
	}
	// Taking the request consumes it, so a state can never be reused, even
	// when the rest of the callback fails.
	req, err := s.st.TakeAuthRequest(ctx, sha256.Sum256([]byte(state)), s.now(), ssoRequestTTL)
	if errors.Is(err, store.ErrNotFound) {
		s.loginError(w, r, http.StatusBadRequest, "/", msgSSOExpired)
		return
	}
	if err != nil {
		s.fail(w, r, nil, err)
		return
	}
	next := safeNext(req.ReturnTo)

	if e := q.Get("error"); e != "" {
		desc := q.Get("error_description")
		var codes []int
		aadsts := ""
		if c := entra.DescriptionCode(desc); c != 0 {
			codes, aadsts = []int{c}, "AADSTS"+strconv.Itoa(c)
		}
		s.log.Warn("sso: identity provider returned an error", "error", truncate(e, 100),
			"error_codes", aadsts, "description", truncate(desc, 300))
		s.loginError(w, r, http.StatusUnauthorized, next, ssoFailedMessage(codes))
		return
	}
	code := q.Get("code")
	if code == "" || len(code) > 4096 {
		s.loginError(w, r, http.StatusBadRequest, next, msgSSOFailed)
		return
	}
	id, err := s.cfg.SSO.Finish(ctx, code, req.Verifier, req.Nonce)
	if err != nil {
		// entra errors never include the secret, tokens or codes. A failed
		// code exchange says why in the log, for whoever set up the app
		// registration; the person signing in sees ssoFailedMessage.
		var te *entra.TokenError
		msg := msgSSOFailed
		if errors.As(err, &te) {
			s.log.Warn("sso: sign-in rejected: token exchange failed", "status", te.Status, "error", te.Code,
				"error_codes", te.AADSTS(), "description", te.Description, "hint", te.Hint)
			msg = ssoFailedMessage(te.Codes)
		} else {
			s.log.Warn("sso: sign-in rejected", "err", err)
		}
		s.loginError(w, r, http.StatusUnauthorized, next, msg)
		return
	}
	token, err := s.auth.LoginIdentity(ctx, store.EntraIdentity{
		TenantID: id.TenantID, ObjectID: id.ObjectID, Email: id.Email, Name: id.Name,
	}, id.Roles, clientIP(r), r.UserAgent(), req.Keep)
	if errors.Is(err, auth.ErrNotProvisioned) {
		s.loginError(w, r, http.StatusForbidden, next, auth.ErrNotProvisioned.Error())
		return
	}
	if err != nil {
		s.log.Error("sso: session creation failed", "err", err)
		s.loginError(w, r, http.StatusInternalServerError, next, msgSSOFailed)
		return
	}
	s.noteTailscaleUser(r, token) // tsproxy.go
	s.setSession(w, token, s.sessionAge(req.Keep))
	s.renderPage(w, r, http.StatusOK, "signedin", page{Title: "Signed in", Refresh: next, Body: next})
}

// ssoFailedMessage is the sign-in failure shown for Microsoft's AADSTS
// codes: a fixed message for the ones Heimdall knows, the generic one
// otherwise, and the code so it can be passed on. Never Microsoft's text.
func ssoFailedMessage(codes []int) string {
	msg, code := entra.SignInMessage(codes)
	if msg == "" {
		msg = msgSSOFailed
	}
	if code != 0 {
		msg += " Error AADSTS" + strconv.Itoa(code) + "."
	}
	return msg
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
