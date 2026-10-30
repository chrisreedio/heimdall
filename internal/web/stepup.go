// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

// Step-up codes (docs/mobile.md): an admin setting on /admin/security
// says whether actions need the user to have proved it's them in the last
// five minutes (auth.StepUpWindow), not just a session: never (the
// default), for admin actions, or for every action that changes
// something on the ban and anomaly pages too. When one is needed and the
// session isn't fresh, the POST isn't carried out: a small page asks for
// the code (or, for SSO users, a Microsoft sign-in) with the form's fields
// kept, and confirming carries it out. app.js asks in a dialog instead
// before the form is sent, so file uploads keep their file.

const (
	settingStepUp = "stepup"
	stepUpOff     = "off"
	stepUpAdmin   = "admin"
	stepUpEvery   = "every"
	// stepUpField carries the code, from the prompt page or app.js.
	stepUpField = "stepup_code"
)

// The actions step-up covers, by path prefix: every admin POST, and with
// "every", ban and anomaly actions.
var (
	adminStepPaths = []string{"/admin/", "/cloudflare/lists"}
	everyStepPaths = []string{"/bans/", "/anomalies/"}
)

func hasPrefix(path string, prefixes []string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(path, p) })
}

// settingsCache holds the hub settings in memory: step-up is checked on
// every covered POST. Only this process writes them.
type settingsCache struct {
	mu sync.Mutex
	m  map[string]string
}

// setting returns a hub setting, or def when it was never set or can't be
// read.
func (s *server) setting(r *http.Request, key, def string) string {
	s.settings.mu.Lock()
	defer s.settings.mu.Unlock()
	if v, ok := s.settings.m[key]; ok {
		return v
	}
	v, ok, err := s.st.Setting(r.Context(), key)
	if err != nil {
		s.log.Error("settings: load failed", "key", key, "err", err)
		return def
	}
	if !ok {
		v = def
	}
	if s.settings.m == nil {
		s.settings.m = map[string]string{}
	}
	s.settings.m[key] = v
	return v
}

func (s *server) stepUpMode(r *http.Request) string { return s.setting(r, settingStepUp, stepUpOff) }

// stepUpPaths are the path prefixes whose POSTs need a step-up from v now
// (none when the session is fresh). Roles narrow them: a non-admin's
// admin POSTs end in "not found" anyway, so they aren't asked first.
func (s *server) stepUpPaths(r *http.Request, v *auth.Viewer) []string {
	mode := s.stepUpMode(r)
	if mode == stepUpOff || v.Fresh(s.now()) {
		return nil
	}
	var out []string
	if v.IsAdmin {
		out = append(out, adminStepPaths...)
	}
	if mode == stepUpEvery && canOperateAny(v) {
		out = append(out, everyStepPaths...)
	}
	return out
}

// stepUpDialog is the layout's data-stepup: the paths app.js asks a code
// for before a form is sent. SSO users have no code; the server sends
// them through Microsoft instead.
func (s *server) stepUpDialog(r *http.Request, v *auth.Viewer) string {
	if v == nil || v.Kind == "entra" {
		return ""
	}
	return strings.Join(s.stepUpPaths(r, v), " ")
}

// stepUp runs in requireAuth after the CSRF check. It returns true when
// the POST may go ahead: no step-up is needed, or the request carries a
// good code. Otherwise it has answered with the prompt.
func (s *server) stepUp(w http.ResponseWriter, r *http.Request, v *auth.Viewer) bool {
	if !hasPrefix(r.URL.Path, s.stepUpPaths(r, v)) {
		return true
	}
	if v.Kind == "entra" {
		s.stepUpPrompt(w, r, v, "")
		return false
	}
	code := r.PostForm.Get(stepUpField)
	if code == "" {
		s.stepUpPrompt(w, r, v, "")
		return false
	}
	switch err := s.auth.StepUp(r.Context(), v, code, clientIP(r)); {
	case err == nil:
		v.SteppedUpAt = s.now()
		return true
	case errors.Is(err, auth.ErrBadCode), errors.Is(err, auth.ErrThrottled):
		msg := err.Error()
		s.stepUpPrompt(w, r, v, strings.ToUpper(msg[:1])+msg[1:]+".")
	default:
		s.fail(w, r, v, err)
	}
	return false
}

type formField struct{ Name, Value string }

type stepUpBody struct {
	What    string      // "Approving a ban"
	Action  string      // where the form goes
	Fields  []formField // the original form's, without the CSRF token and code
	SSO     bool        // sign in with Microsoft again instead of a code
	Pending string      // SSO: the pending action
	Upload  bool        // the form had a file, which can't be carried
	Back    string      // Cancel, and where an upload's prompt returns to
	Error   string
}

// stepUpPrompt answers a POST that needs a step-up with the prompt.
func (s *server) stepUpPrompt(w http.ResponseWriter, r *http.Request, v *auth.Viewer, errMsg string) {
	body := stepUpBody{What: stepUpWhat(r.URL.Path), Action: r.URL.Path, Back: s.backPath(r), Error: errMsg,
		Upload: r.MultipartForm != nil && len(r.MultipartForm.File) > 0, SSO: v.Kind == "entra"}
	keys := make([]string, 0, len(r.PostForm))
	for k := range r.PostForm {
		if k != csrfField && k != stepUpField {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		for _, val := range r.PostForm[k] {
			body.Fields = append(body.Fields, formField{k, val})
		}
	}
	if body.Upload { // the file can't come along: confirm, then go back to choose it again
		body.Action, body.Fields = "/stepup", []formField{{"next", body.Back}}
	}
	if body.SSO {
		if s.cfg.SSO == nil {
			body.Error = "Single sign-on is off on this hub, so this can't be confirmed. Ask an admin to change the step-up setting."
		} else {
			p := pendingStepUp{viewer: *v, back: body.Back, at: s.now()}
			if !body.Upload {
				p.path, p.form = r.URL.Path, url.Values{}
				for _, f := range body.Fields {
					p.form.Add(f.Name, f.Value)
				}
			}
			body.Pending = s.stepups.add(p)
		}
	}
	s.render(w, r, http.StatusUnauthorized, "stepup", v, "Confirm it's you", backNav(body.Back), body)
}

// stepUpWhat names the action for the prompt.
func stepUpWhat(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	last := parts[len(parts)-1]
	switch parts[0] {
	case "bans":
		switch last {
		case "approve":
			return "Approving a ban"
		case "reject":
			return "Dismissing a ban proposal"
		case "unban":
			return "Lifting a ban"
		case "pause", "resume":
			return "Pausing or resuming Cloudflare writes"
		case "zones":
			return "Changing a zone's ban rule"
		}
	case "anomalies":
		switch last {
		case "ack":
			return "Acknowledging an anomaly"
		case "suppress":
			return "Muting a signal"
		case "bulk":
			return "Triaging anomalies"
		}
	}
	return "This admin change"
}

// backPath is the page the form was on, from the Referer (same origin
// only), for Cancel.
func (s *server) backPath(r *http.Request) string {
	ref, err := url.Parse(r.Header.Get("Referer"))
	if err != nil || !slices.Contains(loopbackAliases(s.origin), ref.Scheme+"://"+ref.Host) {
		return "/"
	}
	return safeNext(ref.RequestURI())
}

// backNav is the prompt's nav item: the page the form was on, so the
// phone's tab bar stays on its tab.
func backNav(back string) string {
	page, _, _ := strings.Cut(strings.TrimPrefix(back, "/"), "?")
	page, _, _ = strings.Cut(page, "/")
	if _, ok := tabs[page]; ok {
		return page
	}
	return ""
}

// stepUpSubmit is POST /stepup: a code on its own, from an upload's
// prompt. It goes back to the page the form was on.
func (s *server) stepUpSubmit(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	next := safeNext(r.PostForm.Get("next"))
	if v.Kind == "entra" {
		s.notFound(w, r, v)
		return
	}
	switch err := s.auth.StepUp(r.Context(), v, r.PostForm.Get(stepUpField), clientIP(r)); {
	case err == nil:
		http.Redirect(w, r, next, http.StatusSeeOther)
	case errors.Is(err, auth.ErrBadCode), errors.Is(err, auth.ErrThrottled):
		msg := err.Error()
		s.render(w, r, http.StatusUnauthorized, "stepup", v, "Confirm it's you", "", stepUpBody{What: "Uploading a file",
			Action: "/stepup", Fields: []formField{{"next", next}}, Upload: true, Back: next,
			Error: strings.ToUpper(msg[:1]) + msg[1:] + "."})
	default:
		s.fail(w, r, v, err)
	}
}

// ── SSO users: a Microsoft sign-in with prompt=login ──────────────────────

// pendingStepUp is an action waiting for an SSO user's step-up: the form
// to send again once they're back, and whose session it is.
type pendingStepUp struct {
	viewer auth.Viewer
	path   string     // "" for an upload: go back instead
	form   url.Values // without the CSRF token, which is added again
	back   string
	at     time.Time
	state  [32]byte // the sign-in's state hash, once started
	done   bool     // Microsoft confirmed it was them
	err    string   // or why not
}

// stepUpPending bounds the waiting actions; they're kept for
// ssoRequestTTL, in memory (a restart asks again).
const stepUpPending = 1000

type stepUpStore struct {
	mu   sync.Mutex
	byID map[string]*pendingStepUp
}

func (st *stepUpStore) add(p pendingStepUp) string {
	b := make([]byte, 18)
	rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.byID == nil {
		st.byID = map[string]*pendingStepUp{}
	}
	for k, q := range st.byID {
		if p.at.Sub(q.at) > ssoRequestTTL {
			delete(st.byID, k)
		}
	}
	if len(st.byID) >= stepUpPending {
		return ""
	}
	st.byID[id] = &p
	return id
}

// get returns v's pending action by ID: the same user and session.
func (st *stepUpStore) get(id string, v *auth.Viewer) *pendingStepUp {
	st.mu.Lock()
	defer st.mu.Unlock()
	p := st.byID[id]
	if p == nil || p.viewer.UserID != v.UserID || p.viewer.SessionToken != v.SessionToken {
		return nil
	}
	return p
}

// byState finds the pending action a sign-in's callback is for.
func (st *stepUpStore) byState(hash [32]byte) (string, *pendingStepUp) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for id, p := range st.byID {
		if p.state == hash {
			return id, p
		}
	}
	return "", nil
}

func (st *stepUpStore) finish(id, errMsg string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if p := st.byID[id]; p != nil {
		p.done, p.err, p.state = errMsg == "", errMsg, [32]byte{}
	}
}

func (st *stepUpStore) remove(id string) {
	st.mu.Lock()
	delete(st.byID, id)
	st.mu.Unlock()
}

// stepUpSSO is POST /stepup/sso: send an SSO user to Microsoft to sign in
// again, coming back to /stepup/done.
func (s *server) stepUpSSO(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	id := r.PostForm.Get("p")
	p := s.stepups.get(id, v)
	if s.cfg.SSO == nil || p == nil {
		s.notFound(w, r, v)
		return
	}
	req, err := s.cfg.SSO.BeginReauth(r.Context())
	if err != nil {
		s.log.Warn("sso: step-up begin failed", "err", err)
		s.render(w, r, http.StatusBadGateway, "stepup", v, "Confirm it's you", backNav(p.back), stepUpBody{What: stepUpWhat(p.path),
			SSO: true, Pending: id, Back: p.back, Error: msgSSODown})
		return
	}
	hash := sha256.Sum256([]byte(req.State))
	if err := s.st.PutAuthRequest(r.Context(), hash, store.AuthRequest{Nonce: req.Nonce, Verifier: req.Verifier,
		ReturnTo: "/stepup/done?p=" + id, CreatedAt: s.now()}); err != nil {
		s.fail(w, r, v, err)
		return
	}
	s.stepups.mu.Lock()
	p.state, p.done, p.err = hash, false, ""
	s.stepups.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, req.URL, http.StatusSeeOther)
}

// stepUpCallback finishes a step-up sign-in (from ssoCallback, which has
// taken the auth request): the identity must be the session's user. The
// session cookie doesn't come with Microsoft's cross-site redirect, so
// it's recorded on the session the pending action names, and a same-site
// hand-off page goes on to /stepup/done.
func (s *server) stepUpCallback(w http.ResponseWriter, r *http.Request, id string, p *pendingStepUp, code, verifier, nonce string) {
	errMsg := msgSSOFailed
	if code != "" {
		ident, err := s.cfg.SSO.Finish(r.Context(), code, verifier, nonce)
		if err == nil {
			err = s.auth.StepUpIdentity(r.Context(), &p.viewer, store.EntraIdentity{TenantID: ident.TenantID,
				ObjectID: ident.ObjectID, Email: ident.Email, Name: ident.Name}, clientIP(r))
		}
		switch {
		case err == nil:
			errMsg = ""
		case errors.Is(err, auth.ErrWrongAccount):
			errMsg = "That was a different Microsoft account from the one signed in here. Sign in as " + p.viewer.Email + "."
		default:
			s.log.Warn("sso: step-up rejected", "err", err)
		}
	}
	s.stepups.finish(id, errMsg)
	next := "/stepup/done?p=" + id
	s.renderPage(w, r, http.StatusOK, "signedin", page{Title: "Confirmed", Refresh: next, Body: next})
}

type stepUpResume struct {
	Action string
	Fields []formField
	What   string
}

// stepUpDone is where an SSO step-up comes back: it sends the waiting
// form again (app.js submits it; a button does without JavaScript).
func (s *server) stepUpDone(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	id := r.URL.Query().Get("p")
	p := s.stepups.get(id, v)
	if p == nil {
		s.notFound(w, r, v)
		return
	}
	s.stepups.mu.Lock()
	done, errMsg := p.done, p.err
	s.stepups.mu.Unlock()
	if !done {
		if errMsg == "" {
			errMsg = msgSSOFailed
		}
		s.render(w, r, http.StatusUnauthorized, "stepup", v, "Confirm it's you", backNav(p.back), stepUpBody{What: stepUpWhat(p.path),
			SSO: true, Pending: id, Back: p.back, Error: errMsg})
		return
	}
	s.stepups.remove(id)
	if p.path == "" {
		http.Redirect(w, r, p.back, http.StatusSeeOther)
		return
	}
	body := stepUpResume{Action: p.path, What: stepUpWhat(p.path)}
	keys := make([]string, 0, len(p.form))
	for k := range p.form {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		for _, val := range p.form[k] {
			body.Fields = append(body.Fields, formField{k, val})
		}
	}
	s.render(w, r, http.StatusOK, "stepup_resume", v, "Confirmed", "", body)
}

// ── The setting ───────────────────────────────────────────────────────────

type securityBody struct {
	StepUp string
	Fresh  bool      // the viewer's session is fresh now
	Last   time.Time // when they last stepped up
	Notice string
}

func (s *server) securityPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	body := securityBody{StepUp: s.stepUpMode(r), Fresh: v.Fresh(s.now()), Last: v.SteppedUpAt}
	if r.URL.Query().Get("ok") == "stepup" {
		body.Notice = "Saved."
	}
	s.render(w, r, http.StatusOK, "security", v, "Security", "security", body)
}

// securityAction saves the step-up setting. Changing it is an admin
// action, so once it's on, changing it again needs a fresh code.
func (s *server) securityAction(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	mode := r.PostForm.Get("stepup")
	if !slices.Contains([]string{stepUpOff, stepUpAdmin, stepUpEvery}, mode) {
		http.Error(w, "unknown step-up setting", http.StatusBadRequest)
		return
	}
	if err := s.st.SetSetting(r.Context(), actorOf(v), settingStepUp, mode, s.now()); err != nil {
		s.fail(w, r, v, err)
		return
	}
	s.settings.mu.Lock()
	delete(s.settings.m, settingStepUp)
	s.settings.mu.Unlock()
	http.Redirect(w, r, "/admin/security?ok=stepup", http.StatusSeeOther)
}
