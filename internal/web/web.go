// SPDX-License-Identifier: AGPL-3.0-or-later

// Package web serves the private web UI: sign-in, dashboard, hosts, host
// pages and fleet search. Pages are server-rendered with html/template;
// there is no inline script or style, so a strict CSP applies everywhere.
package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/auth/entra"
	"github.com/chrisreedio/heimdall/internal/search"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/updates"
)

// Authenticator signs users in and resolves session cookies.
type Authenticator interface {
	Login(ctx context.Context, email, password, code, ip, userAgent string) (token string, err error)
	// LoginIdentity starts a session for an identity SSO has validated.
	// auth.ErrNotProvisioned means the user isn't set up in Heimdall.
	LoginIdentity(ctx context.Context, id store.EntraIdentity, roles []string, ip, userAgent string) (token string, err error)
	Session(ctx context.Context, token string) (*auth.Viewer, error)
	Logout(ctx context.Context, token string) error
}

// SSO is the Entra ID OIDC flow (see internal/auth/entra).
type SSO interface {
	Begin(ctx context.Context) (entra.AuthRequest, error)
	Finish(ctx context.Context, code, verifier, nonce string) (entra.Identity, error)
}

// SearchFunc answers a fleet search. Errors are shown to the user.
type SearchFunc func(ctx context.Context, query string, scope store.Scope) (*search.Result, error)

type Config struct {
	Updates    func() (updates.Release, bool) // newer release for the admin banner; nil = off
	IngestURL  string                         // ingest.public_url, for install commands
	BaseURL    string                         // e.g. https://heimdall.internal or http://127.0.0.1:8080
	StaleAfter time.Duration                  // hosts.stale_after
	Version    string
	SessionMax time.Duration // cookie Max-Age

	SSO          SSO      // nil = single sign-on disabled
	LocalLogin   bool     // password + TOTP sign-in; false hides the form and refuses POST /login
	EntraTenants []string // allowed tenant IDs, offered when an admin adds an Entra user
}

// CSP is the Content-Security-Policy sent with every response.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

const (
	maxFormBytes = 16 << 10
	csrfField    = "csrf"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type server struct {
	cfg        Config
	st         *store.Store
	auth       Authenticator
	search     SearchFunc
	log        *slog.Logger
	now        func() time.Time
	origin     string // scheme://host of BaseURL, compared with Origin/Referer
	secure     bool
	cookieName string
	pages      map[string]*template.Template
}

// New returns the UI handler.
func New(cfg Config, st *store.Store, a Authenticator, search SearchFunc, log *slog.Logger, now func() time.Time) (http.Handler, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("web: invalid base URL %q", cfg.BaseURL)
	}
	s := &server{
		cfg: cfg, st: st, auth: a, search: search, log: log, now: now,
		origin:     u.Scheme + "://" + u.Host,
		secure:     u.Scheme == "https",
		cookieName: "heimdall",
	}
	if s.secure {
		s.cookieName = "__Host-heimdall"
	}
	if s.pages, err = parsePages(); err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /logout", s.requireAuth(s.logout))
	mux.HandleFunc("GET /auth/entra/login", s.ssoLogin)
	mux.HandleFunc("GET /auth/callback", s.ssoCallback)
	mux.HandleFunc("GET /{$}", s.requireAuth(s.withScope(s.dashboard)))
	mux.HandleFunc("GET /hosts", s.requireAuth(s.withScope(s.hostsPage)))
	mux.HandleFunc("GET /hosts/{org}/{host}", s.requireAuth(s.hostPage))
	mux.HandleFunc("GET /sites", s.requireAuth(s.withScope(s.sitesPage)))
	mux.HandleFunc("GET /search", s.requireAuth(s.withScope(s.searchPage)))
	mux.HandleFunc("GET /hosts/new", s.requireAuth(s.addHostPage))
	mux.HandleFunc("POST /hosts/new", s.requireAuth(s.addHostSubmit))
	mux.HandleFunc("GET /hosts/{org}/{host}/changes", s.requireAuth(s.changesPage))
	mux.HandleFunc("GET /anomalies", s.requireAuth(s.anomaliesPage))
	mux.HandleFunc("POST /anomalies/{id}/{action}", s.requireAuth(s.anomalyAction))
	mux.HandleFunc("GET /drift", s.requireAuth(s.withScope(s.driftPage)))
	mux.HandleFunc("GET /plans", s.requireAuth(s.plansPage))
	mux.HandleFunc("POST /plans", s.requireAuth(s.planCreate))
	mux.HandleFunc("GET /plans/{id}", s.requireAuth(s.planPage))
	mux.HandleFunc("POST /plans/{id}/{action}", s.requireAuth(s.planAction))
	mux.HandleFunc("GET /admin/users", s.requireAuth(s.requireAdmin(s.adminUsers)))
	mux.HandleFunc("POST /admin/users/{action}", s.requireAuth(s.requireAdmin(s.adminAction)))
	mux.HandleFunc("GET /static/{file}", s.static)
	mux.HandleFunc("/", s.requireAuth(func(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
		s.notFound(w, r, v)
	}))
	return s.headers(mux), nil
}

func (s *server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", CSP)
		h.Set("X-Content-Type-Options", "nosniff")
		// same-origin, not no-referrer: under no-referrer browsers send
		// "Origin: null" on form POSTs, which the Origin check must refuse.
		// Nothing is sent to other sites either way.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if s.secure {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// viewer resolves the session cookie, if any.
func (s *server) viewer(r *http.Request) (*auth.Viewer, error) {
	c, err := r.Cookie(s.cookieName)
	if err != nil || c.Value == "" {
		return nil, auth.ErrNoSession
	}
	v, err := s.auth.Session(r.Context(), c.Value)
	if err != nil {
		if !errors.Is(err, auth.ErrNoSession) {
			s.log.Error("session lookup failed", "err", err)
		}
		return nil, auth.ErrNoSession
	}
	return v, nil
}

type authedHandler func(http.ResponseWriter, *http.Request, *auth.Viewer)

// requireAuth sends signed-out GETs to the login page, refuses other
// signed-out requests, and checks Origin and CSRF on every POST.
func (s *server) requireAuth(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := s.viewer(r)
		if err != nil {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(safeNext(r.URL.RequestURI())), http.StatusSeeOther)
				return
			}
			s.forbidden(w, r)
			return
		}
		if r.Method == http.MethodPost {
			if !s.sameOrigin(r) || !s.parseForm(w, r) || !auth.ValidCSRF(v.SessionToken, r.PostForm.Get(csrfField)) {
				s.forbidden(w, r)
				return
			}
		}
		h(w, r, v)
	}
}

// withScope shows a "no access yet" page instead of empty tables to users
// who haven't been granted a role anywhere.
func (s *server) withScope(h authedHandler) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
		if v.Scope.Empty() {
			s.render(w, r, http.StatusOK, "noaccess", v, "No access yet", "", nil)
			return
		}
		h(w, r, v)
	}
}

// requireAdmin answers non-admins exactly like a missing page.
func (s *server) requireAdmin(h authedHandler) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
		if !v.IsAdmin {
			s.notFound(w, r, v)
			return
		}
		h(w, r, v)
	}
}

// sameOrigin requires the Origin header (or, if absent, the Referer) to
// match the configured base URL.
func (s *server) sameOrigin(r *http.Request) bool {
	origins := loopbackAliases(s.origin)
	o, ref := r.Header.Get("Origin"), r.Header.Get("Referer")
	ok := false
	if o != "" {
		ok = slices.Contains(origins, o)
	} else {
		for _, want := range origins {
			if ref == want || strings.HasPrefix(ref, want+"/") {
				ok = true
			}
		}
	}
	if !ok {
		// Says why a POST got 403 without logging anything sensitive.
		s.log.Warn("refused cross-origin POST", "path", r.URL.Path, "origin", o, "referer_set", ref != "",
			"expected", s.origin, "hint", "open the UI at ui.base_url")
	}
	return ok
}

// loopbackAliases returns the origins equivalent to origin. For a loopback
// base URL, the same server is reachable as localhost, 127.0.0.1 or [::1],
// and browsers send whichever was typed. No other site can claim those
// origins, so accepting all of them keeps the CSRF protection intact.
func loopbackAliases(origin string) []string {
	u, err := url.Parse(origin)
	if err != nil {
		return []string{origin}
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return []string{origin}
	}
	port := ""
	if p := u.Port(); p != "" {
		port = ":" + p
	}
	return []string{origin, u.Scheme + "://localhost" + port, u.Scheme + "://127.0.0.1" + port, u.Scheme + "://[::1]" + port}
}

func (s *server) parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	return r.ParseForm() == nil
}

// safeNext returns p if it's a same-site relative path, else "/".
func safeNext(p string) string {
	if p == "" || len(p) > 2048 || p[0] != '/' || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") ||
		strings.ContainsFunc(p, func(r rune) bool { return unicode.IsControl(r) || r == '\\' }) {
		return "/"
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" || strings.HasPrefix(u.Path, "/login") {
		return "/"
	}
	return p
}

func (s *server) setSession(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ── Static files ───────────────────────────────────────────────────────────

var staticName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

var staticTypes = map[string]string{
	".css": "text/css; charset=utf-8",
	".js":  "text/javascript; charset=utf-8",
	".svg": "image/svg+xml",
}

func (s *server) static(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	ctype, ok := staticTypes[path.Ext(name)]
	if !ok || !staticName.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(staticFS, "static/"+name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(b)
}

// ── Rendering ──────────────────────────────────────────────────────────────

type page struct {
	Title   string
	Nav     string // active nav item
	Viewer  *auth.Viewer
	CSRF    string
	Version string
	Refresh string           // same-site path for a meta refresh (SSO hand-off), or ""
	Update  *updates.Release // a newer release, shown to admins
	Body    any
}

func (s *server) render(w http.ResponseWriter, r *http.Request, status int, name string, v *auth.Viewer, title, nav string, body any) {
	p := page{Title: title, Nav: nav, Viewer: v, Body: body}
	if v != nil && v.IsAdmin && s.cfg.Updates != nil {
		if rel, ok := s.cfg.Updates(); ok {
			p.Update = &rel
		}
	}
	s.renderPage(w, r, status, name, p)
}

// renderPage renders a fully specified page (e.g. one with a Refresh).
func (s *server) renderPage(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	t, ok := s.pages[name]
	if !ok {
		s.log.Error("unknown template", "name", name)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	p.Version = s.cfg.Version
	if p.Viewer != nil {
		p.CSRF = auth.CSRFToken(p.Viewer.SessionToken)
	}
	var buf strings.Builder
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		s.log.Error("render failed", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		w.Write([]byte(buf.String()))
	}
}

func (s *server) notFound(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	s.render(w, r, http.StatusNotFound, "notfound", v, "Not found", "", nil)
}

func (s *server) forbidden(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "forbidden", http.StatusForbidden)
}

func (s *server) fail(w http.ResponseWriter, r *http.Request, v *auth.Viewer, err error) {
	s.log.Error("page failed", "path", r.URL.Path, "err", err)
	s.render(w, r, http.StatusInternalServerError, "error", v, "Something went wrong", "", nil)
}

func parsePages() (map[string]*template.Template, error) {
	names := []string{"login", "dashboard", "hosts", "host", "sites", "search", "notfound", "error",
		"signedin", "noaccess", "admin_users", "plans", "plan", "changes", "drift", "anomalies", "addhost"}
	pages := make(map[string]*template.Template, len(names))
	for _, n := range names {
		t, err := template.New(n).Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/partials.html", "templates/"+n+".html")
		if err != nil {
			return nil, fmt.Errorf("web: template %s: %w", n, err)
		}
		pages[n] = t
	}
	return pages, nil
}

var severities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}

var funcs = template.FuncMap{
	"userRef": store.UserRef,
	"hostURL": func(org, host string) string {
		return "/hosts/" + url.PathEscape(org) + "/" + url.PathEscape(host)
	},
	"time": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return t.Local().Format("2006-01-02 15:04")
	},
	"date": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.Format(time.DateOnly)
	},
	"ago": ago,
	// sev maps a severity to a CSS class suffix from a fixed set.
	"sev": func(s string) string {
		if severities[s] {
			return s
		}
		return "unknown"
	},
	"join":      strings.Join,
	"lifeState": lifeState,
	// unmet: a known-false requirement check (nil means unknown).
	"unmet": func(b *bool) bool { return b != nil && !*b },
	"first": func(s []string) string {
		if len(s) == 0 {
			return ""
		}
		return s[0]
	},
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}
