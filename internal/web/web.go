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
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/realmwatch/heimdall/internal/ai"
	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/auth/entra"
	"github.com/realmwatch/heimdall/internal/bans"
	"github.com/realmwatch/heimdall/internal/handoff"
	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/privilege"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/search"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/updates"
)

// Authenticator signs users in and resolves session cookies.
type Authenticator interface {
	// Login and LoginIdentity start a device session ("Keep me signed in
	// on this device") when keep is set.
	Login(ctx context.Context, email, password, code, ip, userAgent string, keep bool) (token string, err error)
	// LoginIdentity starts a session for an identity SSO has validated.
	// auth.ErrNotProvisioned means the user isn't set up in Heimdall.
	LoginIdentity(ctx context.Context, id store.EntraIdentity, roles []string, ip, userAgent string, keep bool) (token string, err error)
	Session(ctx context.Context, token string) (*auth.Viewer, error)
	Logout(ctx context.Context, token string) error
	// StepUp checks a signed-in local user's TOTP code (refusing a replay)
	// and records it on their session; StepUpIdentity records an SSO
	// sign-in with prompt=login, which must be the session's user
	// (stepup.go).
	StepUp(ctx context.Context, v *auth.Viewer, code, ip string) error
	StepUpIdentity(ctx context.Context, v *auth.Viewer, id store.EntraIdentity, ip string) error
}

// SSO is the Entra ID OIDC flow (see internal/auth/entra).
type SSO interface {
	Begin(ctx context.Context) (entra.AuthRequest, error)
	// BeginReauth is Begin with prompt=login, for step-up (stepup.go).
	BeginReauth(ctx context.Context) (entra.AuthRequest, error)
	Finish(ctx context.Context, code, verifier, nonce string) (entra.Identity, error)
}

// SearchFunc answers a fleet search. Errors are shown to the user.
type SearchFunc func(ctx context.Context, query string, scope store.Scope) (*search.Result, error)

type Config struct {
	Updates     func() (updates.Release, bool) // newer release for the admin banner; nil = off
	IngestURL   string                         // ingest.public_url, for install commands
	BaseURL     string                         // e.g. https://heimdall.internal or http://127.0.0.1:8080
	StaleAfter  time.Duration                  // hosts.stale_after
	Version     string
	SessionMax  time.Duration // cookie Max-Age
	SessionIdle time.Duration // ui.session_idle, for which sessions the Devices list shows

	SSO          SSO      // nil = single sign-on disabled
	LocalLogin   bool     // password + TOTP sign-in; false hides the form and refuses POST /login
	EntraTenants []string // allowed tenant IDs, offered when an admin adds an Entra user

	News bool // threat news is on: show the News page, dashboard strip and host card

	MCP MCPSetup // [mcp]: the AI assistants page and Desktop extension; zero = off

	AI AIService // optional AI analysis (internal/ai); nil = off

	// Agents are the coding agents "Hand off to agent" can ask for a pull
	// request ([[agents]]); none hides the button. See handoff.go.
	Agents []handoff.Agent

	// IPs says what's known about addresses (privilege sessions' sources,
	// sign-ins); nil knows only the built-in ranges.
	IPs *ipinfo.Resolver

	// Cloudflare: [cloudflare] is on, so operators get the overview link.
	Cloudflare bool
	// CloudflareLists syncs the Cloudflare IP lists now, after an admin maps
	// one (cloudflare.go); nil without a Cloudflare token.
	CloudflareLists func(context.Context) error

	// Tailnet: [tailscale] is on, so host pages show their tailnet device
	// and /hosts can filter for hosts not on the tailnet (tailscale.go).
	Tailnet bool
	// BehindTailscaleServe trusts tailscale serve's client address and
	// identity headers on requests from loopback (tsproxy.go).
	BehindTailscaleServe bool
	// BehindProxy trusts another local proxy's client address the same way
	// (tsproxy.go); TrustedEdge says which hops are Cloudflare's edge, whose
	// CF-Connecting-IP is then taken instead (nil: never).
	BehindProxy bool
	TrustedEdge func(netip.Addr) bool

	// Bans: [bans] (internal/bans); nil when it isn't set up.
	Bans *bans.Service

	// Push sends Web Push notifications (notifications.go); nil = off.
	Push PushService
}

// CSP is the Content-Security-Policy sent with every response.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"worker-src 'self'; manifest-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

const (
	maxFormBytes = 16 << 10
	csrfField    = "csrf"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Where pages and static files come from. Release builds always use the
// embedded copies; a dev build (go build -tags dev, see dev.go) can point
// these at the source tree for live editing.
var (
	templatesFS   fs.FS = templateFS
	staticFiles   fs.FS = staticFS
	devMode             = false
	devLoginEmail       = "" // dev builds: the one-click test sign-in, if enabled
	devSetup      func(*server, *http.ServeMux)
)

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
	tokenLimit tokenLimiter // MCP token creation, per user
	// handoffLimit: one hand-off per site and agent every few minutes.
	handoffLimit handoffLimiter
	nav          navCache      // the sidebar's badges, per user (nav.go)
	brand        brandCache    // the hub's branding (branding.go)
	settings     settingsCache // hub settings (stepup.go)
	stepups      stepUpStore   // actions waiting for an SSO step-up (stepup.go)
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
	mux := http.NewServeMux()
	if devSetup != nil {
		devSetup(s, mux)
	}
	if s.pages, err = parsePages(); err != nil {
		return nil, err
	}
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /logout", s.requireAuth(s.logout))
	mux.HandleFunc("GET /auth/entra/login", s.ssoLogin)
	mux.HandleFunc("GET /auth/callback", s.ssoCallback)
	mux.HandleFunc("GET /{$}", s.requireAuth(s.withScope(s.dashboard)))
	mux.HandleFunc("GET /hosts", s.requireAuth(s.withScope(s.hostsPage)))
	mux.HandleFunc("GET /hosts/{org}/{host}", s.requireAuth(s.hostPage))
	mux.HandleFunc("GET /hosts/{org}/{host}/site", s.requireAuth(s.sitePage))
	mux.HandleFunc("GET /sites", s.requireAuth(s.withScope(s.sitesPage)))
	mux.HandleFunc("GET /search", s.requireAuth(s.withScope(s.searchPage)))
	mux.HandleFunc("GET /news", s.requireAuth(s.withScope(s.newsPage)))
	mux.HandleFunc("GET /hosts/new", s.requireAuth(s.addHostPage))
	mux.HandleFunc("POST /hosts/new", s.requireAuth(s.addHostSubmit))
	mux.HandleFunc("GET /hosts/enroll", s.requireAuth(s.enrollPage)) // enrollment keys (enroll.go)
	mux.HandleFunc("POST /hosts/enroll", s.requireAuth(s.enrollSubmit))
	mux.HandleFunc("POST /hosts/enroll/revoke", s.requireAuth(s.enrollRevoke))
	mux.HandleFunc("POST /hosts/enroll/approve", s.requireAuth(s.enrollDecide(true)))
	mux.HandleFunc("POST /hosts/enroll/reject", s.requireAuth(s.enrollDecide(false)))
	mux.HandleFunc("POST /hosts/{org}/{host}/rename", s.requireAuth(s.hostRename))
	mux.HandleFunc("POST /hosts/{org}/{host}/tags", s.requireAuth(s.hostTags))
	mux.HandleFunc("POST /drift/tag", s.requireAuth(s.driftTag))
	mux.HandleFunc("POST /hosts/{org}/{host}/env", s.requireAuth(s.hostEnv))
	mux.HandleFunc("POST /sites/label", s.requireAuth(s.siteLabel))
	mux.HandleFunc("POST /sites/repo", s.requireAuth(s.siteRepo))
	mux.HandleFunc("POST /sites/branch", s.requireAuth(s.siteBranch))
	mux.HandleFunc("GET /hosts/{org}/{host}/handoff", s.requireAuth(s.handoffPage))
	mux.HandleFunc("POST /hosts/{org}/{host}/handoff", s.requireAuth(s.handoffSend))
	mux.HandleFunc("GET /handoff/batch", s.requireAuth(s.handoffBatchPage))
	mux.HandleFunc("POST /handoff/batch", s.requireAuth(s.handoffBatchSend))
	mux.HandleFunc("GET /hosts/{org}/{host}/changes", s.requireAuth(s.changesPage))
	mux.HandleFunc("GET /anomalies", s.requireAuth(s.anomaliesPage))
	mux.HandleFunc("POST /anomalies/{id}/{action}", s.requireAuth(s.anomalyAction))
	mux.HandleFunc("POST /anomalies/bulk", s.requireAuth(s.anomalyBulk))
	mux.HandleFunc("GET /drift", s.requireAuth(s.withScope(s.driftPage)))
	mux.HandleFunc("GET /plans", s.requireAuth(s.plansPage))
	mux.HandleFunc("POST /plans", s.requireAuth(s.planCreate))
	mux.HandleFunc("GET /plans/{id}", s.requireAuth(s.planPage))
	mux.HandleFunc("POST /plans/{id}/{action}", s.requireAuth(s.planAction))
	mux.HandleFunc("GET /admin/users", s.requireAuth(s.requireAdmin(s.adminUsers)))
	mux.HandleFunc("POST /admin/users/{action}", s.requireAuth(s.requireAdmin(s.adminAction)))
	mux.HandleFunc("GET /account/assistants", s.requireAuth(s.assistantsPage))
	mux.HandleFunc("POST /account/assistants", s.requireAuth(s.assistantCreate))
	mux.HandleFunc("POST /account/assistants/revoke", s.requireAuth(s.assistantRevoke))
	mux.HandleFunc("GET /account/assistants/heimdall.mcpb", s.requireAuth(s.assistantBundle))
	mux.HandleFunc("GET /account/devices", s.requireAuth(s.devicesPage)) // where you're signed in (devices.go)
	mux.HandleFunc("POST /account/devices/revoke", s.requireAuth(s.deviceRevoke))
	mux.HandleFunc("POST /admin/users/session-revoke", s.requireAuth(s.requireAdmin(s.adminSessionRevoke)))
	// IP awareness: labels and policy (org admins), what's known about an address (ips.go).
	mux.HandleFunc("GET /ips", s.requireAuth(s.ipsPage))
	mux.HandleFunc("POST /ips/labels", s.requireAuth(s.ipLabelAdd))
	mux.HandleFunc("POST /ips/labels/{id}/remove", s.requireAuth(s.ipLabelRemove))
	mux.HandleFunc("POST /ips/policy", s.requireAuth(s.ipPolicySet))
	mux.HandleFunc("GET /ips/{addr}", s.requireAuth(s.withScope(s.ipPage)))
	mux.HandleFunc("GET /ips/person/{person}", s.requireAuth(s.withScope(s.personPage)))          // people.go
	mux.HandleFunc("GET /cloudflare", s.requireAuth(s.cloudflarePage))                            // Cloudflare overview (cloudflare.go)
	mux.HandleFunc("POST /cloudflare/lists", s.requireAuth(s.requireAdmin(s.cloudflareListsSet))) // which IP lists become labels
	// Failed logins: repeat offenders across the viewer's hosts (logins.go).
	mux.HandleFunc("GET /offenders", s.requireAuth(s.withScope(s.offendersPage)))
	mux.HandleFunc("GET /surface", s.requireAuth(s.surfacePage)) // attack-surface map (surface.go)
	// Bans: proposals, approvals, per-zone opt-in and the pause switch (bans.go).
	mux.HandleFunc("GET /bans", s.requireAuth(s.bansPage))
	mux.HandleFunc("POST /bans/{id}/{action}", s.requireAuth(s.banAction))
	mux.HandleFunc("POST /bans/pause", s.requireAuth(s.banPause(true)))
	mux.HandleFunc("POST /bans/resume", s.requireAuth(s.banPause(false)))
	mux.HandleFunc("POST /bans/zones", s.requireAuth(s.banZone))
	mux.HandleFunc("POST /admin/users/mcp-revoke", s.requireAuth(s.requireAdmin(s.adminTokenRevoke)))
	// Branding: the hub's name, accent, logo and app icon (branding.go).
	mux.HandleFunc("GET /admin/branding", s.requireAuth(s.requireAdmin(s.brandingPage)))
	mux.HandleFunc("POST /admin/branding/{action}", s.requireAuthUpload(s.requireAdmin(s.brandingAction)))
	mux.HandleFunc("GET /branding/{file}", s.brandFile)
	mux.HandleFunc("GET /admin/security", s.requireAuth(s.requireAdmin(s.securityPage))) // step-up codes (stepup.go)
	mux.HandleFunc("POST /admin/security", s.requireAuth(s.requireAdmin(s.securityAction)))
	mux.HandleFunc("POST /stepup", s.requireAuth(s.stepUpSubmit))
	mux.HandleFunc("POST /stepup/sso", s.requireAuth(s.stepUpSSO))
	mux.HandleFunc("GET /stepup/done", s.requireAuth(s.stepUpDone))
	// The installable app: manifest, service worker, offline page (pwa.go).
	mux.HandleFunc("GET /manifest.webmanifest", s.manifest)
	// The phone layout's tabs (phone.go); Home is the dashboard, Hosts /hosts.
	mux.HandleFunc("GET /alerts", s.requireAuth(s.withScope(s.alertsPage)))
	mux.HandleFunc("GET /defense", s.requireAuth(s.withScope(s.defensePage)))
	mux.HandleFunc("GET /more", s.requireAuth(s.morePage))
	mux.HandleFunc("GET /sw.js", s.serviceWorker)
	mux.HandleFunc("GET /offline", s.offlinePage)
	// Push notifications: this device on or off, a test, settings (notifications.go).
	mux.HandleFunc("GET /account/notifications", s.requireAuth(s.notificationsPage))
	mux.HandleFunc("POST /account/notifications/subscribe", s.requireAuth(s.pushSubscribe))
	mux.HandleFunc("POST /account/notifications/unsubscribe", s.requireAuth(s.pushUnsubscribe))
	mux.HandleFunc("POST /account/notifications/test", s.requireAuth(s.pushTest))
	mux.HandleFunc("POST /account/notifications/settings", s.requireAuth(s.pushSettings))
	if cfg.AI != nil { // AI analysis: regenerate a brief or explain a host (operator+)
		mux.HandleFunc("POST /ai/brief/{org}", s.requireAuth(s.aiBriefRun))
		mux.HandleFunc("POST /hosts/{org}/{host}/ai", s.requireAuth(s.aiHostRun))
	}
	mux.HandleFunc("GET /static/{file}", s.static)
	mux.HandleFunc("/", s.requireAuth(func(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
		s.notFound(w, r, v)
	}))
	return s.headers(s.fromProxy(mux)), nil
}

func (s *server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if devMode {
			h.Set("Content-Security-Policy", CSP+"; connect-src 'self'") // live reload
		} else {
			h.Set("Content-Security-Policy", CSP)
		}
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
func (s *server) requireAuth(h authedHandler) http.HandlerFunc { return s.authed(maxFormBytes, h) }

// requireAuthUpload is requireAuth for forms that upload a file
// (multipart, up to maxUploadBytes).
func (s *server) requireAuthUpload(h authedHandler) http.HandlerFunc {
	return s.authed(maxUploadBytes, h)
}

func (s *server) authed(maxBody int64, h authedHandler) http.HandlerFunc {
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
			if !s.sameOrigin(r) || !s.parseBody(w, r, maxBody) || !auth.ValidCSRF(v.SessionToken, r.PostForm.Get(csrfField)) {
				s.forbidden(w, r)
				return
			}
		}
		if v.Kept && v.Renewed { // a device session's expiry moved: so does its cookie's
			s.setSession(w, v.SessionToken, s.sessionAge(true))
		}
		if r.Method == http.MethodPost && !s.stepUp(w, r, v) { // stepup.go
			return
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
	return s.parseBody(w, r, maxFormBytes)
}

// parseBody parses a form of up to maxBody bytes, multipart (an upload)
// only when maxBody allows more than a plain form.
func (s *server) parseBody(w http.ResponseWriter, r *http.Request, maxBody int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt == "multipart/form-data" && maxBody > maxFormBytes {
		return r.ParseMultipartForm(maxBody) == nil
	}
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

// sessionAge is the session cookie's Max-Age, in seconds: a device
// session's (renewed on use) or the configured ui.session_max.
func (s *server) sessionAge(kept bool) int {
	if kept {
		return int(auth.DeviceSessionMax.Seconds())
	}
	return int(s.cfg.SessionMax.Seconds())
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
	".png": "image/png",
}

func (s *server) static(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	ctype, ok := staticTypes[path.Ext(name)]
	if !ok || !staticName.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(staticFiles, "static/"+name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	if devMode {
		w.Header().Set("Cache-Control", "no-store")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
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
	News    bool             // threat news is on (shows the nav item)
	MCP     bool             // MCP is on (shows the AI assistants link)
	CF      bool             // [cloudflare] is on (shows the Cloudflare link to operators)
	Perm    navPerm          // which sidebar links to show (nav.go)
	Counts  navCounts        // the sidebar's badges
	Brand   brandView        // the hub's name, logo and icons (branding.go)
	StepUp  string           // paths app.js asks a step-up code for (stepup.go), or ""
	Body    any
}

func (s *server) render(w http.ResponseWriter, r *http.Request, status int, name string, v *auth.Viewer, title, nav string, body any) {
	p := page{Title: title, Nav: nav, Viewer: v, Body: body}
	if v != nil {
		p.Perm, p.Counts = navPermOf(v), s.navCountsFor(r, v)
		p.StepUp = s.stepUpDialog(r, v)
	}
	if v != nil && v.IsAdmin && s.cfg.Updates != nil {
		if rel, ok := s.cfg.Updates(); ok {
			p.Update = &rel
		}
	}
	s.renderPage(w, r, status, name, p)
}

// renderPage renders a fully specified page (e.g. one with a Refresh).
func (s *server) renderPage(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	pages := s.pages
	if devMode { // re-read templates on every request
		var err error
		if pages, err = parsePages(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	t, ok := pages[name]
	if !ok {
		s.log.Error("unknown template", "name", name)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	p.Version = s.cfg.Version
	p.News = s.cfg.News
	p.MCP = s.cfg.MCP.Enabled
	p.CF = s.cfg.Cloudflare
	p.Brand = s.brandView(r.Context())
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
		"signedin", "noaccess", "admin_users", "plans", "plan", "changes", "drift", "anomalies", "addhost", "enroll", "site", "news", "handoff", "handoffbatch"}
	names = append(names, "assistants")                          // AI assistants (MCP tokens)
	names = append(names, "ips", "ip", "person")                 // IP awareness (ips.go, people.go)
	names = append(names, "cloudflare")                          // Cloudflare overview (cloudflare.go)
	names = append(names, "offenders")                           // failed logins (logins.go)
	names = append(names, "surface")                             // attack-surface map (surface.go)
	names = append(names, "bans")                                // bans (bans.go)
	names = append(names, "branding")                            // branding (branding.go)
	names = append(names, "devices")                             // sessions (devices.go)
	names = append(names, "security", "stepup", "stepup_resume") // step-up codes (stepup.go)
	names = append(names, "offline")                             // the app's offline page (pwa.go)
	names = append(names, "alerts", "defense", "more")           // the phone layout's tabs (phone.go)
	names = append(names, "notifications")                       // push notifications (notifications.go)
	pages := make(map[string]*template.Template, len(names))
	for _, n := range names {
		t, err := template.New(n).Funcs(funcs).ParseFS(templatesFS, "templates/layout.html", "templates/partials.html", "templates/ai.html", "templates/"+n+".html")
		if err != nil {
			return nil, fmt.Errorf("web: template %s: %w", n, err)
		}
		pages[n] = t
	}
	if err := parseTailnetCard(pages); err != nil { // tailscale.go
		return nil, fmt.Errorf("web: template tailnet: %w", err)
	}
	if err := parseLoginsTemplates(pages); err != nil { // logins.go
		return nil, fmt.Errorf("web: template logins: %w", err)
	}
	return pages, nil
}

var severities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}

// findingsCap is how many findings a table shows before "Show all".
const findingsCap = 200

var funcs = template.FuncMap{
	"devMode":   func() bool { return devMode },
	"devLogin":  func() string { return devLoginEmail },
	"userRef":   store.UserRef,
	"hostURL":   hostURL,
	"personURL": personURL,
	// IP labels (ips.go): a kind's pill class, a Cloudflare list item's
	// comment, and where a label came from in words.
	"kindClass":    func(kind string) string { return badgeClass[kind] },
	"listDetail":   privilege.ListDetail,
	"sourceName":   sourceName,
	"isListSource": store.IsIPListSource,
	// aitext renders AI text escaped, with known names linked (aiLinker).
	"aitext": func(l *aiLinker, text string) template.HTML { return l.HTML(text) },
	// aititle is a step's title, without linking the step's own hosts:
	// they're shown as badges next to it.
	"aititle": func(l *aiLinker, text string, hosts []string) template.HTML { return l.HTMLExcept(text, hosts) },
	// aicmds and ainotes pass a step's commands and a result's notes to
	// their partials (templates/ai.html).
	"aicmds":  func(v aiView, a ai.Action, id string) aiCmds { return aiCmds{V: v, A: a, ID: id} },
	"ainotes": func(l *aiLinker, n ai.Notes) aiNotes { return aiNotes{Links: l, Notes: n} },
	// time is an instant in UTC, for tooltips; ts shows it in the viewer's
	// time zone (times.go), iso is its datetime attribute.
	"time": utcText,
	"ts":   tsHTML,
	"iso":  func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
	"day": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return asDay(t).Format("Jan 2, 2006")
	},
	// fixable keeps the findings that have (want=true) or lack a fix.
	"fixable": func(fs []report.Finding, want bool) []report.Finding {
		var out []report.Finding
		for _, f := range fs {
			if (f.Fixed != "") == want {
				out = append(out, f)
			}
		}
		return out
	},
	"date": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return asDay(*t).Format("Jan 2, 2006")
	},
	// month and longDate are friendlier dates for prose and pills
	// ("Feb 2025", "4 Feb 2025"); tables keep ISO dates.
	"month": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return asDay(*t).Format("Jan 2006")
	},
	"longDate": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return asDay(*t).Format("Jan 2, 2006")
	},
	// fullDate is for tooltips: "Friday, October 23, 2026".
	"fullDate": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return asDay(*t).Format("Monday, January 2, 2006")
	},
	"dayAgo": func(t *time.Time) template.HTML { return dayAgoHTML(t, time.Now()) },
	// dayAgoText is dayAgo in UTC, for attributes.
	"dayAgoText": func(t *time.Time) string { return dayAgo(t, time.Now()) },
	"ago":        ago,
	// sev maps a severity to a CSS class suffix from a fixed set.
	"sev": func(s string) string {
		if severities[s] {
			return s
		}
		return "unknown"
	},
	"join":           strings.Join,
	"collectorFlags": collectorFlags,
	// findings passes a findings list to the findingsSplit partial along
	// with whether to show it all, and the URL that shows it all.
	"findings": func(list []report.Finding, all bool, allURL string) map[string]any {
		return map[string]any{"List": list, "All": all, "AllURL": allURL}
	},
	// head returns the first n findings (all of them if all is set).
	"head": func(list []report.Finding, n int, all bool) []report.Finding {
		if all || len(list) <= n {
			return list
		}
		return list[:n]
	},
	"findingsCap": func() int { return findingsCap },
	// navItem is one sidebar link (layout.html): nav names its icon and
	// marks it current; class is "bad" for a badge in alarm colors, or a
	// class for the link.
	"navItem": func(p page, href, nav, label string, count int, class any) map[string]any {
		tone, cls := "", ""
		if c, ok := class.(string); ok && c == "bad" {
			tone = c
		} else if ok {
			cls = c
		}
		return map[string]any{"Href": href, "Icon": nav, "Label": label, "Count": count, "Tone": tone, "Class": cls, "Current": p.Nav == nav}
	},
	// tabItem is one tab of the phone layout's tab bar: tab is what
	// page.Tab returns on its pages, icon a navicon name.
	"tabItem": func(p page, href, tab, icon, label string, count int, tone any) map[string]any {
		t, _ := tone.(string)
		return map[string]any{"Href": href, "Icon": icon, "Label": label, "Count": count, "Tone": t, "Current": p.Tab() == tab}
	},
	// attn says how many need attention: "46 fixable now · 16 to watch (no fix yet)".
	"attn": attnText,
	"chipsFor": func(c report.Counts, v findingsView) map[string]any {
		return map[string]any{"C": chipCounts{c}, "V": v}
	},
	// siteEco is the "siteeco" partial's input: an ecosystem's name, its
	// lockfile (shown beside it, or ""), its section, and whether it's open.
	"siteEco": func(name, file string, e ecoSection, open bool) map[string]any {
		return map[string]any{"Name": name, "File": file, "E": e, "Open": open}
	},
	"sevChips": func() []string { return []string{"critical", "high", "medium", "low", "unknown"} },
	// hotEPSS: an EPSS score worth watching even with no fix (store.WatchEPSS).
	"hotEPSS":   func(e float64) bool { return e >= store.WatchEPSS },
	"watchEPSS": func() string { return pct(store.WatchEPSS) },
	"pct":       pct,
	// siteURL is a site's page: sites are a host plus a web root.
	"siteURL": siteURL,
	"repoWeb": handoff.WebURL, // a GitHub or GitLab link for a repository, or ""
	// shortCommit is a commit hash's first 12 characters.
	"shortCommit": func(c string) string { return c[:min(len(c), 12)] },
	// repoShort shows a web link without its scheme: github.com/owner/repo.
	"repoShort": func(u string) string { return strings.TrimPrefix(u, "https://") },
	// pathBreak renders a path that may wrap only after a "/".
	"pathBreak": func(p string) template.HTML {
		parts := strings.Split(p, "/")
		for i := range parts {
			parts[i] = template.HTMLEscapeString(parts[i])
		}
		return template.HTML(strings.Join(parts, "/<wbr>"))
	},
	// relPath shows p relative to base when it's inside it.
	"relPath": func(base, p string) string {
		if rest, ok := strings.CutPrefix(p, strings.TrimSuffix(base, "/")+"/"); ok && rest != "" {
			return rest
		}
		return p
	},
	"lifeState":     lifeState,
	"runtimeGroups": runtimeGroups,
	"supportState":  supportState,
	"num":           commas,
	"rule":          ruleLabel,
	// timep is a time's address, for the date funcs that take a pointer.
	"timep": func(t time.Time) *time.Time { return &t },
	// unmet: a known-false requirement check (nil means unknown).
	"unmet": func(b *bool) bool { return b != nil && !*b },
	// dict builds a partial's input from key, value pairs.
	"dict": func(kv ...any) map[string]any {
		m := make(map[string]any, len(kv)/2)
		for i := 0; i+1 < len(kv); i += 2 {
			k, _ := kv[i].(string)
			m[k] = kv[i+1]
		}
		return m
	},
	"first": func(s []string) string {
		if len(s) == 0 {
			return ""
		}
		return s[0]
	},
}

// chipCounts adds BySev, for ranging over the severity chips.
type chipCounts struct{ report.Counts }

func (c chipCounts) BySev() map[string]int {
	return map[string]int{"critical": c.Critical, "high": c.High, "medium": c.Medium, "low": c.Low, "unknown": c.Unknown}
}

// pct shows a 0-1 score as a whole percentage ("34%"; "<1%" under one).
func pct(f float64) string {
	if f > 0 && f < 0.01 {
		return "<1%"
	}
	return fmt.Sprintf("%.0f%%", f*100)
}

func hostURL(org, host string) string {
	return "/hosts/" + url.PathEscape(org) + "/" + url.PathEscape(host)
}

// siteURL is a site's page: sites are a host plus a web root.
func siteURL(org, host, root string) string {
	return "/hosts/" + url.PathEscape(org) + "/" + url.PathEscape(host) + "/site?root=" + url.QueryEscape(root)
}

func ago(t time.Time) string { return agoAt(t, time.Now()) }

func agoAt(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
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

// dayAgo describes a date relative to today, in UTC (app.js redraws it in
// the viewer's time zone: dayAgoHTML): "Today 2:01 PM UTC (3h ago)" and
// "Yesterday 4:10 PM UTC" for timestamps ("today" and "yesterday" for plain
// dates), "3 days ago", then "Oct 23, 2026" once it's a month or more back.
func dayAgo(t *time.Time, now time.Time) string {
	if t == nil {
		return ""
	}
	y1, m1, d1 := asDay(*t).Date()
	y2, m2, d2 := now.UTC().Date()
	days := int(time.Date(y2, m2, d2, 0, 0, 0, 0, time.UTC).Sub(time.Date(y1, m1, d1, 0, 0, 0, 0, time.UTC)).Hours() / 24)
	switch {
	case days < 0:
		return t.Format("Jan 2, 2006")
	case days == 0 && isPlainDate(*t):
		return "today"
	case days == 0:
		return "Today " + t.UTC().Format("3:04 PM") + " UTC (" + agoAt(*t, now) + ")"
	case days == 1 && isPlainDate(*t):
		return "yesterday"
	case days == 1:
		return "Yesterday " + t.UTC().Format("3:04 PM") + " UTC"
	case days < 30:
		return fmt.Sprintf("%d days ago", days)
	}
	return t.Format("Jan 2, 2006")
}

// asDay is the day t falls on in UTC, as the server writes it: plain dates
// (lifecycle dates, stored as midnight UTC) are that day everywhere, and
// app.js moves instants to the viewer's day (times.go).
func asDay(t time.Time) time.Time { return t.UTC() }

// isPlainDate reports whether t is a date without a time (midnight UTC).
func isPlainDate(t time.Time) bool {
	u := t.UTC()
	return u.Hour() == 0 && u.Minute() == 0 && u.Second() == 0 && u.Nanosecond() == 0
}
