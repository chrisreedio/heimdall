// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/store"
)

// Branding (admin settings): the hub's display name, accent color, logo
// and app icon. Images are served from /branding/ with the branding's
// version in the URL, so browsers cache them for good and a change is a
// new URL. The accent reaches the pages as a small stylesheet, which
// keeps the CSP free of inline styles.

const (
	maxBrandName  = 30
	defaultAccent = "#1f4e8c" // app.css --accent, light theme
	// maxUploadBytes bounds a branding form's whole body: the largest
	// image allowed plus room for the form, so a slightly too large file
	// still gets a message rather than a refusal.
	maxUploadBytes = 4 << 20
)

// brandCache holds the branding in memory; every page shows it. Only this
// process writes it, so a save replaces the cached copy.
type brandCache struct {
	mu sync.Mutex
	b  *store.Branding
}

// branding returns the hub's branding (Heimdall's own if it can't be read).
func (s *server) branding(ctx context.Context) store.Branding {
	s.brand.mu.Lock()
	defer s.brand.mu.Unlock()
	if s.brand.b == nil {
		b, err := s.st.Branding(ctx)
		if err != nil {
			s.log.Error("branding: load failed", "err", err)
			return store.Branding{}
		}
		s.brand.b = &b
	}
	return *s.brand.b
}

// defaultName is the display name without branding: mcp.name if the hub
// set one, else Heimdall.
func (s *server) defaultName() string {
	if n := s.cfg.MCP.Name; n != "" && n != config.DefaultConnectorName {
		return n
	}
	return "Heimdall"
}

// brandView is what the layout shows. URLs are this hub's own.
type brandView struct {
	Name    string
	Logo    string // the logo, or "" for Heimdall's mark
	Favicon string // 32 px PNG, or "" for the SVG mark
	Touch   string // apple-touch-icon
	CSS     string // the accent stylesheet, or ""
}

func (s *server) brandView(ctx context.Context) brandView {
	b := s.branding(ctx)
	v := brandView{Name: s.defaultName(), Touch: "/static/icon-180.png"}
	if b.Name != "" {
		v.Name = b.Name
	}
	u := func(file string) string { return "/branding/" + file + "?v=" + strconv.FormatInt(b.Version, 10) }
	if len(b.Logo) > 0 {
		v.Logo = u("logo.png")
	}
	if len(b.Icon32) > 0 {
		v.Favicon, v.Touch = u("icon-32.png"), u("icon-180.png")
	}
	if b.Accent != "" || b.AccentDark != "" {
		v.CSS = u("accent.css")
	}
	return v
}

// brandFile serves a branding image or the accent stylesheet. They're
// public: the sign-in page and the app manifest show them.
func (s *server) brandFile(w http.ResponseWriter, r *http.Request) {
	b := s.branding(r.Context())
	var body []byte
	ctype := "image/png"
	switch r.PathValue("file") {
	case "logo.png":
		body = b.Logo
	case "icon-512.png":
		body = b.Icon512
	case "icon-192.png":
		body = b.Icon192
	case "icon-180.png":
		body = b.Icon180
	case "icon-32.png":
		body = b.Icon32
	case "accent.css":
		body = accentCSS(b)
		ctype = "text/css; charset=utf-8"
	}
	if len(body) == 0 {
		http.NotFound(w, r)
		return
	}
	version := strconv.FormatInt(b.Version, 10)
	etag := `"b` + version + `"`
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("ETag", etag)
	if r.URL.Query().Get("v") == version {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "no-cache")
	}
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(body)
}

// accentCSS is /branding/accent.css: the light theme's accent and the
// dark theme's (chosen, or derived from the light one), or nothing for
// Heimdall's own. Repeating :root outranks the theme blocks in app.css.
func accentCSS(b store.Branding) []byte {
	if b.Accent == "" && b.AccentDark == "" {
		return nil
	}
	css := "/* Branding: the accent colors an admin chose. */\n"
	if b.Accent != "" {
		css += ":root:root:root { --accent: " + b.Accent + "; --accent-text: " + accentText + "; }\n"
	}
	if dark := accentDark(b); dark != "" {
		css += "@media (prefers-color-scheme: dark) { :root:root:root:not([data-theme=\"light\"]) { --accent: " + dark + "; } }\n" +
			":root:root:root[data-theme=\"dark\"] { --accent: " + dark + "; }\n"
	}
	return []byte(css)
}

// accentDark is the dark theme's accent: the one chosen, else derived
// from the light one, else "" (Heimdall's).
func accentDark(b store.Branding) string {
	switch {
	case b.AccentDark != "":
		return b.AccentDark
	case b.Accent != "":
		return darkAccent(b.Accent)
	}
	return ""
}

// ── The settings page ─────────────────────────────────────────────────────

type brandingBody struct {
	Name, DefaultName string // the custom name ("" for none) and the one without it
	Accent            string // the custom accent, or ""
	DefaultAccent     string
	AccentDark        string // the dark theme's custom accent, or "" to derive it
	DarkInUse         string // the dark theme's accent in use, or "" for Heimdall's
	DefaultAccentDark string
	Logo, Icon        string // custom images' URLs, or ""
	MaxName           int
	Notice, Error     string
}

var brandingNotices = map[string]string{
	"name":         "Display name saved.",
	"accent":       "Accent colors saved.",
	"logo":         "Logo saved.",
	"icon":         "App icon saved. Phones that installed the app pick it up when they next check its manifest; reinstall to see it at once.",
	"reset-name":   "Display name reset.",
	"reset-accent": "Accent color reset to Heimdall's.",
	"reset-logo":   "Logo reset to Heimdall's.",
	"reset-icon":   "App icon reset to Heimdall's.",
}

func (s *server) brandingPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	s.renderBranding(w, r, v, http.StatusOK, brandingNotices[r.URL.Query().Get("ok")], "")
}

func (s *server) renderBranding(w http.ResponseWriter, r *http.Request, v *auth.Viewer, status int, notice, errMsg string) {
	b := s.branding(r.Context())
	bv := s.brandView(r.Context())
	body := brandingBody{Name: b.Name, DefaultName: s.defaultName(), Accent: b.Accent, DefaultAccent: defaultAccent,
		AccentDark: b.AccentDark, DarkInUse: accentDark(b), DefaultAccentDark: defaultAccentDark,
		Logo: bv.Logo, MaxName: maxBrandName, Notice: notice, Error: errMsg}
	if len(b.Icon192) > 0 {
		body.Icon = "/branding/icon-192.png?v=" + strconv.FormatInt(b.Version, 10)
	}
	s.render(w, r, status, "branding", v, "Branding", "branding", body)
}

// brandingAction saves one branding setting. requireAuthUpload has checked
// Origin and the CSRF token; requireAdmin the role.
func (s *server) brandingAction(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ctx := r.Context()
	b := s.branding(ctx)
	action := r.PathValue("action")
	detail := map[string]any{}
	var err error
	switch action {
	case "name":
		var name string
		if name, err = checkBrandName(r.PostForm.Get("name")); err == nil {
			b.Name, detail["name"] = name, name
		}
		if name == "" {
			action = "reset-name"
		}
	case "accent":
		// The light theme's accent, and the dark theme's if "dark_own" is
		// ticked; otherwise the dark one is derived from the light one.
		var hex, dark string
		if hex, err = checkAccent(r.PostForm.Get("accent")); err == nil && r.PostForm.Get("dark_own") != "" {
			dark, err = checkAccentDark(r.PostForm.Get("accent_dark"))
		}
		if err == nil {
			b.Accent, b.AccentDark, detail["accent"] = hex, dark, hex
			if dark != "" {
				detail["accent_dark"] = dark
			} else {
				detail["accent_dark_derived"] = darkAccent(hex)
			}
		}
	case "logo":
		var data []byte
		if data, err = formFile(r, "logo"); err == nil {
			data, err = logoPNG(data)
		}
		if err == nil {
			b.Logo, detail["bytes"] = data, len(data)
		}
	case "icon":
		var data []byte
		var icons map[int][]byte
		if data, err = formFile(r, "icon"); err == nil {
			icons, err = iconPNGs(data)
		}
		if err == nil {
			b.Icon512, b.Icon192, b.Icon180, b.Icon32 = icons[512], icons[192], icons[180], icons[32]
			detail["bytes"] = len(icons[512])
		}
	case "reset-name":
		b.Name = ""
	case "reset-accent":
		b.Accent, b.AccentDark = "", ""
	case "reset-logo":
		b.Logo = nil
	case "reset-icon":
		b.Icon512, b.Icon192, b.Icon180, b.Icon32 = nil, nil, nil, nil
	default:
		s.notFound(w, r, v)
		return
	}
	if err != nil {
		s.renderBranding(w, r, v, http.StatusBadRequest, "", err.Error())
		return
	}
	what, _ := strings.CutPrefix(action, "reset-")
	if what != action {
		what += ".reset"
	}
	version, err := s.st.SetBranding(ctx, fmt.Sprintf("user:%d", v.UserID), b, what, detail, s.now())
	if err != nil {
		s.log.Error("branding: save failed", "err", err)
		s.renderBranding(w, r, v, http.StatusInternalServerError, "", "That didn't save; see the server log.")
		return
	}
	b.Version = version
	s.brand.mu.Lock()
	s.brand.b = &b
	s.brand.mu.Unlock()
	http.Redirect(w, r, "/admin/branding?ok="+action, http.StatusSeeOther)
}

// checkBrandName trims a display name and refuses one that's too long or
// has control characters. "" means Heimdall's default.
func checkBrandName(s string) (string, error) {
	s = strings.Join(strings.Fields(s), " ")
	if n := len([]rune(s)); n > maxBrandName {
		return "", fmt.Errorf("the display name can be up to %d characters; that one is %d", maxBrandName, n)
	}
	if strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || !unicode.IsPrint(r) }) {
		return "", errors.New("the display name can't contain control characters")
	}
	return s, nil
}

// formFile reads an uploaded file from the form.
func formFile(r *http.Request, field string) ([]byte, error) {
	if r.MultipartForm == nil {
		return nil, errors.New("choose a PNG file")
	}
	f, _, err := r.FormFile(field)
	if err != nil {
		return nil, errors.New("choose a PNG file")
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxUploadBytes))
}
