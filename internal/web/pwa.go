// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// The installable app (docs/mobile.md): a web app manifest, a service
// worker and an offline page make the hub's own UI installable on phones,
// over the tailnet, with the hub's branding. Each hub is its own origin,
// so each is its own app. The service worker caches only static files;
// pages and API answers always come from the hub.

// swCSP is the service worker's own CSP: a worker gets the policy its
// script was served with, and it needs connect-src to pass the hub's
// pages through (fetch), and img-src for notifications' icons. Pages keep
// CSP.
const swCSP = "default-src 'none'; connect-src 'self'; img-src 'self'"

type manifestIcon struct {
	Src     string `json:"src"`
	Sizes   string `json:"sizes"`
	Type    string `json:"type"`
	Purpose string `json:"purpose"`
}

type webManifest struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	ShortName       string         `json:"short_name"`
	Description     string         `json:"description"`
	StartURL        string         `json:"start_url"`
	Scope           string         `json:"scope"`
	Display         string         `json:"display"`
	BackgroundColor string         `json:"background_color"`
	ThemeColor      string         `json:"theme_color"`
	Icons           []manifestIcon `json:"icons"`
}

// manifest serves /manifest.webmanifest. It's public: browsers fetch it
// without cookies.
func (s *server) manifest(w http.ResponseWriter, r *http.Request) {
	b := s.branding(r.Context())
	name := s.brandView(r.Context()).Name
	m := webManifest{ID: "/", Name: name, ShortName: shortName(name), Description: "Server inventory, vulnerabilities and patching",
		StartURL: "/", Scope: "/", Display: "standalone", BackgroundColor: "#f6f7f9", ThemeColor: "#ffffff"}
	icon := func(src string, n int) manifestIcon {
		return manifestIcon{Src: src, Sizes: strconv.Itoa(n) + "x" + strconv.Itoa(n), Type: "image/png", Purpose: "any"}
	}
	if len(b.Icon512) > 0 {
		v := "?v=" + strconv.FormatInt(b.Version, 10)
		m.Icons = []manifestIcon{icon("/branding/icon-192.png"+v, 192), icon("/branding/icon-512.png"+v, 512)}
	} else {
		v := "?v=" + s.cfg.Version
		m.Icons = []manifestIcon{icon("/static/icon-192.png"+v, 192), icon("/static/icon-512.png"+v, 512)}
	}
	body, err := json.Marshal(m)
	if err != nil {
		s.log.Error("manifest", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(body)
}

// shortName is the name under the home-screen icon: the display name if
// it's short, else its first word, else its first 12 characters.
func shortName(name string) string {
	const most = 12
	if len([]rune(name)) <= most {
		return name
	}
	if first, _, _ := strings.Cut(name, " "); len([]rune(first)) <= most {
		return first
	}
	return string([]rune(name)[:most])
}

// serviceWorker serves /sw.js from the site root, so its scope is the
// whole hub. The hub's version and the branding's are in it, so either
// changing makes browsers install the new worker, which refreshes the
// cached files.
func (s *server) serviceWorker(w http.ResponseWriter, r *http.Request) {
	src, err := fs.ReadFile(staticFiles, "static/sw.js")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	version, _ := json.Marshal(s.cfg.Version + "-b" + strconv.FormatInt(s.branding(r.Context()).Version, 10))
	precache, _ := json.Marshal(s.precache(r))
	icon, badge := s.notificationIcons(r)
	iconJS, _ := json.Marshal(icon)
	badgeJS, _ := json.Marshal(badge)
	body := strings.Replace(string(src), `"__VERSION__"`, string(version), 1)
	body = strings.Replace(body, `["__PRECACHE__"]`, string(precache), 1)
	body = strings.Replace(body, `"__ICON__"`, string(iconJS), 1)
	body = strings.Replace(body, `"__BADGE__"`, string(badgeJS), 1)
	h := w.Header()
	h.Set("Content-Type", "text/javascript; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("Content-Security-Policy", swCSP)
	w.Write([]byte(body))
}

// notificationIcons are the push notifications' icon, the hub's app icon,
// and their status-bar badge: Heimdall's mark in white, which Android
// shows as a silhouette. A branded hub has no badge of its own, so the
// browser's is used.
func (s *server) notificationIcons(r *http.Request) (icon, badge string) {
	if b := s.branding(r.Context()); len(b.Icon192) > 0 {
		return "/branding/icon-192.png?v=" + strconv.FormatInt(b.Version, 10), ""
	}
	v := "?v=" + url.QueryEscape(s.cfg.Version)
	return "/static/icon-192.png" + v, "/static/badge-96.png" + v
}

// precache is what the service worker stores when it's installed: the
// offline page and the files it loads, at the URLs layout.html uses.
func (s *server) precache(r *http.Request) []string {
	v := "?v=" + url.QueryEscape(s.cfg.Version)
	list := []string{"/offline", "/static/theme.js" + v, "/static/app.css" + v, "/static/app.js" + v, "/static/icon.svg"}
	bv := s.brandView(r.Context())
	for _, u := range []string{bv.CSS, bv.Logo, bv.Favicon} {
		if u != "" {
			list = append(list, u)
		}
	}
	return list
}

// offlinePage is what the service worker shows when a page can't be
// loaded. It's public and has nothing from the hub but its branding, so
// it's safe to cache.
func (s *server) offlinePage(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, r, http.StatusOK, "offline", page{Title: "Offline"})
}
