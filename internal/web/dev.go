// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build dev

package web

// Live editing for development, like a frontend dev server. Only binaries
// built with -tags dev contain this file; release builds never do.
//
//	HEIMDALL_DEV_DIR=internal/web bin/heimdall-dev -c heimdall.toml serve
//
// Templates and static files are then read from that directory on every
// request, and open pages reload themselves when a file changes or the
// server restarts (after a rebuild). With HEIMDALL_DEV_LOGIN=<local user's
// email> the sign-in page also offers a one-click test sign-in.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func init() { devSetup = setupDev }

// setupDev turns on live editing when HEIMDALL_DEV_DIR is set, and the
// one-click test sign-in when HEIMDALL_DEV_LOGIN names a local user and the
// UI is on loopback.
func setupDev(s *server, mux *http.ServeMux) {
	// Decided afresh for each server, from the current environment.
	templatesFS, staticFiles, devMode, devLoginEmail = templateFS, staticFS, false, ""
	dir := os.Getenv("HEIMDALL_DEV_DIR")
	if dir == "" {
		return
	}
	templatesFS, staticFiles, devMode = os.DirFS(dir), os.DirFS(dir), true
	if email := os.Getenv("HEIMDALL_DEV_LOGIN"); email != "" && loopbackURL(s.cfg.BaseURL) {
		devLoginEmail = email
		mux.HandleFunc("POST /_dev/login", s.devLogin)
	}
	boot := make([]byte, 6)
	rand.Read(boot)
	bootID := hex.EncodeToString(boot)
	mux.HandleFunc("GET /_dev/reload.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprint(w, reloadJS)
	})
	mux.HandleFunc("GET /_dev/events", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, "event: hello\ndata: %s\n\n", bootID)
		fl.Flush()
		last := treeStamp(dir)
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		// End before the server's write timeout; the page reconnects.
		done := time.After(50 * time.Second)
		for {
			select {
			case <-r.Context().Done():
				return
			case <-done:
				return
			case <-tick.C:
				if now := treeStamp(dir); now != last {
					last = now
					fmt.Fprint(w, "event: change\ndata: reload\n\n")
					fl.Flush()
				}
			}
		}
	})
}

// devLogin signs in as the dev test user without a password or code. It
// only exists in dev builds, only when the UI is on loopback, and only
// answers same-origin POSTs from this machine.
func (s *server) devLogin(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() || !s.sameOrigin(r) || !s.parseForm(w, r) {
		s.forbidden(w, r)
		return
	}
	dl, ok := s.auth.(interface {
		DevLogin(ctx context.Context, email, ip, userAgent string) (string, error)
	})
	if !ok {
		http.NotFound(w, r)
		return
	}
	token, err := dl.DevLogin(r.Context(), devLoginEmail, host, r.UserAgent())
	if err != nil {
		body := s.loginBody(safeNext(r.PostForm.Get("next")))
		body.Error = "dev sign-in failed: " + err.Error()
		s.render(w, r, http.StatusInternalServerError, "login", nil, "Sign in", "", body)
		return
	}
	s.setSession(w, token, int(s.cfg.SessionMax.Seconds()))
	http.Redirect(w, r, safeNext(r.PostForm.Get("next")), http.StatusSeeOther)
}

func loopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Hostname() == "localhost" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}

// treeStamp changes whenever a file under templates/ or static/ does.
func treeStamp(dir string) string {
	var n int64
	var latest time.Time
	for _, sub := range []string{"templates", "static"} {
		filepath.WalkDir(filepath.Join(dir, sub), func(_ string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
				if fi.ModTime().After(latest) {
					latest = fi.ModTime()
				}
			}
			return nil
		})
	}
	return fmt.Sprintf("%d-%d", n, latest.UnixNano())
}

// reloadJS reloads the page when a file changes, or when the server comes
// back with a different boot ID (it was rebuilt and restarted).
const reloadJS = `(function () {
  var boot = null;
  function connect() {
    var es = new EventSource("/_dev/events");
    es.addEventListener("hello", function (e) {
      if (boot && e.data !== boot) location.reload();
      boot = e.data;
    });
    es.addEventListener("change", function () { location.reload(); });
    es.onerror = function () { es.close(); setTimeout(connect, 400); };
  }
  connect();
})();
`
