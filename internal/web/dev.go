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
// server restarts (after a rebuild).

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func init() {
	dir := os.Getenv("HEIMDALL_DEV_DIR")
	if dir == "" {
		return
	}
	templatesFS, staticFiles, devMode = os.DirFS(dir), os.DirFS(dir), true
	boot := make([]byte, 6)
	rand.Read(boot)
	bootID := hex.EncodeToString(boot)
	devRoutes = func(mux *http.ServeMux) {
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
