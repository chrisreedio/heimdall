// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"strings"
	"testing"
)

func TestChangesAndDriftPages(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seed()
	if w := e.get("/hosts/acme/web-01/changes", signedIn(e)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Changes on web-01") {
		t.Errorf("changes: %d", w.Code)
	}
	if w := e.get("/hosts/acme/nope/changes", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("unknown host: %d", w.Code)
	}
	if w := e.get("/drift?tag=web", signedIn(e)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Drift") {
		t.Errorf("drift: %d", w.Code)
	}
	if w := e.get("/drift"); w.Code != http.StatusSeeOther {
		t.Errorf("unauthenticated drift: %d", w.Code)
	}
}
