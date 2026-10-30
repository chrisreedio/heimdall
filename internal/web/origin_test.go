// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"net/url"
	"testing"
)

// The same loopback server can be reached as localhost, 127.0.0.1 or [::1];
// a login from any of them must pass the Origin check. Other origins still fail.
func TestLoopbackOriginAliases(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	form := url.Values{"email": {"admin@example.com"}, "password": {"pw"}, "code": {"123456"}}
	for _, o := range []string{"http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"} {
		if w := e.post("/login", form, origin(o)); w.Code == http.StatusForbidden {
			t.Errorf("%s: forbidden", o)
		}
	}
	for _, o := range []string{"http://localhost:9999", "https://localhost:8080", "http://evil.example", "null"} {
		if w := e.post("/login", form, origin(o)); w.Code != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403", o, w.Code)
		}
	}
	// A non-loopback base URL gets no aliases.
	if got := loopbackAliases("https://heimdall.internal"); len(got) != 1 {
		t.Errorf("aliases for a real host: %v", got)
	}
}
