// SPDX-License-Identifier: AGPL-3.0-or-later

package netx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Plain http to an allowlisted loopback host works only in dev builds.
func TestLoopbackHTTPOnlyInDevBuilds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{}")) }))
	defer srv.Close()
	c := New([]string{"127.0.0.1"}, "test")
	_, _, err := c.Get(t.Context(), srv.URL, 1024, nil)
	if devLoopbackHTTP != (err == nil) {
		t.Fatalf("dev build %v: %v", devLoopbackHTTP, err)
	}
	if !devLoopbackHTTP && !errors.Is(err, ErrNotAllowed) {
		t.Errorf("want ErrNotAllowed, got %v", err)
	}
	// Never to a loopback host that isn't on the allowlist.
	if _, _, err := New([]string{"api.osv.dev"}, "test").Get(t.Context(), srv.URL, 1024, nil); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("unlisted loopback: %v", err)
	}
}
