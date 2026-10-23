// SPDX-License-Identifier: AGPL-3.0-or-later

package netx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAllowlist(t *testing.T) {
	c := New([]string{"api.osv.dev"}, "test")
	for _, url := range []string{
		"http://api.osv.dev/v1/query", // not HTTPS
		"https://evil.example.com/",   // not allowlisted
		"https://api.osv.dev.evil.example.com/",
		"https://127.0.0.1/",
	} {
		_, _, err := c.Get(t.Context(), url, 1<<10, nil)
		if !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: want ErrNotAllowed, got %v", url, err)
		}
	}
}

func TestSizeLimitAndStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			w.Write([]byte(strings.Repeat("x", 2048)))
		case "/missing":
			http.NotFound(w, r)
		default:
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()
	c := NewForTest(srv.Client())

	if _, _, err := c.Get(t.Context(), srv.URL+"/big", 1024, nil); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("big: %v", err)
	}
	var se *StatusError
	if _, _, err := c.Get(t.Context(), srv.URL+"/missing", 1024, nil); !errors.As(err, &se) || se.Status != 404 {
		t.Errorf("missing: %v", err)
	}
	var out struct{ OK bool }
	if err := c.GetJSON(t.Context(), srv.URL+"/", 1024, &out); err != nil || !out.OK {
		t.Errorf("json: %v %+v", err, out)
	}
}

func TestRedirectOutsideAllowlist(t *testing.T) {
	// A redirect target is checked like any other request.
	c := New([]string{"api.osv.dev"}, "test")
	req, _ := http.NewRequest(http.MethodGet, "https://evil.example.com/", nil)
	if err := c.hc.CheckRedirect(req, []*http.Request{{}}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("redirect: %v", err)
	}
}
