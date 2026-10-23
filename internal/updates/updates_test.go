// SPDX-License-Identifier: AGPL-3.0-or-later

package updates

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chrisreedio/heimdall/internal/netx"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"v0.5.0", "v0.4.9", true}, {"v0.10.0", "v0.9.0", true}, {"v1.0.0", "v0.99.99", true},
		{"v0.4.0", "v0.4.0", false}, {"v0.3.9", "v0.4.0", false}, {"v0.5.0", "dev", false}, {"latest", "v0.4.0", false}} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

func TestCheck(t *testing.T) {
	body := `{"tag_name":"v0.5.0","html_url":"https://github.com/chrisreedio/heimdall/releases/tag/v0.5.0"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
	defer srv.Close()
	c := &Checker{HTTP: netx.NewForTest(srv.Client()), URL: srv.URL, Current: "v0.4.0"}
	if err := c.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r, ok := c.Available(); !ok || r.Version != "v0.5.0" {
		t.Fatalf("available = %+v %v", r, ok)
	}
	// A release page outside the repo is never offered.
	body = `{"tag_name":"v9.9.9","html_url":"https://evil.example/releases/v9.9.9"}`
	c = &Checker{HTTP: netx.NewForTest(srv.Client()), URL: srv.URL, Current: "v0.4.0"}
	c.Check(t.Context())
	if _, ok := c.Available(); ok {
		t.Error("foreign release URL accepted")
	}
	// Dev builds don't check.
	if (&Checker{Current: "v0.4.0-7-gabc"}).Enabled() {
		t.Error("dev build should not check")
	}
}
