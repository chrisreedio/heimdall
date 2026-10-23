// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build dev

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func (f *fakeAuth) DevLogin(_ context.Context, email, ip, ua string) (string, error) {
	f.devLogins = append(f.devLogins, email+"@"+ip)
	return goodToken, nil
}

func TestDevLogin(t *testing.T) {
	t.Setenv("HEIMDALL_DEV_DIR", ".")
	t.Setenv("HEIMDALL_DEV_LOGIN", "tester@example.com")
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	if body := e.get("/login").Body.String(); !strings.Contains(body, "Sign in as tester@example.com") {
		t.Fatal("dev sign-in button missing")
	}
	post := func(remote, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/_dev/login", strings.NewReader(url.Values{"next": {"/hosts"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		return w
	}
	if w := post("127.0.0.1:5555", "http://127.0.0.1:8080"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/hosts" || len(w.Result().Cookies()) != 1 {
		t.Fatalf("loopback sign-in: %d %v", w.Code, w.Header())
	}
	if w := post("100.64.1.2:5555", "http://127.0.0.1:8080"); w.Code != http.StatusForbidden {
		t.Errorf("non-loopback client: %d", w.Code)
	}
	if w := post("127.0.0.1:5555", "https://evil.example"); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin: %d", w.Code)
	}
	if len(e.auth.devLogins) != 1 {
		t.Errorf("dev logins = %v", e.auth.devLogins)
	}
	// Not offered when the UI isn't on loopback.
	e2 := newEnv(t, "https://hub.example.ts.net", nil)
	if strings.Contains(e2.get("/login").Body.String(), "Sign in as") {
		t.Error("dev sign-in offered on a non-loopback UI")
	}
}
