// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

// keepAuth records whether sign-ins asked for a device session.
type keepAuth struct {
	fakeAuth
	kept []bool
}

func (k *keepAuth) Login(ctx context.Context, email, password, code, ip, ua string, keep bool) (string, error) {
	k.kept = append(k.kept, keep)
	return k.fakeAuth.Login(ctx, email, password, code, ip, ua, keep)
}

// "Keep me signed in on this device" asks for a device session and sets a
// 30-day cookie; without it the cookie lasts ui.session_max.
func TestKeepSignedIn(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	ka := &keepAuth{}
	h, err := New(Config{BaseURL: e.baseURL, Version: "test", SessionMax: 12 * time.Hour, LocalLogin: true}, e.st, ka, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	if !strings.Contains(e.get("/login").Body.String(), `name="keep"`) {
		t.Error("sign-in page has no keep box")
	}
	for _, keep := range []bool{false, true} {
		form := url.Values{"email": {"admin@example.com"}, "password": {"correct horse"}, "totp": {"123456"}}
		if keep {
			form.Set("keep", "on")
		}
		w := e.post("/login", form, origin(e.baseURL))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("keep=%v: %d", keep, w.Code)
		}
		c := w.Result().Cookies()[0]
		want := int((12 * time.Hour).Seconds())
		if keep {
			want = int(auth.DeviceSessionMax.Seconds())
		}
		if c.MaxAge != want || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
			t.Errorf("keep=%v: cookie %+v", keep, c)
		}
	}
	if len(ka.kept) != 2 || ka.kept[0] || !ka.kept[1] {
		t.Errorf("Login keep: %v", ka.kept)
	}
	// A device session that was renewed gets its cookie renewed too.
	ka.viewer = &auth.Viewer{UserID: 1, Email: "admin@example.com", IsAdmin: true, Scope: store.AllScope, SessionToken: goodToken, Kept: true, Renewed: true}
	w := e.get("/", signedIn(e))
	if cs := w.Result().Cookies(); len(cs) != 1 || cs[0].MaxAge != int(auth.DeviceSessionMax.Seconds()) || cs[0].Value != goodToken {
		t.Errorf("renewal cookie: %+v", cs)
	}
}

// devicesEnv: the admin (user 1, signed in with goodToken) on an iPhone
// and a laptop, and bob on Android.
func devicesEnv(t *testing.T) *env {
	t.Helper()
	e := adminEnvCfg(t, func(c *Config) { c.SessionIdle = 30 * time.Minute })
	ctx := t.Context()
	iphone := "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
	for _, s := range []struct {
		token string
		user  int64
		ua    string
		kept  bool
		seen  time.Duration
	}{
		{goodToken, 1, iphone, true, 0},
		{"laptop", 1, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 Edg/130.0", false, 0},
		{"stale", 1, "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0", false, -time.Hour}, // idle past ui.session_idle
		{"bob-phone", 2, "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36", true, 0},
	} {
		create := e.st.CreateSession
		if s.kept {
			create = e.st.CreateDeviceSession
		}
		at := testNow.Add(s.seen)
		if err := create(ctx, sha256.Sum256([]byte(s.token)), s.user, at, at.Add(30*24*time.Hour), "100.64.0.1", s.ua); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func ref(token string) string { return store.SessionRef(sha256.Sum256([]byte(token))) }

func TestDevicesPage(t *testing.T) {
	t.Parallel()
	e := devicesEnv(t)
	body := e.get("/account/devices", signedIn(e)).Body.String()
	for _, want := range []string{"iPhone Safari", "this device", "kept signed in", "Windows Edge", ref("laptop")} {
		if !strings.Contains(body, want) {
			t.Errorf("devices page lacks %q", want)
		}
	}
	// Only your own live sessions: not bob's, not one idle past the limit.
	for _, not := range []string{"Android", ref("bob-phone"), "Linux Firefox"} {
		if strings.Contains(body, not) {
			t.Errorf("devices page shows %q", not)
		}
	}

	// Revoking another of your sessions ends it; someone else's ref does nothing.
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		form.Set("csrf", auth.CSRFToken(goodToken))
		return e.post(path, form, signedIn(e), origin(e.baseURL))
	}
	if w := post("/account/devices/revoke", url.Values{"ref": {ref("bob-phone")}}); w.Code != http.StatusSeeOther {
		t.Fatalf("revoke bob's: %d", w.Code)
	}
	if _, _, err := e.st.SessionByHash(t.Context(), sha256.Sum256([]byte("bob-phone"))); err != nil {
		t.Error("a user revoked someone else's session")
	}
	if w := post("/account/devices/revoke", url.Values{"ref": {ref("laptop")}}); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account/devices?ok=revoked" {
		t.Fatalf("revoke: %d %s", w.Code, w.Header().Get("Location"))
	}
	if _, _, err := e.st.SessionByHash(t.Context(), sha256.Sum256([]byte("laptop"))); err == nil {
		t.Error("revoked session still there")
	}
	// Revoking the one in use signs out here.
	w := post("/account/devices/revoke", url.Values{"ref": {ref(goodToken)}})
	if w.Header().Get("Location") != "/login" || w.Result().Cookies()[0].MaxAge >= 0 {
		t.Errorf("revoking this device: %s %+v", w.Header().Get("Location"), w.Result().Cookies())
	}
}

// Admins see everyone's sessions on Users and can end any of them.
func TestAdminSessions(t *testing.T) {
	t.Parallel()
	e := devicesEnv(t)
	body := e.get("/admin/users", signedIn(e)).Body.String()
	if !strings.Contains(body, "Android Chrome") || !strings.Contains(body, ref("bob-phone")) || !strings.Contains(body, "iPhone Safari (this one)") {
		t.Error("Users page doesn't list sessions")
	}
	w := e.adminPost("session-revoke", url.Values{"user": {"2"}, "ref": {ref("bob-phone")}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/users?ok=session-revoked" {
		t.Fatalf("admin revoke: %d", w.Code)
	}
	if _, _, err := e.st.SessionByHash(t.Context(), sha256.Sum256([]byte("bob-phone"))); err == nil {
		t.Error("bob's session survived")
	}
	if at, _ := e.st.LastAuditAt(t.Context(), "session.revoke"); at.IsZero() {
		t.Error("not audited")
	}
	// Not for non-admins.
	e.auth.viewer = &auth.Viewer{UserID: 2, Email: "bob@example.com", Scope: store.Scope{Orgs: map[int64]store.Role{1: store.RoleAdmin}}, SessionToken: goodToken}
	if w := e.adminPost("session-revoke", url.Values{"user": {"1"}, "ref": {ref("laptop")}}); w.Code != http.StatusNotFound {
		t.Errorf("non-admin: %d", w.Code)
	}
}
