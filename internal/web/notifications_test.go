// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
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

type fakePush struct{ tests []int64 }

func (f *fakePush) PublicKey(context.Context) (string, error) { return "BPUBLICKEY_test", nil }
func (f *fakePush) Test(_ context.Context, uid int64) (int, error) {
	f.tests = append(f.tests, uid)
	return 1, nil
}

// pushEnv is devicesEnv (the admin signed in on an iPhone) with push on.
func pushEnv(t *testing.T) (*env, *fakePush) {
	t.Helper()
	e := devicesEnv(t)
	fp := &fakePush{}
	h, err := New(Config{BaseURL: e.baseURL, Version: "test", SessionMax: 12 * time.Hour, SessionIdle: 30 * time.Minute, LocalLogin: true, Push: fp}, e.st, e.auth, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	return e, fp
}

func browserKeys(t *testing.T) (p256dh, secret string) {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := make([]byte, 16)
	rand.Read(a)
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), base64.RawURLEncoding.EncodeToString(a)
}

func (e *env) pushPost(path string, form url.Values) *httptest.ResponseRecorder {
	e.t.Helper()
	form.Set("csrf", auth.CSRFToken(goodToken))
	return e.post(path, form, signedIn(e), origin(e.baseURL))
}

func TestNotificationsPage(t *testing.T) {
	t.Parallel()
	e, _ := pushEnv(t)
	body := e.get("/account/notifications", signedIn(e)).Body.String()
	for _, want := range []string{`data-push-key="BPUBLICKEY_test"`, "Turn on notifications", "Known-exploited finding",
		"Ban proposal", "Quiet hours", "10 PM", "7 AM", "Kind and host", "Hidden", `name="mode_fleet"`, `action="/account/notifications/subscribe"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, "Send a test notification") {
		t.Error("test button before this device is subscribed")
	}
	// More links to it.
	if !strings.Contains(e.get("/more", signedIn(e)).Body.String(), `href="/account/notifications"`) {
		t.Error("More doesn't link to Notifications")
	}
	// Viewers don't get ban proposals, so aren't offered them.
	e.auth.viewer = &auth.Viewer{UserID: 2, Email: "bob@example.com", Scope: store.Scope{Orgs: map[int64]store.Role{1: store.RoleViewer}}, SessionToken: goodToken}
	if strings.Contains(e.get("/account/notifications", signedIn(e)).Body.String(), "Ban proposal") {
		t.Error("viewer offered ban proposals")
	}
	// Signed out: to the sign-in page.
	if w := e.get("/account/notifications"); w.Code != http.StatusSeeOther {
		t.Errorf("signed out: %d", w.Code)
	}
	// Without push set up, it says so.
	e2 := devicesEnv(t)
	if !strings.Contains(e2.get("/account/notifications", signedIn(e2)).Body.String(), "aren't available on this hub") {
		t.Error("no push: page doesn't say so")
	}
}

func TestPushSubscribe(t *testing.T) {
	t.Parallel()
	e, fp := pushEnv(t)
	ctx := t.Context()
	p256dh, secret := browserKeys(t)
	form := func(endpoint string) url.Values {
		return url.Values{"endpoint": {endpoint}, "p256dh": {p256dh}, "auth": {secret}, "tz": {"America/Chicago"}}
	}
	// CSRF and Origin are checked like any form.
	bad := form("https://fcm.googleapis.com/fcm/send/abc")
	bad.Set("csrf", "nope")
	if w := e.post("/account/notifications/subscribe", bad, signedIn(e), origin(e.baseURL)); w.Code != http.StatusForbidden {
		t.Errorf("bad CSRF: %d", w.Code)
	}
	good := form("https://fcm.googleapis.com/fcm/send/abc")
	good.Set("csrf", auth.CSRFToken(goodToken))
	if w := e.post("/account/notifications/subscribe", good, signedIn(e), origin("https://evil.example.com")); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin: %d", w.Code)
	}
	if w := e.post("/account/notifications/subscribe", good); w.Code != http.StatusForbidden {
		t.Errorf("signed out: %d", w.Code)
	}
	// Endpoints off the push services' list are refused.
	for _, ep := range []string{"http://fcm.googleapis.com/x", "https://169.254.169.254/latest", "https://intranet.example.com/hook", "https://10.0.0.5/x"} {
		if w := e.pushPost("/account/notifications/subscribe", form(ep)); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", ep, w.Code)
		}
	}
	// Bad keys too.
	f := form("https://fcm.googleapis.com/fcm/send/abc")
	f.Set("p256dh", "AAAA")
	if w := e.pushPost("/account/notifications/subscribe", f); w.Code != http.StatusBadRequest {
		t.Errorf("bad keys: %d", w.Code)
	}
	if subs, _ := e.st.UserPushSubscriptions(ctx, 1); len(subs) != 0 {
		t.Fatalf("refused subscriptions stored: %+v", subs)
	}

	w := e.pushPost("/account/notifications/subscribe", form("https://web.push.apple.com/QGuQyavXutnMH4J"))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account/notifications?ok=on" {
		t.Fatalf("subscribe: %d %s", w.Code, w.Body)
	}
	subs, _ := e.st.UserPushSubscriptions(ctx, 1)
	if len(subs) != 1 || subs[0].Endpoint != "https://web.push.apple.com/QGuQyavXutnMH4J" {
		t.Fatalf("stored %+v", subs)
	}
	if p, _ := e.st.PushSettings(ctx, 1); p.TimeZone != "America/Chicago" {
		t.Errorf("time zone %q", p.TimeZone)
	}
	body := e.get("/account/notifications?ok=on", signedIn(e)).Body.String()
	if !strings.Contains(body, "Notifications are on for this device") || !strings.Contains(body, "Send a test notification") {
		t.Error("page doesn't show this device on")
	}

	// The test button only queues.
	if w := e.pushPost("/account/notifications/test", url.Values{}); w.Code != http.StatusSeeOther || len(fp.tests) != 1 || fp.tests[0] != 1 {
		t.Errorf("test: %d %v", w.Code, fp.tests)
	}

	// Turning it off removes this session's subscription.
	if w := e.pushPost("/account/notifications/unsubscribe", url.Values{}); w.Code != http.StatusSeeOther {
		t.Fatalf("unsubscribe: %d", w.Code)
	}
	if subs, _ := e.st.UserPushSubscriptions(ctx, 1); len(subs) != 0 {
		t.Errorf("still subscribed: %+v", subs)
	}

	// Revoking the device removes it too.
	e.pushPost("/account/notifications/subscribe", form("https://fcm.googleapis.com/fcm/send/abc"))
	e.pushPost("/account/devices/revoke", url.Values{"ref": {ref(goodToken)}})
	if subs, _ := e.st.UserPushSubscriptions(ctx, 1); len(subs) != 0 {
		t.Errorf("revoked device still subscribed: %+v", subs)
	}
}

func TestPushSettingsForm(t *testing.T) {
	t.Parallel()
	e, _ := pushEnv(t)
	ctx := t.Context()
	f := url.Values{"mode_kev": {"immediate"}, "mode_anomaly": {"off"}, "mode_silent": {"digest"}, "mode_fleet": {"off"},
		"quiet": {"1"}, "quiet_start": {"21"}, "quiet_end": {"6"}, "tz": {"America/Denver"}, "detail": {"hidden"}}
	if w := e.pushPost("/account/notifications/settings", f); w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	p, _ := e.st.PushSettings(ctx, 1)
	if p.Modes["anomaly"] != "off" || p.Modes["silent"] != "digest" || p.Modes["fleet"] != "off" || p.Modes["kev"] != "" ||
		p.QuietStart != 21 || p.QuietEnd != 6 || !p.Quiet || p.TimeZone != "America/Denver" || p.Detail != "hidden" {
		t.Errorf("saved %+v", p)
	}
	for name, bad := range map[string]url.Values{
		"mode":  {"mode_fleet": {"immediate"}, "quiet_start": {"22"}, "quiet_end": {"7"}},
		"hour":  {"quiet_start": {"24"}, "quiet_end": {"7"}},
		"zone":  {"quiet_start": {"22"}, "quiet_end": {"7"}, "tz": {"Mars/Olympus"}},
		"blank": {},
	} {
		if w := e.pushPost("/account/notifications/settings", bad); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if got, _ := e.st.PushSettings(ctx, 1); got.Modes["fleet"] != "off" || got.QuietStart != 21 {
		t.Errorf("a refused form changed settings: %+v", got)
	}
}

// The service worker shows pushed notifications with the hub's icon and
// opens only the hub's own pages.
func TestServiceWorkerPush(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "https://hub.example-tailnet.ts.net", nil)
	body := e.get("/sw.js").Body.String()
	for _, want := range []string{`addEventListener("push"`, `addEventListener("notificationclick"`, "showNotification",
		`var ICON = "/static/icon-192.png?v=test";`, `var BADGE = "/static/badge-96.png?v=test";`, "openWindow"} {
		if !strings.Contains(body, want) {
			t.Errorf("sw.js lacks %s", want)
		}
	}
	if strings.Contains(body, "__ICON__") || strings.Contains(body, "__BADGE__") {
		t.Error("sw.js not filled in")
	}
	if w := e.get("/static/badge-96.png"); w.Code != http.StatusOK {
		t.Errorf("badge: %d", w.Code)
	}
}
