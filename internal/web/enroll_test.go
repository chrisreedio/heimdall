// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/secret"
	"github.com/realmwatch/heimdall/internal/store"
)

func TestEnrollPage(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.IngestURL, c.Version = "https://ingest.example.com", "v0.4.0"
	})
	e.seed()
	ctx := t.Context()
	w := e.get("/hosts/enroll", signedIn(e))
	if body := w.Body.String(); w.Code != http.StatusOK || !strings.Contains(body, "Create key") ||
		!regexp.MustCompile(`name="approval" value="1" checked`).MatchString(body) || !strings.Contains(body, `<option value="24h" selected>`) {
		t.Fatalf("form: %d\n%s", w.Code, body)
	}

	csrf := auth.CSRFToken(goodToken)
	f := url.Values{"csrf": {csrf}, "env": {"acme/prod"}, "tags": {"web"}, "label": {"rollout"}, "expires": {"7d"}, "uses": {"5"}, "approval": {"1"}}
	w = e.post("/hosts/enroll", f, signedIn(e), origin(e.baseURL))
	body := w.Body.String()
	m := regexp.MustCompile(`<code id="enroll-key">(hmd_enroll_[A-Za-z0-9_-]+)</code>`).FindStringSubmatch(body)
	if w.Code != http.StatusOK || m == nil {
		t.Fatalf("create: %d\n%s", w.Code, body)
	}
	key := m[1]
	// Shown once, and in the cloud-init user data; never in a command
	// that's typed into a shell.
	if n := strings.Count(body, key); n != 2 {
		t.Errorf("key appears %d times, want 2 (the key and cloud-init)", n)
	}
	cloud := regexp.MustCompile(`(?s)<pre id="cmd-cloud">(.*?)</pre>`).FindStringSubmatch(body)
	if cloud == nil || !strings.Contains(cloud[1], key) || !strings.Contains(cloud[1], "--enroll-stdin") {
		t.Errorf("cloud-init: %q", cloud)
	}
	for _, id := range []string{"cmd-each", "cmd-many", "cmd-win"} {
		cmd := regexp.MustCompile(`(?s)<pre id="` + id + `">(.*?)</pre>`).FindStringSubmatch(body)
		if cmd == nil || strings.Contains(cmd[1], key) || !strings.Contains(strings.ToLower(cmd[1]), "-enroll") {
			t.Errorf("%s: %q", id, cmd)
		}
	}
	if !strings.Contains(body, "releases/download/v0.4.0/install.sh &amp;&amp; sudo sh install.sh --hub https://ingest.example.com --enroll") {
		t.Errorf("each-server command missing:\n%s", body)
	}
	if strings.Contains(body, "127.0.0.1:8080/install") {
		t.Error("install command must never point at the hub")
	}
	keys, _ := e.st.ListEnrollKeys(ctx, "acme")
	if len(keys) != 1 || !keys[0].Approval || keys[0].MaxUses != 5 || keys[0].Label != "rollout" ||
		keys[0].ExpiresAt.Sub(keys[0].CreatedAt) != 7*24*time.Hour {
		t.Fatalf("keys = %+v", keys)
	}
	// The page lists it afterwards, without the secret.
	if body := e.get("/hosts/enroll", signedIn(e)).Body.String(); !strings.Contains(body, "rollout") || strings.Contains(body, key) {
		t.Error("key list")
	}

	// A server enrolls and waits for approval.
	got, err := e.st.EnrollHost(ctx, secret.Hash(key), "web-05", "", "192.0.2.7", testNow)
	if err != nil || !got.Awaiting {
		t.Fatalf("enroll: %+v %v", got, err)
	}
	body = e.get("/hosts/enroll", signedIn(e)).Body.String()
	if !strings.Contains(body, "Waiting for approval") || !strings.Contains(body, "web-05") || !strings.Contains(body, "192.0.2.7") {
		t.Errorf("waiting list:\n%s", body)
	}
	if body := e.get("/hosts", signedIn(e)).Body.String(); !strings.Contains(body, "waiting for approval") {
		t.Error("hosts page lacks the waiting pill")
	}
	// Approving needs the CSRF token.
	if w := e.post("/hosts/enroll/approve", url.Values{"org": {"acme"}, "host": {"web-05"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusForbidden {
		t.Errorf("approve without CSRF: %d", w.Code)
	}
	w = e.post("/hosts/enroll/approve", url.Values{"csrf": {csrf}, "org": {"acme"}, "host": {"web-05"}}, signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "web-05 is approved") {
		t.Fatalf("approve: %d", w.Code)
	}
	if h, _ := e.st.HostByToken(ctx, secret.Hash(got.Token)); h.Awaiting {
		t.Error("still waiting after approval")
	}
	// Reject removes the host; a host not waiting can't be rejected.
	got2, _ := e.st.EnrollHost(ctx, secret.Hash(key), "web-06", "", "", testNow)
	if w := e.post("/hosts/enroll/reject", url.Values{"csrf": {csrf}, "org": {"acme"}, "host": {"web-05"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusBadRequest {
		t.Errorf("reject approved host: %d", w.Code)
	}
	if w := e.post("/hosts/enroll/reject", url.Values{"csrf": {csrf}, "org": {"acme"}, "host": {"web-06"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusOK {
		t.Errorf("reject: %d", w.Code)
	}
	if _, err := e.st.HostByToken(ctx, secret.Hash(got2.Token)); err == nil {
		t.Error("rejected host's token still works")
	}

	// Revoke.
	if w := e.post("/hosts/enroll/revoke", url.Values{"csrf": {csrf}, "org": {"acme"}, "id": {"1"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Errorf("revoke: %d", w.Code)
	}
	if keys, _ := e.st.ListEnrollKeys(ctx, "acme"); keys[0].Status(testNow) != "revoked" {
		t.Errorf("status after revoke: %s", keys[0].Status(testNow))
	}

	// Only org admins; others don't learn the page exists.
	orgs, _ := e.st.ListOrgs(ctx)
	e.auth.viewer = &auth.Viewer{UserID: 1, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{orgs[0].ID: store.RoleOperator}}}
	if w := e.get("/hosts/enroll", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("operator: %d", w.Code)
	}
	for _, p := range []string{"/hosts/enroll", "/hosts/enroll/approve", "/hosts/enroll/reject", "/hosts/enroll/revoke"} {
		f := url.Values{"csrf": {csrf}, "env": {"acme/prod"}, "expires": {"1h"}, "org": {"acme"}, "host": {"web-05"}, "id": {"1"}}
		if w := e.post(p, f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
			t.Errorf("operator %s: %d", p, w.Code)
		}
	}
}

func TestEnrollForm(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, nil)
	e.seed()
	csrf := auth.CSRFToken(goodToken)
	// Unchecked approval, and bad input kept on the form.
	f := url.Values{"csrf": {csrf}, "env": {"acme/prod"}, "expires": {"24h"}, "uses": {"many"}, "label": {"x"}}
	w := e.post("/hosts/enroll", f, signedIn(e), origin(e.baseURL))
	if body := w.Body.String(); w.Code != http.StatusBadRequest || !strings.Contains(body, "whole number") ||
		strings.Contains(body, `name="approval" value="1" checked`) || !strings.Contains(body, `value="many"`) {
		t.Errorf("bad uses: %d", w.Code)
	}
	f.Set("uses", "")
	if w := e.post("/hosts/enroll", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusOK {
		t.Fatalf("no approval: %d", w.Code)
	}
	if keys, _ := e.st.ListEnrollKeys(t.Context(), "acme"); len(keys) != 1 || keys[0].Approval || keys[0].MaxUses != 0 {
		t.Errorf("keys = %+v", keys)
	}
	f.Set("expires", "forever")
	if w := e.post("/hosts/enroll", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusBadRequest {
		t.Errorf("bad expiry: %d", w.Code)
	}
}

func TestExpiresIn(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	for d, want := range map[time.Duration]string{
		30 * time.Second: "in 1 minute", 10 * time.Minute: "in 11 minutes", 23 * time.Hour: "in 23 hours", time.Hour: "in 1 hour",
	} {
		if got := string(expiresIn(now.Add(d), now)); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
}
