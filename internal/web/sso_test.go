// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/sha256"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/auth/entra"
	"github.com/realmwatch/heimdall/internal/store"
)

type fakeSSO struct {
	n        int
	last     entra.AuthRequest
	finishes int
}

func (f *fakeSSO) Begin(context.Context) (entra.AuthRequest, error) {
	f.n++
	f.last = entra.AuthRequest{
		State: fmt.Sprintf("state-%d", f.n), Nonce: fmt.Sprintf("nonce-%d", f.n), Verifier: fmt.Sprintf("verifier-%d", f.n),
	}
	f.last.URL = "https://login.microsoftonline.com/authorize?state=" + f.last.State
	return f.last, nil
}

func (f *fakeSSO) Finish(_ context.Context, code, verifier, nonce string) (entra.Identity, error) {
	f.finishes++
	// The handler must hand back exactly what Begin produced.
	if verifier != f.last.Verifier || nonce != f.last.Nonce {
		return entra.Identity{}, fmt.Errorf("%w: wrong verifier or nonce", entra.ErrInvalidToken)
	}
	switch code {
	case "good":
		return entra.Identity{TenantID: "t", ObjectID: "oid-1", Email: "alice@example.com", Name: "Alice", Roles: []string{"Heimdall.Viewer"}}, nil
	case "nobody":
		return entra.Identity{TenantID: "t", ObjectID: "unprovisioned", Email: "eve@example.com"}, nil
	case "badsecret":
		return entra.Identity{}, fmt.Errorf("entra: exchange: %w", &entra.TokenError{Status: http.StatusUnauthorized,
			Code: "invalid_client", Codes: []int{7000215}, Description: "Invalid client secret provided."})
	}
	return entra.Identity{}, fmt.Errorf("%w: bad signature", entra.ErrInvalidToken)
}

func newSSOEnv(t *testing.T, local bool) (*env, *fakeSSO) {
	sso := &fakeSSO{}
	e := newEnvCfg(t, "https://heimdall.example.com", nil, func(c *Config) {
		c.SSO, c.LocalLogin = sso, local
	})
	return e, sso
}

// begin starts a sign-in and returns the state Microsoft would echo back.
func (e *env) begin(next string) string {
	e.t.Helper()
	w := e.get("/auth/entra/login?next=" + url.QueryEscape(next))
	if w.Code != http.StatusSeeOther {
		e.t.Fatalf("begin: status %d", w.Code)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || loc.Host != "login.microsoftonline.com" {
		e.t.Fatalf("begin redirected to %q", w.Header().Get("Location"))
	}
	return loc.Query().Get("state")
}

func TestSSOHappyPath(t *testing.T) {
	t.Parallel()
	e, _ := newSSOEnv(t, true)
	state := e.begin("/hosts?org=acme")
	w := e.get("/auth/callback?code=good&state=" + url.QueryEscape(state))
	if w.Code != http.StatusOK {
		t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	// A same-site hand-off page, not a redirect: SameSite=Strict cookies
	// set on a cross-site navigation must not depend on further redirects.
	if !strings.Contains(body, `http-equiv="refresh"`) || !strings.Contains(body, `url=/hosts?org=acme`) {
		t.Errorf("no meta refresh to next: %s", body)
	}
	c := w.Result().Cookies()
	if len(c) != 1 || c[0].Name != "__Host-heimdall" || c[0].Value != goodToken || !c[0].Secure || !c[0].HttpOnly ||
		c[0].SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie = %+v", c)
	}
	if ids := e.auth.identities; len(ids) != 1 || ids[0].ObjectID != "oid-1" || ids[0].Email != "alice@example.com" {
		t.Errorf("identities = %+v", ids)
	}
	if strings.Contains(body, "<script>") && !strings.Contains(body, `src="/static/app.js`) {
		t.Error("inline script on hand-off page")
	}
}

func TestSSOStateIsSingleUseAndBound(t *testing.T) {
	t.Parallel()
	e, _ := newSSOEnv(t, true)
	state := e.begin("/")
	if w := e.get("/auth/callback?code=good&state=" + url.QueryEscape(state)); w.Code != http.StatusOK {
		t.Fatalf("first use: %d", w.Code)
	}
	w := e.get("/auth/callback?code=good&state=" + url.QueryEscape(state))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Sign-in expired") {
		t.Errorf("replayed state: %d", w.Code)
	}
	for _, q := range []string{"code=good&state=forged", "code=good", "state=" + strings.Repeat("x", 600)} {
		if w := e.get("/auth/callback?" + q); w.Code != http.StatusBadRequest || len(w.Result().Cookies()) != 0 {
			t.Errorf("%s: status %d cookies %v", q, w.Code, w.Result().Cookies())
		}
	}
}

func TestSSOExpiredState(t *testing.T) {
	t.Parallel()
	e, _ := newSSOEnv(t, true)
	// Store a request that is older than the TTL.
	if err := e.st.PutAuthRequest(t.Context(), sha("old"), store.AuthRequest{Nonce: "n", Verifier: "v",
		ReturnTo: "/", CreatedAt: testNow.Add(-ssoRequestTTL - 1)}); err != nil {
		t.Fatal(err)
	}
	if w := e.get("/auth/callback?code=good&state=old"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Sign-in expired") {
		t.Errorf("expired: %d", w.Code)
	}
}

func TestSSOFailures(t *testing.T) {
	t.Parallel()
	e, sso := newSSOEnv(t, true)

	state := e.begin("/")
	w := e.get("/auth/callback?code=nobody&state=" + url.QueryEscape(state))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "hasn&#39;t been set up") {
		t.Errorf("not provisioned: %d %s", w.Code, w.Body.String())
	}

	state = e.begin("/")
	w = e.get("/auth/callback?code=forged&state=" + url.QueryEscape(state))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Sign-in failed") ||
		strings.Contains(w.Body.String(), "bad signature") {
		t.Errorf("invalid token: %d", w.Code)
	}

	// Entra reports an error (e.g. the user cancelled): shown generically,
	// and the state is consumed.
	before := sso.finishes
	state = e.begin("/")
	w = e.get("/auth/callback?error=access_denied&error_description=" + url.QueryEscape("<b>evil</b>") + "&state=" + url.QueryEscape(state))
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "evil") || sso.finishes != before {
		t.Errorf("idp error: %d finishes %d", w.Code, sso.finishes-before)
	}
	if w := e.get("/auth/callback?code=good&state=" + url.QueryEscape(state)); w.Code != http.StatusBadRequest {
		t.Errorf("state reused after an error: %d", w.Code)
	}
}

// Microsoft's sign-in errors tell the person what to do, with the AADSTS
// code to pass on, and never echo Microsoft's text or anything else from
// the query.
func TestSSOErrorMessages(t *testing.T) {
	t.Parallel()
	e, _ := newSSOEnv(t, true)
	for _, tc := range []struct {
		query, want string
	}{
		{"error=access_denied&error_description=" + url.QueryEscape("AADSTS65004: User declined to consent to access the app.\r\nTrace ID: 1"),
			"Your organization needs an administrator to approve Heimdall before you can sign in. Ask your Microsoft 365 admin to grant consent for the Heimdall app. Error AADSTS65004."},
		{"error=access_denied&error_description=" + url.QueryEscape("AADSTS50105: Your administrator has configured the application to block users unless they are specifically granted access."),
			"Your account hasn't been given access to Heimdall in Microsoft Entra. Ask your admin to assign you to the app. Error AADSTS50105."},
		{"error=invalid_request&error_description=" + url.QueryEscape("AADSTS12345678: Something new."),
			"Sign-in failed. Try again, or ask an admin to check the server log. Error AADSTS12345678."},
		{"error=access_denied", "Sign-in failed. Try again, or ask an admin to check the server log."},
		{"code=badsecret", "Heimdall's sign-in is misconfigured. Tell your Heimdall admin; the details are in the hub log. Error AADSTS7000215."},
	} {
		state := e.begin("/")
		w := e.get("/auth/callback?" + tc.query + "&state=" + url.QueryEscape(state))
		body := html.UnescapeString(w.Body.String())
		if w.Code != http.StatusUnauthorized || !strings.Contains(body, tc.want) {
			t.Errorf("%s: %d, want %q in %s", tc.query, w.Code, tc.want, body)
		}
		for _, leak := range []string{"declined to consent", "specifically granted", "Something new", "Invalid client secret", "Trace ID", "badsecret"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s: page shows %q", tc.query, leak)
			}
		}
	}

	// Injected markup, before or after a code, is never echoed.
	for _, desc := range []string{"<script>alert(1)</script>", "AADSTS65004<script>alert(1)</script>",
		"AADSTS65004: <script>alert(1)</script>", "AADSTS1234567890123: x"} {
		state := e.begin("/")
		w := e.get("/auth/callback?error=" + url.QueryEscape("<script>x</script>") + "&error_description=" + url.QueryEscape(desc) + "&state=" + url.QueryEscape(state))
		if b := w.Body.String(); w.Code != http.StatusUnauthorized || strings.Contains(b, "<script>") || strings.Contains(b, "script&gt;") || strings.Contains(b, "alert(1)") ||
			strings.Contains(b, "1234567890123") {
			t.Errorf("%q: %d %s", desc, w.Code, b)
		}
	}
}

func TestSSONextIsSanitized(t *testing.T) {
	t.Parallel()
	e, _ := newSSOEnv(t, true)
	for _, next := range []string{"//evil.com", "https://evil.com/", "/\\evil.com", "javascript:alert(1)"} {
		state := e.begin(next)
		w := e.get("/auth/callback?code=good&state=" + url.QueryEscape(state))
		if !strings.Contains(w.Body.String(), `content="0;url=/"`) || strings.Contains(w.Body.String(), "evil") {
			t.Errorf("next %q leaked into hand-off: %s", next, w.Body.String())
		}
	}
}

func TestLoginMethods(t *testing.T) {
	t.Parallel()
	// SSO only: no password form, POST /login refused.
	e, _ := newSSOEnv(t, false)
	body := e.get("/login").Body.String()
	if !strings.Contains(body, "Sign in with Microsoft") || strings.Contains(body, `name="password"`) {
		t.Errorf("SSO-only login page: %s", body)
	}
	w := e.post("/login", url.Values{"email": {"admin@example.com"}, "password": {"correct horse"}, "code": {"123456"}},
		origin("https://heimdall.example.com"))
	if w.Code != http.StatusNotFound || len(w.Result().Cookies()) != 0 {
		t.Errorf("POST /login with local login off: %d", w.Code)
	}

	// Local only: no SSO button, SSO routes don't exist.
	e = newEnv(t, "http://127.0.0.1:8080", nil)
	body = e.get("/login").Body.String()
	if strings.Contains(body, "Sign in with Microsoft") || !strings.Contains(body, `name="password"`) {
		t.Errorf("local-only login page: %s", body)
	}
	if w := e.get("/auth/entra/login"); w.Code != http.StatusNotFound {
		t.Errorf("SSO route without SSO: %d", w.Code)
	}

	// Neither.
	e = newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.LocalLogin = false })
	if !strings.Contains(e.get("/login").Body.String(), "No sign-in method is configured") {
		t.Error("no-method message missing")
	}
}

func sha(s string) [32]byte { return sha256.Sum256([]byte(s)) }
