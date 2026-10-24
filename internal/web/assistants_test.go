// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/store"
)

const testMCPURL = "https://hub.example.ts.net:8444"

var tokenRe = regexp.MustCompile(`hmd_mcp_[A-Za-z0-9_-]{43}`)

// mcpEnv has the admin (user 1) and bob (user 2, a viewer in acme), with
// MCP on unless disabled.
func mcpEnv(t *testing.T, enabled bool) *env {
	t.Helper()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.MCP = MCPSetup{Enabled: enabled, BaseURL: testMCPURL}
	})
	ctx := t.Context()
	secret := []byte("0123456789abcdefghij")
	if _, err := e.st.CreateLocalUser(ctx, "test", "admin@example.com", "Admin", true, "$argon2id$x", secret); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CreateLocalUser(ctx, "test", "bob@example.com", "Bob", false, "$argon2id$x", secret); err != nil {
		t.Fatal(err)
	}
	e.st.CreateOrg(ctx, "test", "acme", "Acme")
	e.st.Grant(ctx, "test", "bob@example.com", "acme", store.RoleViewer)
	return e
}

func (e *env) asBob() {
	e.auth.viewer = &auth.Viewer{UserID: 2, Email: "bob@example.com",
		Scope: store.Scope{Orgs: map[int64]store.Role{1: store.RoleViewer}}, SessionToken: goodToken}
}

func (e *env) formPost(path string, form url.Values) *httptest.ResponseRecorder {
	e.t.Helper()
	form.Set("csrf", auth.CSRFToken(goodToken))
	return e.post(path, form, signedIn(e), origin("http://127.0.0.1:8080"))
}

func (e *env) createToken(name string) (string, *httptest.ResponseRecorder) {
	e.t.Helper()
	w := e.formPost("/account/assistants", url.Values{"name": {name}})
	return tokenRe.FindString(w.Body.String()), w
}

func TestAssistantsCreateShowsTokenOnce(t *testing.T) {
	e := mcpEnv(t, true)
	e.asBob()
	page := e.get("/account/assistants", signedIn(e))
	body := page.Body.String()
	if page.Code != http.StatusOK || !strings.Contains(body, "No tokens yet") || tokenRe.MatchString(body) {
		t.Fatalf("empty page: %d", page.Code)
	}
	// Setup filled in with mcp.base_url; the Claude Code command keeps the
	// token out of shell history.
	for _, want := range []string{
		`href="/account/assistants"`, // the link beside the email
		testMCPURL + "/mcp", "read -rs HMD_TOKEN", `--header &#34;Authorization: Bearer $HMD_TOKEN&#34;`, "unset HMD_TOKEN",
		`Authorization:${AUTH_HEADER}`, "mcp-remote", `href="/account/assistants/heimdall.mcpb"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}

	token, w := e.createToken("MacBook Claude Desktop")
	if w.Code != http.StatusOK || token == "" || !strings.Contains(w.Body.String(), "You won't see it again") {
		t.Fatalf("create: %d token=%v", w.Code, token != "")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("token page is cacheable")
	}
	// The token works and belongs to bob.
	u, _, err := e.st.MCPTokenUser(t.Context(), sha256.Sum256([]byte(token)), testNow)
	if err != nil || u.ID != 2 {
		t.Fatalf("token user: %+v %v", u, err)
	}
	// Shown once: the next view lists it by name but not its value.
	again := e.get("/account/assistants", signedIn(e)).Body.String()
	if tokenRe.MatchString(again) || !strings.Contains(again, "MacBook Claude Desktop") || !strings.Contains(again, "never") {
		t.Error("token shown again, or not listed")
	}
	// Audited like the CLI.
	if !auditHas(t, e, "mcp_token.create") {
		t.Error("create not audited")
	}
}

func auditHas(t *testing.T, e *env, action string) bool {
	t.Helper()
	at, err := e.st.LastAuditAt(t.Context(), action)
	if err != nil {
		t.Fatal(err)
	}
	return !at.IsZero()
}

func TestAssistantsRevoke(t *testing.T) {
	e := mcpEnv(t, true)
	e.asBob()
	token, _ := e.createToken("laptop")
	ts, _ := e.st.ListMCPTokens(t.Context(), 2)
	id := strconv.FormatInt(ts[0].ID, 10)

	w := e.formPost("/account/assistants/revoke", url.Values{"id": {id}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account/assistants?ok=revoked" {
		t.Fatalf("revoke: %d %s", w.Code, w.Header().Get("Location"))
	}
	if _, _, err := e.st.MCPTokenUser(t.Context(), sha256.Sum256([]byte(token)), testNow); err == nil {
		t.Error("revoked token still works")
	}
	if !auditHas(t, e, "mcp_token.revoke") {
		t.Error("revoke not audited")
	}
	if body := e.get("/account/assistants?ok=revoked", signedIn(e)).Body.String(); strings.Contains(body, ">laptop<") ||
		!strings.Contains(body, "Token revoked") {
		t.Error("revoked token still listed")
	}
	// Twice: not found.
	if w := e.formPost("/account/assistants/revoke", url.Values{"id": {id}}); w.Code != http.StatusNotFound {
		t.Errorf("second revoke: %d", w.Code)
	}
}

func TestAssistantsCannotRevokeOthersTokens(t *testing.T) {
	e := mcpEnv(t, true)
	adminToken, adminID, err := e.st.CreateMCPToken(t.Context(), "test", 1, "admin laptop")
	if err != nil {
		t.Fatal(err)
	}
	e.asBob()
	if w := e.formPost("/account/assistants/revoke", url.Values{"id": {strconv.FormatInt(adminID, 10)}}); w.Code != http.StatusNotFound {
		t.Errorf("bob revoking the admin's token: %d", w.Code)
	}
	if _, _, err := e.st.MCPTokenUser(t.Context(), sha256.Sum256([]byte(adminToken)), testNow); err != nil {
		t.Error("another user's token was revoked")
	}
	// Bob's page doesn't list it.
	if strings.Contains(e.get("/account/assistants", signedIn(e)).Body.String(), "admin laptop") {
		t.Error("another user's token listed")
	}
	// Nor can bob use the admin route.
	if w := e.formPost("/admin/users/mcp-revoke", url.Values{"user": {"1"}, "id": {strconv.FormatInt(adminID, 10)}}); w.Code != http.StatusNotFound {
		t.Errorf("non-admin admin revoke: %d", w.Code)
	}
}

func TestAssistantsCSRFAndOrigin(t *testing.T) {
	e := mcpEnv(t, true)
	e.asBob()
	form := url.Values{"name": {"x"}}
	if w := e.post("/account/assistants", form, signedIn(e), origin("http://127.0.0.1:8080")); w.Code != http.StatusForbidden {
		t.Errorf("no CSRF: %d", w.Code)
	}
	form.Set("csrf", auth.CSRFToken(goodToken))
	if w := e.post("/account/assistants", form, signedIn(e), origin("https://evil.example.com")); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin: %d", w.Code)
	}
	if w := e.post("/account/assistants", form, origin("http://127.0.0.1:8080")); w.Code != http.StatusForbidden {
		t.Errorf("signed out: %d", w.Code)
	}
	if ts, _ := e.st.ListMCPTokens(t.Context(), 2); len(ts) != 0 {
		t.Error("a refused request created a token")
	}
	if w := e.get("/account/assistants"); w.Code != http.StatusSeeOther {
		t.Errorf("signed-out GET: %d", w.Code)
	}
}

func TestAssistantsCapAndRateLimit(t *testing.T) {
	e := mcpEnv(t, true)
	e.asBob()
	if _, w := e.createToken(""); w.Code != http.StatusBadRequest {
		t.Errorf("blank name: %d", w.Code)
	}
	for i := range tokenCreateLimit {
		if tok, w := e.createToken("t" + strconv.Itoa(i)); tok == "" {
			t.Fatalf("create %d: %d", i, w.Code)
		}
	}
	if tok, w := e.createToken("one too many"); w.Code != http.StatusTooManyRequests || tok != "" {
		t.Errorf("rate limit: %d", w.Code)
	}
	// The cap counts active tokens, however they were created.
	e = mcpEnv(t, true)
	e.asBob()
	for i := range maxMCPTokens {
		e.st.CreateMCPToken(t.Context(), "test", 2, "cli"+strconv.Itoa(i))
	}
	if tok, w := e.createToken("eleventh"); w.Code != http.StatusConflict || tok != "" {
		t.Errorf("cap: %d", w.Code)
	}
	if !strings.Contains(e.get("/account/assistants", signedIn(e)).Body.String(), "the most allowed") {
		t.Error("full page doesn't say so")
	}
}

func TestTokenLimiterWindow(t *testing.T) {
	var l tokenLimiter
	for range tokenCreateLimit {
		if !l.allow(7, testNow) {
			t.Fatal("refused under the limit")
		}
	}
	if l.allow(7, testNow) || !l.allow(8, testNow) {
		t.Error("limit isn't per user")
	}
	if !l.allow(7, testNow.Add(tokenCreateEvery)) {
		t.Error("limit doesn't expire")
	}
}

func TestAssistantsScopeAnyUser(t *testing.T) {
	// A user with no role anywhere can still manage tokens (they see
	// nothing through them, same as in the UI).
	e := mcpEnv(t, true)
	ctx := t.Context()
	id, err := e.st.CreateLocalUser(ctx, "test", "nobody@example.com", "", false, "$argon2id$x", []byte("0123456789abcdefghij"))
	if err != nil {
		t.Fatal(err)
	}
	e.auth.viewer = &auth.Viewer{UserID: id, Email: "nobody@example.com", SessionToken: goodToken}
	if w := e.get("/account/assistants", signedIn(e)); w.Code != http.StatusOK {
		t.Fatalf("no-role user: %d", w.Code)
	}
	if tok, _ := e.createToken("phone"); tok == "" {
		t.Error("no-role user couldn't create a token")
	}
}

func TestAssistantsDisabled(t *testing.T) {
	e := mcpEnv(t, false)
	// Admins get the "MCP is off" note with the config to turn it on.
	w := e.get("/account/assistants", signedIn(e))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "MCP is off on this hub") ||
		!strings.Contains(w.Body.String(), "enabled  = true") {
		t.Errorf("admin, disabled: %d", w.Code)
	}
	if strings.Contains(w.Body.String(), `class="who-link"`) {
		t.Error("link shown while MCP is off")
	}
	if !strings.Contains(e.get("/admin/users", signedIn(e)).Body.String(), "AI assistants (MCP) are off") {
		t.Error("Users page doesn't point admins at the setup")
	}
	if _, w := e.createToken("x"); w.Code != http.StatusNotFound {
		t.Errorf("create while disabled: %d", w.Code)
	}
	if w := e.get("/account/assistants/heimdall.mcpb", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("bundle while disabled: %d", w.Code)
	}
	// Everyone else: no such page.
	e.asBob()
	if w := e.get("/account/assistants", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("user, disabled: %d", w.Code)
	}
}

func TestAssistantsBundle(t *testing.T) {
	e := mcpEnv(t, true)
	e.asBob()
	w := e.get("/account/assistants/heimdall.mcpb", signedIn(e))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/zip" ||
		!strings.Contains(w.Header().Get("Content-Disposition"), `filename="heimdall.mcpb"`) {
		t.Fatalf("bundle: %d %v", w.Code, w.Header())
	}
	b := w.Body.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name != "manifest.json" {
			continue
		}
		rc, _ := f.Open()
		raw, _ := io.ReadAll(rc)
		var m struct {
			UserConfig map[string]map[string]any `json:"user_config"`
		}
		json.Unmarshal(raw, &m)
		if m.UserConfig["hub_url"]["default"] != testMCPURL || m.UserConfig["token"]["sensitive"] != true {
			t.Errorf("manifest: %s", raw)
		}
		if tokenRe.Match(raw) {
			t.Error("manifest carries a token")
		}
	}
	if w := e.get("/account/assistants/heimdall.mcpb"); w.Code != http.StatusSeeOther {
		t.Errorf("signed-out download: %d", w.Code)
	}
}

func TestAdminSeesAndRevokesTokens(t *testing.T) {
	e := mcpEnv(t, true)
	bobToken, bobID, _ := e.st.CreateMCPToken(t.Context(), "test", 2, "bob phone")
	body := e.get("/admin/users", signedIn(e)).Body.String()
	if !strings.Contains(body, "AI tokens") || !strings.Contains(body, "bob phone") || tokenRe.MatchString(body) {
		t.Fatal("admin page doesn't list tokens (or leaks one)")
	}
	w := e.formPost("/admin/users/mcp-revoke", url.Values{"user": {"2"}, "id": {strconv.FormatInt(bobID, 10)}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/users?ok=token-revoked" {
		t.Fatalf("admin revoke: %d", w.Code)
	}
	if _, _, err := e.st.MCPTokenUser(t.Context(), sha256.Sum256([]byte(bobToken)), testNow); err == nil {
		t.Error("token still works")
	}
	if !auditHas(t, e, "mcp_token.revoke") {
		t.Error("admin revoke not audited")
	}
	// The wrong user for a token ID is not found.
	_, otherID, _ := e.st.CreateMCPToken(t.Context(), "test", 2, "bob laptop")
	if w := e.formPost("/admin/users/mcp-revoke", url.Values{"user": {"1"}, "id": {strconv.FormatInt(otherID, 10)}}); w.Code != http.StatusNotFound {
		t.Errorf("mismatched user: %d", w.Code)
	}
}
