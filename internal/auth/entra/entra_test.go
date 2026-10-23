// SPDX-License-Identifier: AGPL-3.0-or-later

package entra

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/netx"
)

const (
	testTenant   = "11111111-2222-3333-4444-555555555555"
	otherTenant  = "99999999-8888-7777-6666-555555555555"
	testClientID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	testSecret   = "s3cret"
	testRedirect = "https://heimdall.example.ts.net/auth/callback"
	testOID      = "0f0f0f0f-1111-2222-3333-444444444444"
)

var key1, key2 *rsa.PrivateKey

func init() {
	var err error
	if key1, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	if key2, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
}

// fakeIdP plays Entra: discovery, JWKS and the token endpoint.
type fakeIdP struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	keys      map[string]*rsa.PrivateKey // published in the JWKS
	challenge string                     // from the authorize URL
	idToken   string                     // returned by the token endpoint
	tokenErr  int                        // HTTP status to fail with

	jwksFetches atomic.Int32
}

func newIdP(t *testing.T) *fakeIdP {
	f := &fakeIdP{t: t, keys: map[string]*rsa.PrivateKey{"k1": key1}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /organizations/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := f.srv.URL
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 base + "/{tenantid}/v2.0",
			"authorization_endpoint": base + "/organizations/oauth2/v2.0/authorize",
			"token_endpoint":         base + "/organizations/oauth2/v2.0/token",
			"jwks_uri":               base + "/organizations/discovery/v2.0/keys",
		})
	})
	mux.HandleFunc("GET /organizations/discovery/v2.0/keys", func(w http.ResponseWriter, r *http.Request) {
		f.jwksFetches.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		var keys []map[string]string
		for kid, k := range f.keys {
			keys = append(keys, map[string]string{
				"kty": "RSA", "use": "sig", "kid": kid,
				"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			})
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	mux.HandleFunc("POST /organizations/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		r.ParseForm()
		if f.tokenErr != 0 {
			http.Error(w, `{"error":"invalid_grant"}`, f.tokenErr)
			return
		}
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		switch {
		case r.PostForm.Get("grant_type") != "authorization_code",
			r.PostForm.Get("client_id") != testClientID,
			r.PostForm.Get("client_secret") != testSecret,
			r.PostForm.Get("redirect_uri") != testRedirect,
			r.PostForm.Get("code") != "the-code":
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		case base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge:
			http.Error(w, `{"error":"invalid_grant","error_description":"PKCE"}`, http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": f.idToken, "token_type": "Bearer"})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// testHTTP adapts the test server's client to the HTTP interface: GETs go
// through netx (as production does), form POSTs through a plain request.
type testHTTP struct {
	nx *netx.Client
	hc *http.Client
}

func (h testHTTP) GetJSON(ctx context.Context, u string, max int64, out any) error {
	return h.nx.GetJSON(ctx, u, max, out)
}

func (h testHTTP) PostForm(ctx context.Context, u string, form url.Values, max int64, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &netx.StatusError{URL: u, Status: resp.StatusCode}
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, max))
	return json.Unmarshal(b, out)
}

type env struct {
	t   *testing.T
	idp *fakeIdP
	c   *Client
	now time.Time
	req AuthRequest
}

func newEnv(t *testing.T) *env {
	idp := newIdP(t)
	e := &env{t: t, idp: idp, now: time.Unix(1_800_000_000, 0)}
	c, err := New(Config{
		Authority: idp.srv.URL, Tenant: "organizations", ClientID: testClientID, ClientSecret: testSecret,
		RedirectURL: testRedirect, AllowedTenants: []string{testTenant},
		HTTP: testHTTP{nx: netx.NewForTest(idp.srv.Client()), hc: idp.srv.Client()},
		Now:  func() time.Time { return e.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.c = c
	if e.req, err = c.Begin(t.Context()); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(e.req.URL)
	idp.challenge = u.Query().Get("code_challenge")
	return e
}

func (e *env) claims() map[string]any {
	return map[string]any{
		"ver": "2.0", "iss": e.idp.srv.URL + "/" + testTenant + "/v2.0", "aud": testClientID,
		"exp": e.now.Add(time.Hour).Unix(), "nbf": e.now.Add(-time.Minute).Unix(), "iat": e.now.Add(-time.Minute).Unix(),
		"nonce": e.req.Nonce, "tid": testTenant, "oid": testOID,
		"preferred_username": "chris@example.com", "name": "Chris", "roles": []string{"Heimdall.Admin"},
	}
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func signRS256(key *rsa.PrivateKey, kid string, claims map[string]any) string {
	head := b64(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"}) + "." + b64(claims)
	sum := sha256.Sum256([]byte(head))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	return head + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (e *env) finishWith(token string) (Identity, error) {
	e.idp.mu.Lock()
	e.idp.idToken = token
	e.idp.mu.Unlock()
	return e.c.Finish(e.t.Context(), "the-code", e.req.Verifier, e.req.Nonce)
}

func TestHappyPath(t *testing.T) {
	e := newEnv(t)
	id, err := e.finishWith(signRS256(key1, "k1", e.claims()))
	if err != nil {
		t.Fatal(err)
	}
	if id.TenantID != testTenant || id.ObjectID != testOID || id.Email != "chris@example.com" || id.Name != "Chris" ||
		len(id.Roles) != 1 || id.Roles[0] != "Heimdall.Admin" {
		t.Errorf("identity = %+v", id)
	}
}

func TestBeginURL(t *testing.T) {
	e := newEnv(t)
	u, err := url.Parse(e.req.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	want := map[string]string{
		"client_id": testClientID, "response_type": "code", "redirect_uri": testRedirect, "response_mode": "query",
		"scope": "openid profile email", "state": e.req.State, "nonce": e.req.Nonce,
		"code_challenge_method": "S256", "prompt": "select_account",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if q.Get("code_challenge") != pkceChallenge(e.req.Verifier) {
		t.Error("code_challenge is not S256(verifier)")
	}
	if u.Path != "/organizations/oauth2/v2.0/authorize" {
		t.Errorf("path = %s", u.Path)
	}
	for _, s := range []string{e.req.State, e.req.Nonce, e.req.Verifier} {
		if b, err := base64.RawURLEncoding.DecodeString(s); err != nil || len(b) != 32 {
			t.Errorf("secret %q is not 32 random bytes", s)
		}
	}
	other, _ := e.c.Begin(t.Context())
	if other.State == e.req.State || other.Nonce == e.req.Nonce || other.Verifier == e.req.Verifier {
		t.Error("per-login secrets must be unique")
	}
}

func TestRejections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(e *env, c map[string]any) string // returns the token
	}{
		{"wrong aud", func(e *env, c map[string]any) string { c["aud"] = "someone-else"; return signRS256(key1, "k1", c) }},
		{"aud array with extra", func(e *env, c map[string]any) string {
			c["aud"] = []string{testClientID, "other"}
			return signRS256(key1, "k1", c)
		}},
		{"wrong iss", func(e *env, c map[string]any) string {
			c["iss"] = "https://login.microsoftonline.com/" + testTenant + "/v2.0"
			return signRS256(key1, "k1", c)
		}},
		{"iss of another tenant", func(e *env, c map[string]any) string {
			c["iss"] = e.idp.srv.URL + "/" + otherTenant + "/v2.0"
			return signRS256(key1, "k1", c)
		}},
		{"expired", func(e *env, c map[string]any) string {
			c["exp"] = e.now.Add(-10 * time.Minute).Unix()
			return signRS256(key1, "k1", c)
		}},
		{"missing exp", func(e *env, c map[string]any) string { delete(c, "exp"); return signRS256(key1, "k1", c) }},
		{"nbf in future", func(e *env, c map[string]any) string {
			c["nbf"] = e.now.Add(10 * time.Minute).Unix()
			return signRS256(key1, "k1", c)
		}},
		{"iat in future", func(e *env, c map[string]any) string {
			c["iat"] = e.now.Add(10 * time.Minute).Unix()
			return signRS256(key1, "k1", c)
		}},
		{"wrong nonce", func(e *env, c map[string]any) string { c["nonce"] = "nope"; return signRS256(key1, "k1", c) }},
		{"tenant not allowed", func(e *env, c map[string]any) string {
			c["tid"] = otherTenant
			c["iss"] = e.idp.srv.URL + "/" + otherTenant + "/v2.0"
			return signRS256(key1, "k1", c)
		}},
		{"v1 token", func(e *env, c map[string]any) string { c["ver"] = "1.0"; return signRS256(key1, "k1", c) }},
		{"missing oid", func(e *env, c map[string]any) string { delete(c, "oid"); return signRS256(key1, "k1", c) }},
		{"missing tid", func(e *env, c map[string]any) string { delete(c, "tid"); return signRS256(key1, "k1", c) }},
		{"alg none", func(e *env, c map[string]any) string {
			return b64(map[string]string{"alg": "none", "kid": "k1"}) + "." + b64(c) + "."
		}},
		{"alg HS256 with the public key as secret", func(e *env, c map[string]any) string {
			head := b64(map[string]string{"alg": "HS256", "kid": "k1"}) + "." + b64(c)
			pub, _ := x509.MarshalPKIXPublicKey(&key1.PublicKey)
			m := hmac.New(sha256.New, pub)
			m.Write([]byte(head))
			return head + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
		}},
		{"tampered payload", func(e *env, c map[string]any) string {
			tok := signRS256(key1, "k1", c)
			parts := strings.Split(tok, ".")
			c["oid"] = "deadbeef-0000-0000-0000-000000000000"
			parts[1] = b64(c)
			return strings.Join(parts, ".")
		}},
		{"signed by an unpublished key", func(e *env, c map[string]any) string { return signRS256(key2, "k1", c) }},
		{"missing kid", func(e *env, c map[string]any) string { return signRS256(key1, "", c) }},
		{"not a JWS", func(e *env, c map[string]any) string { return "a.b" }},
		{"oversized", func(e *env, c map[string]any) string { return strings.Repeat("a", maxToken+1) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			_, err := e.finishWith(tt.mutate(e, e.claims()))
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("want ErrInvalidToken, got %v", err)
			}
		})
	}
}

func TestKeyRotationAndRefetchLimit(t *testing.T) {
	e := newEnv(t)
	if _, err := e.finishWith(signRS256(key1, "k1", e.claims())); err != nil {
		t.Fatal(err)
	}
	if n := e.idp.jwksFetches.Load(); n != 1 {
		t.Fatalf("jwks fetches = %d", n)
	}

	// Entra rotates to k2. The first token with the new kid triggers one
	// refetch, but only once the rate limit allows it.
	e.idp.mu.Lock()
	e.idp.keys = map[string]*rsa.PrivateKey{"k2": key2}
	e.idp.mu.Unlock()
	if _, err := e.finishWith(signRS256(key2, "k2", e.claims())); !errors.Is(err, ErrInvalidToken) ||
		!strings.Contains(err.Error(), "rate-limited") {
		t.Fatalf("refetch within 5 minutes should be refused: %v", err)
	}
	if n := e.idp.jwksFetches.Load(); n != 1 {
		t.Fatalf("rate limit not applied: %d fetches", n)
	}
	e.now = e.now.Add(keyRefetchGap)
	if _, err := e.finishWith(signRS256(key2, "k2", e.claims())); err != nil {
		t.Fatalf("rotated key not picked up: %v", err)
	}
	// Bogus kids right after don't cause more fetches.
	for range 5 {
		e.finishWith(signRS256(key2, "bogus", e.claims()))
	}
	if n := e.idp.jwksFetches.Load(); n != 2 {
		t.Fatalf("jwks fetches = %d, want 2", n)
	}
}

func TestTokenEndpointErrors(t *testing.T) {
	e := newEnv(t)
	e.idp.tokenErr = http.StatusBadRequest
	if _, err := e.finishWith(signRS256(key1, "k1", e.claims())); err == nil || errors.Is(err, ErrInvalidToken) {
		t.Fatalf("token endpoint error: %v", err)
	}

	e.idp.tokenErr = 0
	e.idp.idToken = signRS256(key1, "k1", e.claims())
	if _, err := e.c.Finish(t.Context(), "the-code", "wrong-verifier", e.req.Nonce); err == nil {
		t.Fatal("PKCE verifier mismatch must fail")
	}
	if _, err := e.c.Finish(t.Context(), "", e.req.Verifier, e.req.Nonce); err == nil {
		t.Fatal("empty code must fail")
	}
}

func TestNewValidation(t *testing.T) {
	base := Config{Tenant: "organizations", ClientID: testClientID, ClientSecret: testSecret, RedirectURL: testRedirect,
		AllowedTenants: []string{testTenant}, HTTP: testHTTP{}}
	if _, err := New(base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"no tenants":     func(c *Config) { c.AllowedTenants = nil },
		"bad tenant":     func(c *Config) { c.Tenant = "../evil" },
		"http redirect":  func(c *Config) { c.RedirectURL = "http://heimdall.example.com/auth/callback" },
		"http authority": func(c *Config) { c.Authority = "http://login.example.com" },
		"no secret":      func(c *Config) { c.ClientSecret = "" },
		"no client id":   func(c *Config) { c.ClientID = "" },
		"no http":        func(c *Config) { c.HTTP = nil },
		"bad allowed":    func(c *Config) { c.AllowedTenants = []string{"not a guid!"} },
	} {
		c := base
		mutate(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestDiscoveryOnForeignHostRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer": "x", "authorization_endpoint": "https://evil.example.com/authorize",
			"token_endpoint": "https://evil.example.com/token", "jwks_uri": "https://evil.example.com/keys",
		})
	}))
	defer srv.Close()
	c, err := New(Config{Authority: srv.URL, Tenant: "organizations", ClientID: testClientID, ClientSecret: testSecret,
		RedirectURL: testRedirect, AllowedTenants: []string{testTenant},
		HTTP: testHTTP{nx: netx.NewForTest(srv.Client()), hc: srv.Client()}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Begin(t.Context()); err == nil || !strings.Contains(err.Error(), "is not on") {
		t.Fatalf("foreign endpoints must be rejected: %v", err)
	}
}
