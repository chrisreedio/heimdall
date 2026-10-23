// SPDX-License-Identifier: AGPL-3.0-or-later

// Package entra signs users in with Microsoft Entra ID using the OpenID
// Connect authorization code flow with PKCE. Only Entra is supported, so
// the flow and ID token validation are implemented with the standard
// library: RS256 only, keys from the tenant's JWKS, and every claim the
// README lists checked before an Identity is returned.
package entra

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const DefaultAuthority = "https://login.microsoftonline.com"

const (
	maxJSON       = 1 << 20 // discovery, JWKS and token responses
	maxToken      = 16 << 10
	metadataTTL   = 24 * time.Hour
	keyRefetchGap = 5 * time.Minute
	clockSkew     = 5 * time.Minute
)

// HTTP is the outbound client the package needs. *netx.Client satisfies it
// (PostForm sends application/x-www-form-urlencoded, which the token
// endpoint requires); tests can supply their own.
type HTTP interface {
	GetJSON(ctx context.Context, url string, maxBytes int64, out any) error
	PostForm(ctx context.Context, url string, form url.Values, maxBytes int64, out any) error
}

type Config struct {
	Authority      string // DefaultAuthority if empty (tests point it at httptest)
	Tenant         string // tenant ID (single-tenant) or "organizations"
	ClientID       string
	ClientSecret   string   // client_secret_post; never logged
	RedirectURL    string   // https://<ui>/auth/callback
	AllowedTenants []string // tid values allowed to sign in (required, non-empty)
	HTTP           HTTP
	Now            func() time.Time
}

// ErrInvalidToken wraps every ID token validation failure, so callers can
// show one generic message while logging the specific reason.
var ErrInvalidToken = errors.New("invalid ID token")

type metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	fetched               time.Time
}

type Client struct {
	cfg       Config
	authority *url.URL

	mu          sync.Mutex
	meta        *metadata
	keys        map[string]*rsaKey
	keysFetched time.Time
}

var (
	tenantRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$`)
	idRe     = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`) // tid / oid (GUIDs)
)

// New validates cfg. It does no network I/O.
func New(cfg Config) (*Client, error) {
	if cfg.Authority == "" {
		cfg.Authority = DefaultAuthority
	}
	cfg.Authority = strings.TrimSuffix(cfg.Authority, "/")
	auth, err := url.Parse(cfg.Authority)
	if err != nil || auth.Host == "" || (auth.Scheme != "https" && !(auth.Scheme == "http" && isLoopback(auth.Hostname()))) {
		return nil, errors.New("entra: authority must be an https URL")
	}
	if !tenantRe.MatchString(cfg.Tenant) {
		return nil, errors.New("entra: tenant must be a tenant ID or \"organizations\"")
	}
	if cfg.ClientID == "" || len(cfg.ClientID) > 128 {
		return nil, errors.New("entra: client ID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("entra: client secret is required")
	}
	ru, err := url.Parse(cfg.RedirectURL)
	if err != nil || ru.Host == "" || (ru.Scheme != "https" && !(ru.Scheme == "http" && isLoopback(ru.Hostname()))) {
		return nil, errors.New("entra: redirect URL must be an absolute https URL")
	}
	if len(cfg.AllowedTenants) == 0 {
		return nil, errors.New("entra: allowed tenants must not be empty")
	}
	for _, t := range cfg.AllowedTenants {
		if !idRe.MatchString(t) {
			return nil, fmt.Errorf("entra: invalid allowed tenant %q", t)
		}
	}
	if cfg.HTTP == nil {
		return nil, errors.New("entra: HTTP client is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Client{cfg: cfg, authority: auth}, nil
}

// AuthRequest holds per-login secrets the caller stores server-side (hashed state).
type AuthRequest struct {
	State, Nonce, Verifier string // random, base64url, 32 bytes each
	URL                    string // authorization URL to redirect the browser to
}

// Begin starts a sign-in: PKCE S256, scope "openid profile email".
func (c *Client) Begin(ctx context.Context) (AuthRequest, error) {
	meta, err := c.metadata(ctx)
	if err != nil {
		return AuthRequest{}, err
	}
	req := AuthRequest{State: randomString(), Nonce: randomString(), Verifier: randomString()}
	q := url.Values{
		"client_id":             {c.cfg.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {c.cfg.RedirectURL},
		"response_mode":         {"query"},
		"scope":                 {"openid profile email"},
		"state":                 {req.State},
		"nonce":                 {req.Nonce},
		"code_challenge":        {pkceChallenge(req.Verifier)},
		"code_challenge_method": {"S256"},
		"prompt":                {"select_account"},
	}
	req.URL = meta.AuthorizationEndpoint + "?" + q.Encode()
	return req, nil
}

type Identity struct {
	TenantID, ObjectID string   // tid, oid (immutable identity)
	Email, Name        string   // email or preferred_username; name
	Roles              []string // app roles from the "roles" claim
}

// Finish exchanges the code (with the PKCE verifier) at the token endpoint
// and validates the ID token.
func (c *Client) Finish(ctx context.Context, code, verifier, nonce string) (Identity, error) {
	if code == "" || len(code) > 4096 {
		return Identity{}, errors.New("entra: missing or oversized authorization code")
	}
	if verifier == "" || nonce == "" {
		return Identity{}, errors.New("entra: missing PKCE verifier or nonce")
	}
	meta, err := c.metadata(ctx)
	if err != nil {
		return Identity{}, err
	}
	var tok struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {c.cfg.RedirectURL},
		"code_verifier": {verifier},
		"scope":         {"openid profile email"},
	}
	if err := c.cfg.HTTP.PostForm(ctx, meta.TokenEndpoint, form, maxJSON, &tok); err != nil {
		return Identity{}, fmt.Errorf("entra: token request: %w", err)
	}
	if tok.Error != "" {
		return Identity{}, fmt.Errorf("entra: token endpoint returned %q", truncate(tok.Error, 64))
	}
	if tok.IDToken == "" {
		return Identity{}, errors.New("entra: token response has no id_token")
	}
	return c.validate(ctx, meta, tok.IDToken, nonce)
}

// metadata returns cached discovery metadata, refreshing it after a day.
func (c *Client) metadata(ctx context.Context) (*metadata, error) {
	c.mu.Lock()
	m := c.meta
	c.mu.Unlock()
	if m != nil && c.cfg.Now().Sub(m.fetched) < metadataTTL {
		return m, nil
	}
	u := c.cfg.Authority + "/" + url.PathEscape(c.cfg.Tenant) + "/v2.0/.well-known/openid-configuration"
	var fresh metadata
	if err := c.cfg.HTTP.GetJSON(ctx, u, maxJSON, &fresh); err != nil {
		return nil, fmt.Errorf("entra: discovery: %w", err)
	}
	for name, v := range map[string]string{
		"issuer": fresh.Issuer, "authorization_endpoint": fresh.AuthorizationEndpoint,
		"token_endpoint": fresh.TokenEndpoint, "jwks_uri": fresh.JWKSURI,
	} {
		// Every endpoint must live on the authority's host and scheme.
		p, err := url.Parse(v)
		if err != nil || p.Scheme != c.authority.Scheme || !strings.EqualFold(p.Host, c.authority.Host) {
			return nil, fmt.Errorf("entra: discovery %s %q is not on %s", name, truncate(v, 100), c.authority.Host)
		}
	}
	fresh.fetched = c.cfg.Now()
	c.mu.Lock()
	c.meta = &fresh
	c.mu.Unlock()
	return &fresh, nil
}

func randomString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
