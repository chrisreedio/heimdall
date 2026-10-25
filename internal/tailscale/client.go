// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tailscale reads the tailnet's devices from the Tailscale API
// (read only: nothing is ever written to Tailscale) so Heimdall knows the
// person and device behind each tailnet address, and which of your hosts
// are on the tailnet.
//
// API reference: https://tailscale.com/api (OpenAPI at
// https://api.tailscale.com/api/v2?outputOpenapiSchema=true); OAuth
// clients: https://tailscale.com/kb/1215/oauth-clients.
package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chrisreedio/heimdall/internal/netx"
	"github.com/chrisreedio/heimdall/internal/store"
)

// Hosts are the only hosts the client may reach.
var Hosts = []string{"api.tailscale.com"}

// BaseURL is the API's base.
const BaseURL = "https://api.tailscale.com/api/v2"

// Scope is the one OAuth scope Heimdall needs: list the tailnet's devices.
const Scope = "devices:core:read"

// OAuthClientsURL is where an OAuth client is created (Settings > Trust
// credentials, formerly OAuth clients). Tailscale has no pre-filled form.
const OAuthClientsURL = "https://login.tailscale.com/admin/settings/oauth"

// Credential kinds.
const (
	KindOAuth  = "oauth"   // an OAuth client: doesn't expire
	KindAPIKey = "api-key" // an API access token: expires in 1 to 90 days
)

// Credential is an OAuth client (recommended) or an API access token.
type Credential struct {
	ClientID, ClientSecret string
	APIKey                 string
}

// Kind is KindOAuth or KindAPIKey.
func (c Credential) Kind() string {
	if c.APIKey != "" {
		return KindAPIKey
	}
	return KindOAuth
}

// Encode is the credential file's content.
func (c Credential) Encode() string {
	if c.APIKey != "" {
		return "api_key = " + c.APIKey + "\n"
	}
	return "oauth_client_id = " + c.ClientID + "\noauth_client_secret = " + c.ClientSecret + "\n"
}

func secretLike(s string) bool {
	return s != "" && len(s) <= 512 && !strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f || r == '=' })
}

// ParseCredential reads a credential file (see Encode). Errors never
// include the secret.
func ParseCredential(text string) (Credential, error) {
	var c Credential
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return Credential{}, errors.New("credential file: expected key = value lines")
		}
		switch v = strings.TrimSpace(v); strings.TrimSpace(k) {
		case "api_key":
			c.APIKey = v
		case "oauth_client_id":
			c.ClientID = v
		case "oauth_client_secret":
			c.ClientSecret = v
		default:
			return Credential{}, fmt.Errorf("credential file: unknown key %q", strings.TrimSpace(k))
		}
	}
	return c, c.Check()
}

// Check reports whether the credential is complete and well formed.
func (c Credential) Check() error {
	switch {
	case c.APIKey != "" && (c.ClientID != "" || c.ClientSecret != ""):
		return errors.New("credential: either an API access token or an OAuth client, not both")
	case c.APIKey != "":
		if !secretLike(c.APIKey) {
			return errors.New("credential: that doesn't look like an API access token (tskey-api-…)")
		}
	case c.ClientID == "" || c.ClientSecret == "":
		return errors.New("credential: an OAuth client needs both its client ID and its secret")
	case !secretLike(c.ClientID) || !secretLike(c.ClientSecret):
		return errors.New("credential: that doesn't look like an OAuth client ID and secret (tskey-client-…)")
	}
	return nil
}

// Client lists a tailnet's devices.
type Client struct {
	Cred    Credential
	Tailnet string       // "-": the credential's tailnet
	HTTP    *netx.Client // netx.New(Hosts, ...) outside tests
	BaseURL string       // BaseURL outside tests
	Now     func() time.Time

	mu       sync.Mutex
	token    string // OAuth access token, valid for an hour
	tokenExp time.Time
}

// NewClient returns a client for the real API.
func NewClient(cred Credential, tailnet, userAgent string) *Client {
	return &Client{Cred: cred, Tailnet: tailnet, HTTP: netx.New(Hosts, userAgent), BaseURL: BaseURL, Now: time.Now}
}

const maxBody = 16 << 20 // a tailnet of thousands of devices fits

// hint turns an API status into what to do about it.
func hint(err error) error {
	var se *netx.StatusError
	if errors.As(err, &se) {
		switch se.Status {
		case http.StatusUnauthorized:
			return fmt.Errorf("%w: the credential was refused (revoked, expired, or mistyped); store a new one with `sudo heimdall tailscale set-key`", err)
		case http.StatusForbidden:
			return fmt.Errorf("%w: the credential may not list devices; an OAuth client needs the %s scope", err, Scope)
		case http.StatusNotFound:
			return fmt.Errorf("%w: tailnet not found; check [tailscale] tailnet (\"-\" is the credential's own)", err)
		}
	}
	return err
}

// bearer returns the Authorization value, exchanging the OAuth client for
// a fresh access token when needed (client credentials grant).
func (c *Client) bearer(ctx context.Context) (string, error) {
	if c.Cred.APIKey != "" {
		return "Bearer " + c.Cred.APIKey, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.Now().Before(c.tokenExp) {
		return "Bearer " + c.token, nil
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.Cred.ClientID}, "client_secret": {c.Cred.ClientSecret}}
	if err := c.HTTP.PostForm(ctx, c.BaseURL+"/oauth/token", form, 64<<10, &resp); err != nil {
		return "", fmt.Errorf("tailscale OAuth token: %w", hint(err))
	}
	if resp.AccessToken == "" {
		return "", errors.New("tailscale OAuth token: no access_token in the response")
	}
	life := time.Duration(resp.ExpiresIn) * time.Second
	if life <= 0 {
		life = time.Hour
	}
	c.token, c.tokenExp = resp.AccessToken, c.Now().Add(life-time.Minute)
	return "Bearer " + c.token, nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	auth, err := c.bearer(ctx)
	if err != nil {
		return err
	}
	raw, _, err := c.HTTP.Get(ctx, c.BaseURL+path, maxBody, http.Header{"Authorization": {auth}})
	if err != nil {
		return hint(err)
	}
	return json.Unmarshal(raw, out)
}

// apiDevice is the API's Device (fields=default has all of these).
type apiDevice struct {
	ID                 string   `json:"id"`
	NodeID             string   `json:"nodeId"`
	Addresses          []string `json:"addresses"`
	User               string   `json:"user"`
	Name               string   `json:"name"`
	Hostname           string   `json:"hostname"`
	ClientVersion      string   `json:"clientVersion"`
	UpdateAvailable    bool     `json:"updateAvailable"`
	OS                 string   `json:"os"`
	ConnectedToControl bool     `json:"connectedToControl"`
	LastSeen           string   `json:"lastSeen"`
	KeyExpiryDisabled  bool     `json:"keyExpiryDisabled"`
	Expires            string   `json:"expires"`
	Tags               []string `json:"tags"`
}

func apiTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.Year() < 2000 { // "0001-01-01T00:00:00Z" means none
		return time.Time{}
	}
	return t.UTC()
}

// Devices lists the tailnet's devices: GET /tailnet/{tailnet}/devices.
func (c *Client) Devices(ctx context.Context) ([]store.TailnetDevice, error) {
	var resp struct {
		Devices []apiDevice `json:"devices"`
	}
	if err := c.get(ctx, "/tailnet/"+url.PathEscape(c.Tailnet)+"/devices?fields=default", &resp); err != nil {
		return nil, fmt.Errorf("tailscale devices: %w", err)
	}
	out := make([]store.TailnetDevice, 0, len(resp.Devices))
	for _, d := range resp.Devices {
		id := d.NodeID
		if id == "" {
			id = d.ID
		}
		if id == "" {
			continue
		}
		td := store.TailnetDevice{ID: id, Name: strings.TrimSuffix(d.Name, "."), Hostname: d.Hostname, Addresses: d.Addresses,
			User: d.User, Tags: d.Tags, OS: d.OS, ClientVersion: d.ClientVersion, UpdateAvailable: d.UpdateAvailable,
			Online: d.ConnectedToControl, LastSeen: apiTime(d.LastSeen), KeyExpiryDisabled: d.KeyExpiryDisabled}
		if !d.KeyExpiryDisabled {
			td.KeyExpiry = apiTime(d.Expires)
		}
		if len(td.Tags) > 0 {
			// A tagged device belongs to its tags, not to whoever
			// registered it (the API's user for it).
			td.User = ""
		}
		out = append(out, td)
	}
	return out, nil
}

// APIKeyID is an API access token's key ID (tskey-api-<id>-<secret>), or
// "" if it doesn't have that shape.
func APIKeyID(key string) string {
	rest, ok := strings.CutPrefix(key, "tskey-api-")
	if !ok {
		return ""
	}
	id, _, ok := strings.Cut(rest, "-")
	if !ok {
		return ""
	}
	return id
}

// KeyExpiry asks when the API access token expires: GET
// /tailnet/{tailnet}/keys/{keyId}. Zero for an OAuth client (its tokens
// are renewed hourly) or when the API doesn't say.
func (c *Client) KeyExpiry(ctx context.Context) (time.Time, error) {
	id := APIKeyID(c.Cred.APIKey)
	if id == "" {
		return time.Time{}, nil
	}
	var resp struct {
		Expires string `json:"expires"`
	}
	if err := c.get(ctx, "/tailnet/"+url.PathEscape(c.Tailnet)+"/keys/"+url.PathEscape(id), &resp); err != nil {
		return time.Time{}, fmt.Errorf("tailscale key: %w", err)
	}
	return apiTime(resp.Expires), nil
}
