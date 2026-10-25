// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cloudflare reads a hub owner's Cloudflare account with a
// read-only API token: zones and their DNS records, security event counts
// from the GraphQL Analytics API, and Radar's ASN for unknown addresses.
// It also fetches Cloudflare's published edge ranges (no token), so the
// hub knows Cloudflare's own addresses and can trust CF-Connecting-IP from
// them only. Nothing here writes to Cloudflare, except lists.go: the ban
// list and rules (internal/bans), with a second token of their own.
//
// API references (checked Oct 2026):
//   - token verify: https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify/
//   - zones: https://developers.cloudflare.com/api/resources/zones/methods/list/ (Zone Read)
//   - DNS records: https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/ (DNS Read)
//   - GraphQL: https://developers.cloudflare.com/analytics/graphql-api/ (Analytics Read)
//   - Radar: https://developers.cloudflare.com/api/resources/radar/subresources/entities/subresources/asns/methods/ip/ (Account > Radar > Read)
//   - edge ranges: https://www.cloudflare.com/ips/
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/netx"
)

// EdgeHost serves the published edge ranges.
const EdgeHost = "www.cloudflare.com"

// Client calls the Cloudflare API with a token. Base is the API's base URL
// (config.CloudflareAPI; an httptest server in tests).
type Client struct {
	Base      string
	Token     string
	HTTP      *http.Client
	UserAgent string
}

// NewHTTP returns an HTTP client that may reach only the API host and the
// edge-range host, over HTTPS, with a short timeout.
func NewHTTP(apiHost, userAgent string) *http.Client {
	hc := *netx.New([]string{apiHost, EdgeHost}, userAgent).HTTPClient()
	hc.Timeout = 30 * time.Second
	return &hc
}

// maxResponse caps any API response.
const maxResponse = 8 << 20

// APIError is an error answer from the API: its HTTP status and the
// errors it listed. It never includes the token.
type APIError struct {
	Status   int
	Codes    []int
	Messages []string
}

func (e *APIError) Error() string {
	msg := strings.Join(e.Messages, "; ")
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("Cloudflare API: HTTP %d: %s", e.Status, msg)
}

// Permission reports whether the token lacks a permission (or is invalid).
func (e *APIError) Permission() bool {
	if e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden {
		return true
	}
	for _, c := range e.Codes {
		if c == 9109 || c == 10000 || c == 1000 { // unauthorized / authentication error / invalid token
			return true
		}
	}
	return false
}

// IsPermission reports whether err says the token can't do that.
func IsPermission(err error) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Permission()
	}
	var ge *GraphQLError
	return errors.As(err, &ge) && ge.Kind == "permission"
}

type envelope struct {
	Success  bool            `json:"success"`
	Errors   []apiMessage    `json:"errors"`
	Result   json.RawMessage `json:"result"`
	Info     *resultInfo     `json:"result_info"`
	Messages []apiMessage    `json:"messages"`
}

type apiMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type resultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

// do sends a request and returns the raw body of a 2xx answer, or an
// APIError built from the envelope.
func (c *Client) do(ctx context.Context, method, path string, q url.Values, body []byte) ([]byte, error) {
	u := strings.TrimSuffix(c.Base, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, redact(err, c.Token)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxResponse {
		return nil, fmt.Errorf("cloudflare API %s: response too large", path)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{Status: resp.StatusCode}
		var env envelope
		if json.Unmarshal(b, &env) == nil {
			for _, m := range env.Errors {
				ae.Codes = append(ae.Codes, m.Code)
				ae.Messages = append(ae.Messages, clip(m.Message))
			}
		}
		return nil, ae
	}
	return b, nil
}

// redact keeps the token out of an error (it's only ever in a header, but
// be sure).
func redact(err error, token string) error {
	if token != "" && strings.Contains(err.Error(), token) {
		return errors.New(strings.ReplaceAll(err.Error(), token, "[token]"))
	}
	return err
}

func clip(s string) string {
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// get calls a REST endpoint and decodes its result.
func (c *Client) get(ctx context.Context, path string, q url.Values, out any) (*resultInfo, error) {
	b, err := c.do(ctx, http.MethodGet, path, q, nil)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("cloudflare API %s: %w", path, err)
	}
	if !env.Success {
		ae := &APIError{Status: http.StatusOK}
		for _, m := range env.Errors {
			ae.Codes, ae.Messages = append(ae.Codes, m.Code), append(ae.Messages, clip(m.Message))
		}
		return nil, ae
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return nil, fmt.Errorf("cloudflare API %s: %w", path, err)
		}
	}
	return env.Info, nil
}

// Token is what token verify says about the token.
type Token struct {
	ID        string `json:"id"`
	Status    string `json:"status"` // active, disabled, expired
	ExpiresOn string `json:"expires_on"`
}

// VerifyToken checks the token (user-owned tokens; an account-owned token
// fails here but works for everything else).
func (c *Client) VerifyToken(ctx context.Context) (Token, error) {
	var t Token
	_, err := c.get(ctx, "/user/tokens/verify", nil, &t)
	return t, err
}

// Zone is a zone the token can read.
type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Plan   struct {
		Name     string `json:"name"`      // "Free Website", "Pro Website", ...
		LegacyID string `json:"legacy_id"` // free, pro, business, enterprise
	} `json:"plan"`
}

// maxPages bounds pagination against a misbehaving server.
const maxPages = 200

// Zones lists every zone the token can read (Zone Read), 50 a page.
func (c *Client) Zones(ctx context.Context) ([]Zone, error) {
	var out []Zone
	for page := 1; page <= maxPages; page++ {
		var zs []Zone
		info, err := c.get(ctx, "/zones", url.Values{"page": {strconv.Itoa(page)}, "per_page": {"50"}}, &zs)
		if err != nil {
			return nil, err
		}
		out = append(out, zs...)
		if info == nil || page >= info.TotalPages || len(zs) == 0 {
			return out, nil
		}
	}
	return nil, errors.New("cloudflare API /zones: too many pages")
}

// Record is a DNS record.
type Record struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

// DNSRecords lists a zone's A, AAAA and CNAME records (DNS Read).
func (c *Client) DNSRecords(ctx context.Context, zoneID string) ([]Record, error) {
	if !zoneIDRe(zoneID) {
		return nil, fmt.Errorf("bad zone ID %q", zoneID)
	}
	var out []Record
	for page := 1; page <= maxPages; page++ {
		var rs []Record
		info, err := c.get(ctx, "/zones/"+zoneID+"/dns_records",
			url.Values{"page": {strconv.Itoa(page)}, "per_page": {"500"}}, &rs)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			if r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME" {
				out = append(out, r)
			}
		}
		if info == nil || page >= info.TotalPages || len(rs) == 0 {
			return out, nil
		}
	}
	return nil, errors.New("cloudflare API dns_records: too many pages")
}

// zoneIDRe accepts Cloudflare's 32-hex zone IDs, which are put into paths
// and GraphQL text.
func zoneIDRe(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
