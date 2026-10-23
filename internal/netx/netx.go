// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netx is the hub's only way to make outbound HTTP requests:
// HTTPS only, to a fixed allowlist of hosts, with bounded response sizes.
// systemd can't allowlist by hostname, so this is enforced in-process.
package netx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"slices"
	"strings"
	"time"
)

// FeedHosts are the hosts feed sync may contact.
var FeedHosts = []string{
	"api.osv.dev",
	"www.cisa.gov",
	"endoflife.date",
	"api.first.org", // EPSS (M6)
}

// EntraHosts are the hosts single sign-on may contact. They're kept apart
// from FeedHosts so feed sync can never reach the identity provider.
var EntraHosts = []string{"login.microsoftonline.com"}

// ErrNotAllowed is returned for any request outside the allowlist.
var ErrNotAllowed = errors.New("outbound request not allowed")

// Client wraps an *http.Client. Feed packages take a *Client so tests can
// point them at an httptest server with NewForTest.
type Client struct {
	hc        *http.Client
	userAgent string
}

// New returns a client that may only reach the given hosts over HTTPS.
func New(allowedHosts []string, userAgent string) *Client {
	check := func(r *http.Request) error {
		if r.URL.Scheme != "https" || !slices.Contains(allowedHosts, strings.ToLower(r.URL.Hostname())) {
			return fmt.Errorf("%w: %s://%s", ErrNotAllowed, r.URL.Scheme, r.URL.Host)
		}
		return nil
	}
	return &Client{
		userAgent: userAgent,
		hc: &http.Client{
			Timeout:   2 * time.Minute,
			Transport: guard{check: check, next: http.DefaultTransport},
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return errors.New("too many redirects")
				}
				return check(r) // redirects must stay inside the allowlist too
			},
		},
	}
}

// HTTPClient exposes the allowlisted *http.Client for packages that take
// one directly (e.g. notify.Webhook).
func (c *Client) HTTPClient() *http.Client { return c.hc }

// NewForTest wraps an arbitrary client (e.g. httptest.Server.Client())
// without the allowlist. Only for tests.
func NewForTest(hc *http.Client) *Client { return &Client{hc: hc, userAgent: "heimdall-test"} }

type guard struct {
	check func(*http.Request) error
	next  http.RoundTripper
}

func (g guard) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := g.check(r); err != nil {
		return nil, err
	}
	return g.next.RoundTrip(r)
}

// StatusError is a non-2xx response.
type StatusError struct {
	URL    string
	Status int
}

func (e *StatusError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.URL, e.Status) }

// Get fetches url and returns at most maxBytes of body; larger is an error.
// Extra headers (e.g. If-None-Match) may be passed; a 304 returns nil, nil.
func (c *Client) Get(ctx context.Context, url string, maxBytes int64, header http.Header) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return c.do(req, maxBytes)
}

// PostJSON sends body as JSON and decodes a JSON response into out.
func (c *Client) PostJSON(ctx context.Context, url string, body any, maxBytes int64, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	raw, _, err := c.do(req, maxBytes)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// PostForm sends a URL-encoded form (e.g. an OAuth token request) and
// decodes the JSON response into out.
func (c *Client) PostForm(ctx context.Context, url string, form neturl.Values, maxBytes int64, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	raw, _, err := c.do(req, maxBytes)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// GetJSON fetches url and decodes the JSON body into out.
func (c *Client) GetJSON(ctx context.Context, url string, maxBytes int64, out any) error {
	raw, _, err := c.Get(ctx, url, maxBytes, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func (c *Client) do(req *http.Request, maxBytes int64) ([]byte, http.Header, error) {
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, resp.Header, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, nil, &StatusError{URL: req.URL.Redacted(), Status: resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, nil, fmt.Errorf("GET %s: response larger than %d bytes", req.URL.Redacted(), maxBytes)
	}
	return b, resp.Header, nil
}
