// SPDX-License-Identifier: AGPL-3.0-or-later

package push

import (
	"crypto/ecdh"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/realmwatch/heimdall/internal/netx"
)

// A subscription's endpoint is a URL the browser hands the hub, and the
// hub POSTs to it: left open, anyone signed in could aim the hub at an
// internal address. So an endpoint must be HTTPS on a known push service
// (netx.PushHosts), checked when a browser subscribes and again on every
// send, and the HTTP client is allowlisted the same way.

// ErrEndpoint is a subscription endpoint the hub won't send to.
var ErrEndpoint = errors.New("not a known push service")

// maxEndpoint bounds an endpoint URL; real ones are under 500 bytes.
const maxEndpoint = 1024

// CheckEndpoint returns nil for an endpoint the hub may send to.
func CheckEndpoint(raw string) error {
	if len(raw) > maxEndpoint {
		return ErrEndpoint
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return ErrEndpoint
	}
	host := u.Hostname()
	if host != strings.ToLower(host) || !allowedHost(host) {
		return ErrEndpoint
	}
	if devLoopback && isLoopback(host) {
		if u.Scheme != "http" && u.Scheme != "https" {
			return ErrEndpoint
		}
		return nil // dev builds only (dev.go): a local fake push service
	}
	if u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") {
		return ErrEndpoint
	}
	return nil
}

// allowedHost is the client's allowlist: a push service, or in dev builds
// a loopback address. Tests may replace it.
var allowedHost = func(host string) bool {
	return netx.PushHost(host) || (devLoopback && isLoopback(host))
}

// devLoopback is set only in dev builds (dev.go, -tags dev): an endpoint
// on a loopback address, over http, is then allowed, so a local fake push
// service can stand in for a real one. Release builds never contain it.
var devLoopback = false

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

// NewClient is the HTTP client for sending: HTTPS to push services only
// (netx), redirects included.
func NewClient(userAgent string) *netx.Client {
	return netx.NewMatching(func(host string) bool { return allowedHost(host) }, userAgent)
}

// ParseKeys decodes a subscription's keys as the Push API gives them
// (base64url): p256dh must be a P-256 public key and auth 16 bytes.
func ParseKeys(p256dh, auth string) ([]byte, []byte, error) {
	pub, err1 := decodeKey(p256dh)
	sec, err2 := decodeKey(auth)
	if err1 != nil || err2 != nil || len(sec) != 16 {
		return nil, nil, errors.New("bad subscription keys")
	}
	if _, err := ecdh.P256().NewPublicKey(pub); err != nil {
		return nil, nil, errors.New("bad subscription keys")
	}
	return pub, sec, nil
}

// decodeKey takes base64url with or without padding.
func decodeKey(s string) ([]byte, error) {
	if len(s) > 200 {
		return nil, errors.New("too long")
	}
	return b64.DecodeString(strings.TrimRight(s, "="))
}
