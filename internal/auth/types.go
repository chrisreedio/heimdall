// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/realmwatch/heimdall/internal/store"
)

// Viewer is the signed-in user behind a request.
type Viewer struct {
	UserID       int64
	Email        string
	DisplayName  string
	IsAdmin      bool
	Kind         string      // "local" or "entra"
	Scope        store.Scope // orgs and roles this user may act on
	SessionToken string      // raw cookie value; never logged or rendered
}

var (
	// ErrInvalidLogin is the only error a failed login reveals, whatever
	// the reason (unknown email, wrong password, wrong or replayed code).
	ErrInvalidLogin = errors.New("invalid email, password or code")
	// ErrThrottled means too many recent failures from this IP or account.
	ErrThrottled = errors.New("too many attempts; try again later")
	// ErrNoSession means the cookie is missing, unknown, expired or revoked.
	ErrNoSession = errors.New("not signed in")
	// ErrNotProvisioned means a valid Entra sign-in for someone who hasn't
	// been added to Heimdall (or was disabled).
	ErrNotProvisioned = errors.New("your account hasn't been set up in Heimdall; ask an admin to add you")
)

// CSRFToken derives a session's CSRF token. It's one-way, so a token that
// leaks into a page or log doesn't reveal the session itself.
func CSRFToken(sessionToken string) string {
	m := hmac.New(sha256.New, []byte(sessionToken))
	m.Write([]byte("heimdall-csrf-v1"))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// ValidCSRF reports whether got is the session's CSRF token (constant time).
func ValidCSRF(sessionToken, got string) bool {
	return sessionToken != "" && hmac.Equal([]byte(CSRFToken(sessionToken)), []byte(got))
}
