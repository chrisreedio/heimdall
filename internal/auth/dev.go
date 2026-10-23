// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build dev

package auth

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/chrisreedio/heimdall/internal/store"
)

// DevLogin starts a session for a local user without a password or TOTP
// code, for the dev build's one-click test sign-in. Only binaries built
// with -tags dev have it.
func (s *Service) DevLogin(ctx context.Context, email, ip, userAgent string) (string, error) {
	u, err := s.Store.LocalUserByEmail(ctx, email)
	if err != nil {
		return "", fmt.Errorf("dev user %s: %w", email, err)
	}
	if u.Disabled {
		return "", ErrInvalidLogin
	}
	now := s.Now()
	token := newSessionToken()
	if err := s.Store.CreateSession(ctx, sha256.Sum256([]byte(token)), u.ID, now, now.Add(s.SessionMax), ip, userAgent); err != nil {
		return "", err
	}
	return token, s.Store.Audit(ctx, store.AuditEntry{Actor: fmt.Sprintf("user:%d", u.ID), Action: "login.dev", Target: u.Email, IP: ip})
}
