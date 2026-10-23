// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

// Login throttling: failures allowed per window, per source IP and per
// account. Kept in memory; a restart resets it, which is acceptable for a
// private UI with mandatory TOTP.
const (
	throttleWindow     = 15 * time.Minute
	maxFailuresPerIP   = 10
	maxFailuresPerUser = 5
	maxThrottleKeys    = 10000
	// touchEvery limits session last_seen_at writes to one per minute.
	touchEvery = time.Minute
)

// sessionPrefix marks session cookies so they're recognizable.
const sessionPrefix = "hmd_sess_"

// Service implements login, session lookup and logout for local and
// Entra ID accounts.
type Service struct {
	Store       *store.Store
	Now         func() time.Time
	SessionIdle time.Duration
	SessionMax  time.Duration
	// DisableLocal turns off password logins (auth.local_login = false) and
	// ends local users' sessions. Accounts stay manageable from the CLI.
	DisableLocal bool
	// SyncAppRoles maps Entra app roles to Heimdall roles on each login
	// (auth.entra.app_role_mapping).
	SyncAppRoles bool

	mu       sync.Mutex
	failures map[string][]time.Time // "ip:<addr>" or "user:<email>" -> failure times
}

// Login checks email, password and TOTP code and returns a new session
// token. User-facing failures are only ErrInvalidLogin or ErrThrottled.
func (s *Service) Login(ctx context.Context, email, password, code, ip, userAgent string) (string, error) {
	if s.DisableLocal {
		return "", ErrInvalidLogin
	}
	now := s.Now()
	emailKey := strings.ToLower(strings.TrimSpace(email))
	ipKey, userKey := "ip:"+ip, "user:"+emailKey

	fail := func(userID int64, reason string) (string, error) {
		s.recordFailure(ipKey, now)
		s.recordFailure(userKey, now)
		return "", s.auditLogin(ctx, userID, false, reason, emailKey, ip, ErrInvalidLogin)
	}

	if s.throttled(ipKey, maxFailuresPerIP, now) || s.throttled(userKey, maxFailuresPerUser, now) {
		return "", s.auditLogin(ctx, 0, false, "throttled", emailKey, ip, ErrThrottled)
	}

	u, err := s.Store.LocalUserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		VerifyPassword(dummyHash, password) // same work as a real check
		return fail(0, "unknown_user")
	}
	if err != nil {
		return "", err
	}
	ok, err := VerifyPassword(u.PasswordHash, password)
	if err != nil {
		return "", fmt.Errorf("verify password for user %d: %w", u.ID, err)
	}
	if !ok {
		return fail(u.ID, "bad_password")
	}
	step, ok := VerifyTOTP(u.TOTPSecret, code, now)
	if !ok {
		return fail(u.ID, "bad_code")
	}
	if u.Disabled {
		// Checked after the credentials so a disabled account isn't revealed.
		return fail(u.ID, "disabled")
	}
	fresh, err := s.Store.AcceptTOTPStep(ctx, u.ID, step)
	if err != nil {
		return "", err
	}
	if !fresh {
		return fail(u.ID, "replayed_code")
	}

	token := newSessionToken()
	if err := s.Store.CreateSession(ctx, sha256.Sum256([]byte(token)), u.ID, now, now.Add(s.SessionMax), ip, userAgent); err != nil {
		return "", err
	}
	s.clearFailures(userKey)
	if err := s.auditLogin(ctx, u.ID, true, "", emailKey, ip, nil); err != nil {
		return "", err
	}
	return token, nil
}

// auditLogin records a login attempt and returns ret (or an audit error).
func (s *Service) auditLogin(ctx context.Context, userID int64, success bool, reason, email, ip string, ret error) error {
	actor, action := "anon", "login.failure"
	if userID != 0 {
		actor = fmt.Sprintf("user:%d", userID)
	}
	e := store.AuditEntry{Actor: actor, Action: action, Target: truncate(email, 254), IP: ip}
	if success {
		e.Action = "login.success"
	} else {
		e.Detail = map[string]any{"reason": reason}
	}
	if err := s.Store.Audit(ctx, e); err != nil {
		return err
	}
	return ret
}

// Session resolves a session token to its user, enforcing idle and
// absolute timeouts. Any problem is ErrNoSession.
func (s *Service) Session(ctx context.Context, token string) (*Viewer, error) {
	if !validTokenShape(token) {
		return nil, ErrNoSession
	}
	hash := sha256.Sum256([]byte(token))
	sess, u, err := s.Store.SessionByHash(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	now := s.Now()
	kindOK := u.Kind == "entra" || (u.Kind == "local" && !s.DisableLocal)
	if !now.Before(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > s.SessionIdle || u.Disabled || !kindOK {
		if err := s.Store.DeleteSession(ctx, hash); err != nil {
			return nil, err
		}
		return nil, ErrNoSession
	}
	if now.Sub(sess.LastSeenAt) >= touchEvery {
		if err := s.Store.TouchSession(ctx, hash, now); err != nil {
			return nil, err
		}
	}
	scope, err := s.Store.ScopeFor(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	return &Viewer{UserID: u.ID, Email: u.Email, DisplayName: u.DisplayName, IsAdmin: u.IsAdmin, Kind: u.Kind,
		Scope: scope, SessionToken: token}, nil
}

// LoginIdentity starts a session for a validated Entra ID identity. Only
// pre-provisioned users get in; everyone else gets ErrNotProvisioned.
func (s *Service) LoginIdentity(ctx context.Context, id store.EntraIdentity, roles []string, ip, userAgent string) (string, error) {
	now := s.Now()
	u, err := s.Store.ResolveEntraUser(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		s.Store.Audit(ctx, store.AuditEntry{Actor: "anon", Action: "login.failure", Target: id.Email, IP: ip,
			Detail: map[string]any{"method": "entra", "reason": "not_provisioned", "tenant": id.TenantID, "oid": id.ObjectID}})
		return "", ErrNotProvisioned
	}
	if err != nil {
		return "", err
	}
	if u.Disabled {
		s.Store.Audit(ctx, store.AuditEntry{Actor: fmt.Sprintf("user:%d", u.ID), Action: "login.failure", Target: u.Email,
			IP: ip, Detail: map[string]any{"method": "entra", "reason": "disabled"}})
		return "", ErrNotProvisioned
	}
	if s.SyncAppRoles {
		if err := s.Store.SyncAppRoles(ctx, u.ID, roles); err != nil {
			return "", err
		}
	}
	token := newSessionToken()
	if err := s.Store.CreateSession(ctx, sha256.Sum256([]byte(token)), u.ID, now, now.Add(s.SessionMax), ip, userAgent); err != nil {
		return "", err
	}
	if err := s.Store.Audit(ctx, store.AuditEntry{Actor: fmt.Sprintf("user:%d", u.ID), Action: "login.success",
		Target: u.Email, IP: ip, Detail: map[string]any{"method": "entra", "roles": roles}}); err != nil {
		return "", err
	}
	return token, nil
}

// Logout ends a session. Unknown tokens are not an error.
func (s *Service) Logout(ctx context.Context, token string) error {
	if !validTokenShape(token) {
		return nil
	}
	hash := sha256.Sum256([]byte(token))
	sess, _, err := s.Store.SessionByHash(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.Store.DeleteSession(ctx, hash); err != nil {
		return err
	}
	return s.Store.Audit(ctx, store.AuditEntry{Actor: fmt.Sprintf("user:%d", sess.UserID), Action: "logout"})
}

func newSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return sessionPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func validTokenShape(t string) bool {
	rest, ok := strings.CutPrefix(t, sessionPrefix)
	if !ok || len(rest) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(rest)
	return err == nil
}

func (s *Service) prune(key string, now time.Time) []time.Time {
	ts := s.failures[key]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) > throttleWindow {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(s.failures, key)
	} else {
		s.failures[key] = ts
	}
	return ts
}

func (s *Service) throttled(key string, max int, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures == nil {
		return false
	}
	return len(s.prune(key, now)) >= max
}

func (s *Service) recordFailure(key string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures == nil {
		s.failures = map[string][]time.Time{}
	}
	if len(s.failures) >= maxThrottleKeys {
		for k := range s.failures {
			s.prune(k, now)
		}
		// Still full (a flood of source IPs): drop IP counters, but keep
		// per-account ones so the flood can't reset an account's lockout.
		if len(s.failures) >= maxThrottleKeys {
			for k := range s.failures {
				if strings.HasPrefix(k, "ip:") {
					delete(s.failures, k)
				}
			}
		}
	}
	s.failures[key] = append(s.prune(key, now), now)
}

func (s *Service) clearFailures(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, key)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
