// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLocalUsers(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	id, err := s.CreateLocalUser(ctx, "test", " Admin@Example.COM ", "Admin", true, "$argon2id$x", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateLocalUser(ctx, "test", "admin@example.com", "", false, "h", []byte("s")); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate: %v", err)
	}
	var ve *ValidationError
	for _, bad := range []string{"", "nope", "a@b", "a b@example.com"} {
		if _, err := s.CreateLocalUser(ctx, "test", bad, "", false, "h", []byte("s")); !errors.As(err, &ve) {
			t.Errorf("email %q: %v", bad, err)
		}
	}

	u, err := s.LocalUserByEmail(ctx, "ADMIN@example.com")
	if err != nil || u.ID != id || u.Email != "admin@example.com" || !u.IsAdmin || u.Kind != "local" || string(u.TOTPSecret) != "secret" {
		t.Fatalf("lookup: %+v %v", u, err)
	}
	if _, err := s.LocalUserByEmail(ctx, "other@example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}

	// TOTP steps only move forward.
	if ok, err := s.AcceptTOTPStep(ctx, id, 100); !ok || err != nil {
		t.Fatalf("first step: %v %v", ok, err)
	}
	if ok, _ := s.AcceptTOTPStep(ctx, id, 100); ok {
		t.Error("same step accepted twice")
	}
	if ok, _ := s.AcceptTOTPStep(ctx, id, 99); ok {
		t.Error("older step accepted")
	}
	if ok, _ := s.AcceptTOTPStep(ctx, id, 101); !ok {
		t.Error("newer step rejected")
	}

	// Sessions, and that account changes end them.
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	newSession := func() [32]byte {
		h := sha256.Sum256([]byte(now.String() + t.Name()))
		now = now.Add(time.Second)
		if err := s.CreateSession(ctx, h, id, now, now.Add(time.Hour), "203.0.113.5", "ua"); err != nil {
			t.Fatal(err)
		}
		return h
	}
	h := newSession()
	sess, su, err := s.SessionByHash(ctx, h)
	if err != nil || sess.UserID != id || su.Email != "admin@example.com" || !sess.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("session: %+v %+v %v", sess, su, err)
	}
	if err := s.TouchSession(ctx, h, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if sess, _, _ := s.SessionByHash(ctx, h); !sess.LastSeenAt.Equal(now.Add(time.Minute)) {
		t.Errorf("touch: %v", sess.LastSeenAt)
	}

	for name, change := range map[string]func() error{
		"disable":  func() error { return s.SetUserDisabled(ctx, "test", "admin@example.com", true) },
		"password": func() error { return s.SetPassword(ctx, "test", "admin@example.com", "new") },
		"totp":     func() error { return s.SetTOTP(ctx, "test", "admin@example.com", []byte("new")) },
	} {
		h := newSession()
		if err := change(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, _, err := s.SessionByHash(ctx, h); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: session survived", name)
		}
	}
	u, _ = s.UserByID(ctx, id)
	if !u.Disabled || u.PasswordHash != "new" || string(u.TOTPSecret) != "new" || u.TOTPLastStep != 0 {
		t.Errorf("after changes: %+v", u)
	}
	if err := s.SetUserDisabled(ctx, "test", "admin@example.com", false); err != nil {
		t.Fatal(err)
	}
	if u, _ = s.UserByID(ctx, id); u.Disabled {
		t.Error("enable failed")
	}
	if err := s.SetPassword(ctx, "test", "ghost@example.com", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}

	if n, err := s.DeleteExpiredSessions(ctx, now.Add(2*time.Hour)); err != nil || n < 0 {
		t.Errorf("expire: %d %v", n, err)
	}

	users, err := s.ListUsers(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("list: %+v %v", users, err)
	}

	if err := s.Audit(ctx, AuditEntry{Actor: "anon", Action: "login.failure", Detail: map[string]any{"reason": "bad_password"}}); err != nil {
		t.Fatal(err)
	}
	var actions string
	s.db.QueryRowContext(ctx, `SELECT group_concat(action, ' ') FROM (SELECT action FROM audit_log ORDER BY id)`).Scan(&actions)
	for _, a := range []string{"user.create", "user.disable", "user.password", "user.totp_reset", "user.enable", "login.failure"} {
		if !slices.Contains(strings.Fields(actions), a) {
			t.Errorf("audit log %q missing %s", actions, a)
		}
	}
}
