// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"crypto/sha256"
	"testing"
	"time"
)

func TestSettings(t *testing.T) {
	t.Parallel()
	s, ctx := newStore(t), t.Context()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	if v, ok, err := s.Setting(ctx, "stepup"); v != "" || ok || err != nil {
		t.Fatalf("unset: %q %v %v", v, ok, err)
	}
	for _, v := range []string{"admin", "every"} {
		if err := s.SetSetting(ctx, "user:1", "stepup", v, now); err != nil {
			t.Fatal(err)
		}
	}
	if v, ok, _ := s.Setting(ctx, "stepup"); v != "every" || !ok {
		t.Errorf("set: %q %v", v, ok)
	}
	if at, _ := s.LastAuditAt(ctx, "setting.stepup"); at.IsZero() {
		t.Error("not audited")
	}
	if err := s.SetSetting(ctx, "user:1", "", "x", now); err == nil {
		t.Error("an empty key was stored")
	}
}

func TestSessionStepUp(t *testing.T) {
	t.Parallel()
	s, ctx := newStore(t), t.Context()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	id, err := s.CreateLocalUser(ctx, "test", "a@example.com", "", false, "$argon2id$x", []byte("01234567890123456789"))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("tok"))
	if err := s.CreateSession(ctx, hash, id, now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	if sess, _, _ := s.SessionByHash(ctx, hash); !sess.SteppedUpAt.IsZero() {
		t.Errorf("new session stepped up at %v", sess.SteppedUpAt)
	}
	if err := s.SetSessionStepUp(ctx, hash, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if sess, _, _ := s.SessionByHash(ctx, hash); !sess.SteppedUpAt.Equal(now.Add(time.Minute)) {
		t.Errorf("stepped up at %v", sess.SteppedUpAt)
	}
}
