// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// A device session outlives the idle and absolute limits while it's used,
// renewing for DeviceSessionMax from each use, and ends a month after the
// last one. Normal sessions keep their limits.
func TestDeviceSessionRenewal(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	iphone := "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
	tok, err := e.svc.Login(t.Context(), email, password, e.code(), "203.0.113.5", iphone, true)
	if err != nil {
		t.Fatal(err)
	}
	start := e.now
	for range 9 { // used every 10 days for 90 days
		e.now = e.now.Add(10 * 24 * time.Hour)
		v, err := e.svc.Session(t.Context(), tok)
		if err != nil || !v.Kept || !v.Renewed {
			t.Fatalf("day %.0f: %+v %v", e.now.Sub(start).Hours()/24, v, err)
		}
	}
	// A request within touchEvery doesn't renew again (no cookie churn).
	if v, _ := e.svc.Session(t.Context(), tok); v == nil || v.Renewed {
		t.Errorf("renewed twice in a minute: %+v", v)
	}
	sessions, err := e.st.UserSessions(t.Context(), e.userID, e.now)
	if err != nil || len(sessions) != 1 || !sessions[0].Kept || sessions[0].Label != "iPhone Safari" ||
		!sessions[0].ExpiresAt.Equal(e.now.Add(DeviceSessionMax)) {
		t.Fatalf("sessions: %+v %v", sessions, err)
	}
	// Unused for longer than DeviceSessionMax: gone.
	e.now = e.now.Add(DeviceSessionMax + time.Minute)
	if _, err := e.svc.Session(t.Context(), tok); !errors.Is(err, ErrNoSession) {
		t.Fatalf("after a month unused: %v", err)
	}

	// A normal session from the same user still ends when idle.
	normal, err := e.login(email, password, e.code())
	if err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(31 * time.Minute)
	if _, err := e.svc.Session(t.Context(), normal); !errors.Is(err, ErrNoSession) {
		t.Fatalf("normal session outlived idle: %v", err)
	}
}

// Revoking a session (from the Devices list) ends it at once, and only the
// owner's sessions can be named.
func TestRevokeSession(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tok, err := e.svc.Login(t.Context(), email, password, e.code(), "203.0.113.5", "", true)
	if err != nil {
		t.Fatal(err)
	}
	ref := store.SessionRef(sha256.Sum256([]byte(tok)))
	if err := e.st.RevokeSession(t.Context(), "user:99", e.userID+1, ref, ""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another user's ref: %v", err)
	}
	if _, err := e.svc.Session(t.Context(), tok); err != nil {
		t.Fatalf("before revoking: %v", err)
	}
	if err := e.st.RevokeSession(t.Context(), "user:1", e.userID, ref, "203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Session(t.Context(), tok); !errors.Is(err, ErrNoSession) {
		t.Errorf("after revoking: %v", err)
	}
	if at, _ := e.st.LastAuditAt(t.Context(), "session.revoke"); at.IsZero() {
		t.Error("revoke not audited")
	}
	for _, bad := range []string{"", "nothex!!nothex!!", ref + "00", "'; DROP TABLE x"} {
		if err := e.st.RevokeSession(t.Context(), "user:1", e.userID, bad, ""); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ref %q: %v", bad, err)
		}
	}
}
