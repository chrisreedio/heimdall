// SPDX-License-Identifier: AGPL-3.0-or-later

package store_test

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

func TestPushVAPIDKeyMadeOnce(t *testing.T) {
	t.Parallel()
	st := storetest.New(t)
	ctx := t.Context()
	calls := 0
	gen := func() ([]byte, error) { calls++; return bytes.Repeat([]byte{byte(calls)}, 32), nil }
	a, err := st.PushVAPIDKey(ctx, gen, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := st.PushVAPIDKey(ctx, gen, time.Now())
	if !bytes.Equal(a, b) || calls != 1 {
		t.Fatalf("key changed or made twice (%d calls)", calls)
	}
}

// A subscription lives as long as its session: revoking the device (or
// signing out, or the session expiring) removes it.
func TestPushSubscriptionsFollowSessions(t *testing.T) {
	t.Parallel()
	st := storetest.New(t)
	ctx := t.Context()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	uid, err := st.CreateLocalUser(ctx, "test", "a@example.com", "A", false, "$argon2id$x", []byte("0123456789abcdefghij"))
	if err != nil {
		t.Fatal(err)
	}
	key := append([]byte{4}, bytes.Repeat([]byte{1}, 64)...)
	auth := bytes.Repeat([]byte{2}, 16)
	for _, s := range []string{"phone", "laptop", "idle"} {
		hash := sha256.Sum256([]byte(s))
		create := st.CreateDeviceSession
		seen := now
		if s == "idle" {
			create, seen = st.CreateSession, now.Add(-2*time.Hour)
		}
		if err := create(ctx, hash, uid, seen, now.Add(24*time.Hour), "", ""); err != nil {
			t.Fatal(err)
		}
		if err := st.SavePushSubscription(ctx, uid, hash, "https://fcm.googleapis.com/fcm/send/"+s, key, auth, s, now); err != nil {
			t.Fatal(err)
		}
	}
	// A normal session idle past ui.session_idle is signed out: not a recipient.
	rs, err := st.PushRecipients(ctx, now, 30*time.Minute)
	if err != nil || len(rs) != 1 || len(rs[0].Subs) != 2 || rs[0].Settings.QuietStart != 22 {
		t.Fatalf("recipients: %+v %v", rs, err)
	}
	if err := st.RevokeSession(ctx, "test", uid, store.SessionRef(sha256.Sum256([]byte("phone"))), ""); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSession(ctx, sha256.Sum256([]byte("laptop"))); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.DeleteExpiredSessions(ctx, now.Add(48*time.Hour)); n != 1 {
		t.Fatalf("expired %d", n)
	}
	if subs, _ := st.UserPushSubscriptions(ctx, uid); len(subs) != 0 {
		t.Errorf("subscriptions outlived their sessions: %+v", subs)
	}

	// The same endpoint from a new sign-in moves to the new session.
	hash := sha256.Sum256([]byte("again"))
	st.CreateDeviceSession(ctx, hash, uid, now, now.Add(time.Hour), "", "")
	for range 2 {
		if err := st.SavePushSubscription(ctx, uid, hash, "https://fcm.googleapis.com/fcm/send/x", key, auth, "x", now); err != nil {
			t.Fatal(err)
		}
	}
	if subs, _ := st.UserPushSubscriptions(ctx, uid); len(subs) != 1 {
		t.Errorf("%d subscriptions for one endpoint", len(subs))
	}
}

func TestPushSettingsAndHeld(t *testing.T) {
	t.Parallel()
	st := storetest.New(t)
	ctx := t.Context()
	uid, _ := st.CreateLocalUser(ctx, "test", "a@example.com", "A", false, "$argon2id$x", []byte("0123456789abcdefghij"))
	if p, err := st.PushSettings(ctx, uid); err != nil || !p.Quiet || p.QuietStart != 22 || p.QuietEnd != 7 || p.Detail != "host" {
		t.Fatalf("defaults: %+v %v", p, err)
	}
	// The browser's zone is taken only while none is set.
	st.SetPushTimeZoneIfUnset(ctx, uid, "America/Chicago")
	st.SetPushTimeZoneIfUnset(ctx, uid, "Europe/Berlin")
	p, _ := st.PushSettings(ctx, uid)
	if p.TimeZone != "America/Chicago" {
		t.Errorf("zone %q", p.TimeZone)
	}
	p.Modes, p.Detail, p.QuietStart = map[string]string{"anomaly": "off"}, "hidden", 23
	if err := st.SetPushSettings(ctx, uid, p); err != nil {
		t.Fatal(err)
	}
	if err := st.SetPushDigestDay(ctx, uid, "2026-10-30"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.PushSettings(ctx, uid)
	if got.Modes["anomaly"] != "off" || got.Detail != "hidden" || got.QuietStart != 23 || got.DigestDay != "2026-10-30" || got.TimeZone != "America/Chicago" {
		t.Errorf("settings %+v", got)
	}
	p.QuietEnd = 24
	if err := st.SetPushSettings(ctx, uid, p); err == nil {
		t.Error("hour 24 accepted")
	}

	now := time.Now()
	st.HoldPush(ctx, uid, false, store.PushHeld{Kind: "anomaly", Host: "web-01", Count: 1, At: now})
	st.HoldPush(ctx, uid, false, store.PushHeld{Kind: "silent", Host: "web-02", Count: 1, At: now})
	st.HoldPush(ctx, uid, true, store.PushHeld{Kind: "kev", Host: "web-03", Count: 2, At: now})
	if w, _ := st.PushHeldUsers(ctx, false); !w[uid] {
		t.Error("held users")
	}
	held, err := st.TakePushHeld(ctx, uid, false)
	if err != nil || len(held) != 2 || held[0].Kind != "anomaly" || held[1].Kind != "silent" {
		t.Fatalf("held %+v %v", held, err)
	}
	if again, _ := st.TakePushHeld(ctx, uid, false); len(again) != 0 {
		t.Error("taken twice")
	}
	if digest, _ := st.TakePushHeld(ctx, uid, true); len(digest) != 1 || digest[0].Count != 2 {
		t.Errorf("digest %+v", digest)
	}
}
