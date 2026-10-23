// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

func TestRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, tt := range []struct {
		unix int64
		code string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}} {
		if got := hotp(secret, uint64(tt.unix/30), 8); got != tt.code {
			t.Errorf("T=%d: got %s want %s", tt.unix, got, tt.code)
		}
		// The 6-digit code is the same truncation mod 10^6.
		step, ok := VerifyTOTP(secret, tt.code[2:], time.Unix(tt.unix, 0))
		if !ok || step != tt.unix/30 {
			t.Errorf("T=%d: 6-digit %s not accepted (step %d)", tt.unix, tt.code[2:], step)
		}
	}
}

func TestVerifyTOTPWindow(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	cur := now.Unix() / 30
	for _, d := range []int64{-1, 0, 1} {
		if _, ok := VerifyTOTP(secret, totpAt(secret, cur+d), now); !ok {
			t.Errorf("drift %d rejected", d)
		}
	}
	for _, d := range []int64{-2, 2} {
		if _, ok := VerifyTOTP(secret, totpAt(secret, cur+d), now); ok {
			t.Errorf("drift %d accepted", d)
		}
	}
	code := totpAt(secret, cur)
	if _, ok := VerifyTOTP(secret, " "+code[:3]+" "+code[3:]+" ", now); !ok {
		t.Error("spaces should be ignored")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "12345a"} {
		if _, ok := VerifyTOTP(secret, bad, now); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTOTPURI(t *testing.T) {
	uri := TOTPURI("Heimdall", "a@b.co", []byte("12345678901234567890"))
	for _, want := range []string{"otpauth://totp/Heimdall:a@b.co?", "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "issuer=Heimdall", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI %q missing %q", uri, want)
		}
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Errorf("hash = %s", h)
	}
	if ok, err := VerifyPassword(h, "correct horse battery"); !ok || err != nil {
		t.Errorf("verify: %v %v", ok, err)
	}
	if ok, _ := VerifyPassword(h, "wrong horse battery"); ok {
		t.Error("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Error("salt not random")
	}
	parts := strings.Split(h, "$")
	for name, bad := range map[string]string{
		"argon2i":     strings.Replace(h, "argon2id", "argon2i", 1),
		"huge memory": strings.Join([]string{"", parts[1], parts[2], "m=4194304,t=3,p=2", parts[4], parts[5]}, "$"),
		"huge time":   strings.Join([]string{"", parts[1], parts[2], "m=65536,t=99,p=2", parts[4], parts[5]}, "$"),
		"bad base64":  strings.Join([]string{"", parts[1], parts[2], parts[3], "!!!", parts[5]}, "$"),
		"truncated":   strings.Join(parts[:5], "$"),
		"empty":       "",
	} {
		if ok, err := VerifyPassword(bad, "correct horse battery"); ok || err == nil {
			t.Errorf("%s: ok=%v err=%v", name, ok, err)
		}
	}
	// A tampered key just fails to match.
	tampered := strings.Join([]string{"", parts[1], parts[2], parts[3], parts[4], b64.EncodeToString(make([]byte, 32))}, "$")
	if ok, err := VerifyPassword(tampered, "correct horse battery"); ok || err != nil {
		t.Errorf("tampered: ok=%v err=%v", ok, err)
	}
}

func TestPasswordPolicy(t *testing.T) {
	for _, bad := range []string{"short", "aaaaaaaaaaaaaaaa", "Password1234", strings.Repeat("x", 100) + strings.Repeat("y", 200)} {
		if CheckPasswordPolicy(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := CheckPasswordPolicy("correct horse battery"); err != nil {
		t.Error(err)
	}
}

func TestCSRF(t *testing.T) {
	tok := newSessionToken()
	c := CSRFToken(tok)
	if !ValidCSRF(tok, c) || ValidCSRF(tok, c+"x") || ValidCSRF(newSessionToken(), c) || ValidCSRF("", CSRFToken("")) {
		t.Error("CSRF validation wrong")
	}
}

// ── Service ────────────────────────────────────────────────────────────────

type env struct {
	t      *testing.T
	st     *store.Store
	svc    *Service
	now    time.Time
	secret []byte
	userID int64
}

const (
	email    = "admin@example.com"
	password = "correct horse battery"
)

func newEnv(t *testing.T) *env {
	t.Helper()
	path := filepath.Join(t.TempDir(), "h.db")
	if err := store.Create(path); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, st: st, now: time.Unix(1_800_000_000, 0), secret: NewTOTPSecret()}
	hash, _ := HashPassword(password)
	if e.userID, err = st.CreateLocalUser(t.Context(), "test", email, "Admin", true, hash, e.secret); err != nil {
		t.Fatal(err)
	}
	e.svc = &Service{Store: st, Now: func() time.Time { return e.now }, SessionIdle: 30 * time.Minute, SessionMax: 12 * time.Hour}
	return e
}

func (e *env) code() string { return totpAt(e.secret, e.now.Unix()/30) }

func (e *env) login(em, pw, code string) (string, error) {
	return e.svc.Login(e.t.Context(), em, pw, code, "203.0.113.5", "test-agent")
}

func TestLoginAndSession(t *testing.T) {
	e := newEnv(t)
	tok, err := e.login("  Admin@Example.com ", password, e.code())
	if err != nil {
		t.Fatal(err)
	}
	v, err := e.svc.Session(t.Context(), tok)
	if err != nil || v.Email != email || !v.IsAdmin || v.SessionToken != tok || v.UserID != e.userID {
		t.Fatalf("session: %+v %v", v, err)
	}
	u, _ := e.st.UserByID(t.Context(), e.userID)
	if u.LastLoginAt.IsZero() {
		t.Error("last_login_at not set")
	}
	if err := e.svc.Logout(t.Context(), tok); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Session(t.Context(), tok); !errors.Is(err, ErrNoSession) {
		t.Errorf("after logout: %v", err)
	}
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	e := newEnv(t)
	cases := map[string][3]string{
		"wrong password": {email, "wrong password!!", e.code()},
		"unknown user":   {"nobody@example.com", password, e.code()},
		"bad code":       {email, password, "000000"},
		"bad email":      {"not an email", password, e.code()},
	}
	for name, c := range cases {
		if _, err := e.login(c[0], c[1], c[2]); !errors.Is(err, ErrInvalidLogin) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReplayedCodeRejected(t *testing.T) {
	e := newEnv(t)
	code := e.code()
	if _, err := e.login(email, password, code); err != nil {
		t.Fatal(err)
	}
	if _, err := e.login(email, password, code); !errors.Is(err, ErrInvalidLogin) {
		t.Fatalf("replay: %v", err)
	}
	// The previous step's code (still inside the window) is also stale now.
	if _, err := e.login(email, password, totpAt(e.secret, e.now.Unix()/30-1)); !errors.Is(err, ErrInvalidLogin) {
		t.Fatalf("older step: %v", err)
	}
	e.now = e.now.Add(30 * time.Second)
	if _, err := e.login(email, password, e.code()); err != nil {
		t.Fatalf("next step: %v", err)
	}
}

func TestThrottling(t *testing.T) {
	e := newEnv(t)
	for range maxFailuresPerUser {
		if _, err := e.login(email, "wrong password!!", e.code()); !errors.Is(err, ErrInvalidLogin) {
			t.Fatal(err)
		}
	}
	// Locked out even with the right credentials.
	if _, err := e.login(email, password, e.code()); !errors.Is(err, ErrThrottled) {
		t.Fatalf("want throttled, got %v", err)
	}
	e.now = e.now.Add(throttleWindow + time.Minute)
	if _, err := e.login(email, password, e.code()); err != nil {
		t.Fatalf("after window: %v", err)
	}

	// Per-IP: many accounts from one address.
	e2 := newEnv(t)
	for i := range maxFailuresPerIP {
		e2.login("user"+string(rune('a'+i))+"@example.com", password, "000000")
	}
	if _, err := e2.login(email, password, e2.code()); !errors.Is(err, ErrThrottled) {
		t.Fatalf("per-IP: want throttled, got %v", err)
	}
	if _, err := e2.svc.Login(t.Context(), email, password, e2.code(), "198.51.100.1", ""); err != nil {
		t.Fatalf("other IP: %v", err)
	}
}

func TestDisabledUser(t *testing.T) {
	e := newEnv(t)
	tok, err := e.login(email, password, e.code())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetUserDisabled(t.Context(), "test", email, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Session(t.Context(), tok); !errors.Is(err, ErrNoSession) {
		t.Errorf("session survived disable: %v", err)
	}
	e.now = e.now.Add(30 * time.Second)
	if _, err := e.login(email, password, e.code()); !errors.Is(err, ErrInvalidLogin) {
		t.Errorf("disabled login: %v", err)
	}
}

func TestSessionTimeouts(t *testing.T) {
	e := newEnv(t)
	tok, _ := e.login(email, password, e.code())

	// Activity keeps it alive past the idle limit...
	for range 5 {
		e.now = e.now.Add(20 * time.Minute)
		if _, err := e.svc.Session(t.Context(), tok); err != nil {
			t.Fatalf("active session expired: %v", err)
		}
	}
	// ...but idle for longer than SessionIdle ends it.
	e.now = e.now.Add(31 * time.Minute)
	if _, err := e.svc.Session(t.Context(), tok); !errors.Is(err, ErrNoSession) {
		t.Fatalf("idle: %v", err)
	}

	// The absolute limit applies even to active sessions.
	e.now = e.now.Add(time.Minute)
	tok2, err := e.login(email, password, e.code())
	if err != nil {
		t.Fatal(err)
	}
	for elapsed := time.Duration(0); elapsed < 12*time.Hour; elapsed += 25 * time.Minute {
		e.now = e.now.Add(25 * time.Minute)
		if _, err := e.svc.Session(t.Context(), tok2); err != nil {
			if elapsed+25*time.Minute < 12*time.Hour {
				t.Fatalf("expired early at %v: %v", elapsed, err)
			}
			return
		}
	}
	t.Fatal("session outlived SessionMax")
}

func TestMalformedTokens(t *testing.T) {
	e := newEnv(t)
	for _, tok := range []string{"", "x", sessionPrefix, sessionPrefix + strings.Repeat("A", 43), "hmd_ingest_" + strings.Repeat("A", 43)} {
		if _, err := e.svc.Session(t.Context(), tok); !errors.Is(err, ErrNoSession) {
			t.Errorf("%q: %v", tok, err)
		}
		if err := e.svc.Logout(t.Context(), tok); err != nil {
			t.Errorf("logout %q: %v", tok, err)
		}
	}
}
