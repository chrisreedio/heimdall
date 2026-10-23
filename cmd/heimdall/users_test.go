// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/store"
)

// totpNow computes the current 6-digit code for a secret (RFC 6238).
func totpNow(secret []byte, offset int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(time.Now().Unix()/30+offset))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

func (c *cli) user(t *testing.T, cmd command, input string, args ...string) (string, error) {
	t.Helper()
	stdin = strings.NewReader(input)
	t.Cleanup(func() { stdin = os.Stdin })
	var out, errOut bytes.Buffer
	err := cmd(&app{ctx: t.Context(), configPath: c.config, stdout: &out, stderr: &errOut}, args)
	return out.String() + errOut.String(), err
}

func TestUserCommands(t *testing.T) {
	c := newCLI(t)
	c.ok("init")
	secret := []byte("12345678901234567890")
	newTOTPSecret = func() []byte { return bytes.Clone(secret) }
	t.Cleanup(func() { newTOTPSecret = auth.NewTOTPSecret })

	// Weak password and wrong code are refused, and nothing is created.
	if _, err := c.user(t, cmdUserCreate, "short\n", "--password-stdin", "a@example.com"); err == nil {
		t.Error("weak password accepted")
	}
	if _, err := c.user(t, cmdUserCreate, "correct horse battery\n000000\n", "--password-stdin", "a@example.com"); err == nil {
		t.Error("wrong code accepted")
	}
	// Without --password-stdin, a non-terminal stdin is refused.
	if _, err := c.user(t, cmdUserCreate, "", "a@example.com"); err == nil || !strings.Contains(err.Error(), "--password-stdin") {
		t.Errorf("non-terminal: %v", err)
	}

	out, err := c.user(t, cmdUserCreate, "correct horse battery\n"+totpNow(secret, 0)+"\n",
		"--password-stdin", "--admin", "--name", "Admin", "Admin@Example.com")
	if err != nil {
		t.Fatalf("create: %v\n%s", err, out)
	}
	if !strings.Contains(out, "GEZD GNBV") || !strings.Contains(out, "otpauth://totp/Heimdall:admin@example.com") {
		t.Errorf("enrollment output:\n%s", out)
	}
	if _, err := c.user(t, cmdUserCreate, "", "--password-stdin", "admin@example.com"); err == nil {
		t.Error("duplicate user created")
	}

	out, err = c.user(t, cmdUserList, "")
	if err != nil || !strings.Contains(out, "admin@example.com") || !strings.Contains(out, "yes") || !strings.Contains(out, "active") {
		t.Fatalf("list: %v\n%s", err, out)
	}

	// The enrollment code can't be used to sign in; the password works.
	cfg, _ := config.Load(c.config)
	st, err := store.Open(t.Context(), cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc := &auth.Service{Store: st, Now: time.Now, SessionIdle: time.Hour, SessionMax: time.Hour}
	if _, err := svc.Login(t.Context(), "admin@example.com", "correct horse battery", totpNow(secret, 0), "127.0.0.1", ""); err == nil {
		t.Error("enrollment code reused for login")
	}
	if _, err := svc.Login(t.Context(), "admin@example.com", "correct horse battery", totpNow(secret, 1), "127.0.0.1", ""); err != nil {
		t.Fatalf("login: %v", err)
	}

	if _, err := c.user(t, cmdUserPasswd, "another long passphrase\n", "--password-stdin", "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.user(t, cmdUserDisable, "", "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	if out, _ := c.user(t, cmdUserList, ""); !strings.Contains(out, "disabled") {
		t.Errorf("not disabled:\n%s", out)
	}
	if _, err := c.user(t, cmdUserEnable, "", "admin@example.com"); err != nil {
		t.Fatal(err)
	}

	secret = []byte("abcdefghijabcdefghij")
	if _, err := c.user(t, cmdUserResetTOTP, totpNow(secret, 0)+"\n", "--password-stdin", "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	u, _ := st.LocalUserByEmail(t.Context(), "admin@example.com")
	if string(u.TOTPSecret) != string(secret) || u.TOTPLastStep == 0 {
		t.Errorf("reset-totp: secret %q step %d", u.TOTPSecret, u.TOTPLastStep)
	}
	if _, err := c.user(t, cmdUserPasswd, "x\n", "--password-stdin", "ghost@example.com"); err == nil {
		t.Error("unknown user")
	}
}
