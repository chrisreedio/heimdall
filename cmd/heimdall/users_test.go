// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/store"
)

// totpNow computes the current 6-digit code for a secret (RFC 6238).
// awayFromStepBoundary waits out a TOTP step boundary that's less than 5s
// away, so codes computed at the start of a test stay current to its end.
func awayFromStepBoundary() {
	if left := 30 - time.Now().Unix()%30; left < 5 {
		time.Sleep(time.Duration(left)*time.Second + 100*time.Millisecond)
	}
}

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
	var out, errOut bytes.Buffer
	err := cmd(&app{ctx: t.Context(), configPath: c.config, stdin: strings.NewReader(input), stdout: &out, stderr: &errOut,
		newTOTPSecret: c.newTOTPSecret}, args)
	return out.String() + errOut.String(), err
}

func TestUserCommands(t *testing.T) {
	t.Parallel()
	awayFromStepBoundary()
	c := newCLI(t)
	c.init()
	secret := []byte("12345678901234567890")
	c.newTOTPSecret = func() []byte { return bytes.Clone(secret) }

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
	if _, err := svc.Login(t.Context(), "admin@example.com", "correct horse battery", totpNow(secret, 0), "127.0.0.1", "", false); err == nil {
		t.Error("enrollment code reused for login")
	}
	if _, err := svc.Login(t.Context(), "admin@example.com", "correct horse battery", totpNow(secret, 1), "127.0.0.1", "", false); err != nil {
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

func TestUserDelete(t *testing.T) {
	t.Parallel()
	awayFromStepBoundary()
	c := newCLI(t)
	c.init()
	const tenantA, tenantB = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	secret := []byte("12345678901234567890")
	c.newTOTPSecret = func() []byte { return bytes.Clone(secret) }
	if out, err := c.user(t, cmdUserCreate, "correct horse battery\n"+totpNow(secret, 0)+"\n", "--password-stdin", "--admin", "admin@example.com"); err != nil {
		t.Fatalf("create admin: %v\n%s", err, out)
	}
	c.ok("user", "create", "--entra", "--tenant", tenantA, "alice@example.com") // #2
	c.ok("user", "create", "--entra", "--tenant", tenantB, "alice@example.com") // #3

	// A second Entra user with the same email in a tenant is refused.
	if _, _, err := c.run("user", "create", "--entra", "--tenant", tenantA, "Alice@example.com"); err == nil ||
		!strings.Contains(err.Error(), "already exists (#2, pending first sign-in)") {
		t.Errorf("duplicate Entra user: %v", err)
	}

	if _, _, err := c.run("user", "delete", "--yes"); err == nil {
		t.Error("no user accepted")
	}
	if _, _, err := c.run("user", "delete", "--yes", "#x"); err == nil || !strings.Contains(err.Error(), "#<id>") {
		t.Errorf("bad ID: %v", err)
	}
	if _, _, err := c.run("user", "delete", "--yes", "#99"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("unknown ID: %v", err)
	}
	// An email two users share lists both, so the caller can pick.
	_, _, err := c.run("user", "delete", "--yes", "alice@example.com")
	if err == nil || !strings.Contains(err.Error(), "#2, entra, active") || !strings.Contains(err.Error(), "#3, entra, active") {
		t.Errorf("ambiguous email: %v", err)
	}
	// Without --yes nothing happens.
	if _, _, err := c.run("user", "delete", "#3"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("no --yes: %v", err)
	}
	if out := c.ok("user", "list"); strings.Count(out, "alice@example.com") != 2 {
		t.Fatalf("deleted without --yes:\n%s", out)
	}
	_, errOut, err := c.run("user", "delete", "#3", "--yes")
	if err != nil || !strings.Contains(errOut, "Deleted alice@example.com (#3, entra, active)") {
		t.Fatalf("delete: %v\n%s", err, errOut)
	}
	// Now the email is unambiguous.
	c.ok("user", "delete", "--yes", "alice@example.com")
	if out := c.ok("user", "list"); strings.Contains(out, "alice@") {
		t.Errorf("still listed:\n%s", out)
	}
	// The last admin who can sign in stays.
	if _, _, err := c.run("user", "delete", "--yes", "admin@example.com"); err == nil || !strings.Contains(err.Error(), "last active admin") {
		t.Errorf("last admin: %v", err)
	}
}

func TestSharedEmailPickedByKind(t *testing.T) {
	t.Parallel()
	awayFromStepBoundary()
	c := newCLI(t)
	c.init()
	c.ok("org", "create", "acme")
	secret := []byte("12345678901234567890")
	c.newTOTPSecret = func() []byte { return bytes.Clone(secret) }
	if out, err := c.user(t, cmdUserCreate, "correct horse battery\n"+totpNow(secret, 0)+"\n", "--password-stdin", "chris@example.com"); err != nil {
		t.Fatalf("create local: %v\n%s", err, out)
	}
	c.ok("user", "create", "--entra", "--tenant", "11111111-1111-1111-1111-111111111111", "chris@example.com")

	_, _, err := c.run("user", "grant", "--role", "operator", "chris@example.com")
	if err == nil || !strings.Contains(err.Error(), "--local or --entra") {
		t.Fatalf("ambiguous email: %v", err)
	}
	c.ok("user", "grant", "--role", "operator", "--entra", "chris@example.com")
	out := c.ok("user", "list")
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, " entra ") != strings.Contains(l, "acme:operator") && strings.Contains(l, "chris@") {
			t.Errorf("role landed on the wrong account:\n%s", out)
		}
	}
	c.ok("user", "disable", "--local", "chris@example.com")
	c.ok("user", "revoke", "--entra", "chris@example.com")
	if _, _, err := c.run("user", "grant", "--role", "viewer", "--local", "--entra", "chris@example.com"); err == nil {
		t.Error("--local with --entra accepted")
	}
	if _, _, err := c.run("user", "grant", "--role", "viewer", "--entra", "nobody@example.com"); err == nil {
		t.Error("missing account accepted")
	}
}

func TestTokenPurposeCLI(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.init()
	c.ok("user", "create", "--entra", "--tenant", "11111111-1111-1111-1111-111111111111", "chris@example.com")
	out, errOut, err := c.run("user", "mcp-token", "create", "--purpose", "threats", "--name", "edge firewall", "chris@example.com")
	if err != nil || !strings.HasPrefix(out, "hmd_threats_") || !strings.Contains(errOut, "/api/v1/threats") || strings.Contains(errOut, "hmd_") {
		t.Fatalf("threats token: %v %q %q", err, out, errOut)
	}
	if out := c.ok("user", "mcp-token", "create", "chris@example.com"); !strings.HasPrefix(out, "hmd_mcp_") {
		t.Errorf("default purpose: %q", out)
	}
	if _, _, err := c.run("user", "mcp-token", "create", "--purpose", "admin", "chris@example.com"); err == nil {
		t.Error("bad purpose accepted")
	}
	list := c.ok("user", "mcp-token", "list", "chris@example.com")
	if !strings.Contains(list, "PURPOSE") || !strings.Contains(list, "edge firewall  threats") || !strings.Contains(list, "mcp ") {
		t.Errorf("list:\n%s", list)
	}
}
