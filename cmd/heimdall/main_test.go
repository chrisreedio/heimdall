// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"io"

	"bytes"
	"errors"
	"filippo.io/age"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chrisreedio/heimdall/internal/secret"
)

type cli struct {
	t      *testing.T
	config string
}

func newCLI(t *testing.T) *cli {
	return &cli{t: t, config: filepath.Join(t.TempDir(), "heimdall.toml")}
}

func (c *cli) run(args ...string) (stdout, stderr string, err error) {
	var out, errOut bytes.Buffer
	err = run(c.t.Context(), append([]string{"-c", c.config}, args...), &out, &errOut)
	return out.String(), errOut.String(), err
}

func (c *cli) ok(args ...string) string {
	c.t.Helper()
	out, errOut, err := c.run(args...)
	if err != nil {
		c.t.Fatalf("heimdall %s: %v\n%s", strings.Join(args, " "), err, errOut)
	}
	return out
}

func TestEndToEnd(t *testing.T) {
	c := newCLI(t)
	c.ok("init")

	fi, err := os.Stat(filepath.Join(filepath.Dir(c.config), "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("database perm %04o", fi.Mode().Perm())
	}

	if _, _, err := c.run("init"); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("second init: %v", err)
	}

	c.ok("migrate")
	c.ok("org", "create", "acme", "--name", "Acme Corp")
	c.ok("env", "create", "--org", "acme", "prod")
	// Flags after the positional argument work too.
	token := strings.TrimSpace(c.ok("host", "add", "web-01", "--org", "acme", "--env", "prod", "--tag", "web,role:lb"))
	if !secret.LooksLike(token, secret.IngestPrefix) {
		t.Fatalf("stdout should be exactly the token, got %q", token)
	}

	if out := c.ok("org", "list"); !strings.Contains(out, "Acme Corp") || !strings.Contains(out, "1") {
		t.Errorf("org list:\n%s", out)
	}
	if out := c.ok("env", "list", "--org", "acme"); !strings.Contains(out, "prod") {
		t.Errorf("env list:\n%s", out)
	}
	out := c.ok("host", "list")
	if !strings.Contains(out, "web-01") || !strings.Contains(out, "role:lb,web") || !strings.Contains(out, "never") {
		t.Errorf("host list:\n%s", out)
	}
	if strings.Contains(out, token) {
		t.Error("host list must never show tokens")
	}

	if _, _, err := c.run("host", "rm", "--org", "acme", "web-01"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("rm without --yes: %v", err)
	}
	c.ok("host", "rm", "--org", "acme", "--yes", "web-01")
	if out := c.ok("host", "list", "--org", "acme"); strings.Contains(out, "web-01") {
		t.Errorf("host still listed after rm:\n%s", out)
	}
}

func TestUsageErrors(t *testing.T) {
	c := newCLI(t)
	c.ok("init")
	for _, args := range [][]string{
		{},
		{"bogus"},
		{"org"},
		{"org", "create"},
		{"host", "add", "--org", "acme"}, // missing hostname and --env
		{"org", "create", "a", "b"},      // too many args
	} {
		if _, _, err := c.run(args...); !errors.Is(err, errUsage) {
			t.Errorf("heimdall %v: want usage error, got %v", args, err)
		}
	}
}

// With one org and one env (the usual one-install-per-org setup), --org
// and --env can be left out; with several, they're required.
func TestDefaultOrgAndEnv(t *testing.T) {
	c := newCLI(t)
	c.ok("init")
	if _, _, err := c.run("env", "create", "prod"); err == nil || !strings.Contains(err.Error(), "org create") {
		t.Fatalf("no orgs: %v", err)
	}
	c.ok("org", "create", "acme")
	c.ok("env", "create", "prod")
	c.ok("host", "add", "web-01")
	if out := c.ok("host", "show", "web-01"); !strings.Contains(out, "org acme") {
		t.Errorf("host show:\n%s", out)
	}

	c.ok("env", "create", "staging")
	if _, _, err := c.run("host", "add", "web-02"); err == nil || !strings.Contains(err.Error(), "pass --env") {
		t.Fatalf("two envs: %v", err)
	}
	c.ok("org", "create", "globex")
	if _, _, err := c.run("host", "show", "web-01"); err == nil || !strings.Contains(err.Error(), "pass --org") {
		t.Fatalf("two orgs: %v", err)
	}
	c.ok("host", "show", "--org", "acme", "web-01")
}

func TestCommandsNeedInit(t *testing.T) {
	c := newCLI(t)
	if _, _, err := c.run("org", "list"); err == nil {
		t.Fatal("expected error without config")
	}
}

func TestEntraUserAndRoles(t *testing.T) {
	c := newCLI(t)
	c.ok("init")
	c.ok("org", "create", "acme")
	if _, _, err := c.run("user", "create", "--entra", "alice@example.com"); err == nil || !strings.Contains(err.Error(), "--tenant") {
		t.Fatalf("missing tenant: %v", err)
	}
	c.ok("user", "create", "--entra", "--tenant", "11111111-1111-1111-1111-111111111111", "alice@example.com")
	c.ok("user", "grant", "--role", "operator", "alice@example.com")
	out := c.ok("user", "list")
	if !strings.Contains(out, "entra") || !strings.Contains(out, "acme:operator") {
		t.Errorf("user list:\n%s", out)
	}
	if _, _, err := c.run("user", "grant", "--role", "root", "alice@example.com"); err == nil {
		t.Error("bad role accepted")
	}
	c.ok("user", "revoke", "alice@example.com")
	if out := c.ok("user", "list"); strings.Contains(out, "acme:operator") {
		t.Errorf("revoke didn't remove the role:\n%s", out)
	}
}

func TestEntraSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv("HEIMDALL_ENTRA_SECRET_FILE", "")
	if _, err := entraSecret(); err == nil || !strings.Contains(err.Error(), "LoadCredential") {
		t.Fatalf("no secret configured: %v", err)
	}
	os.WriteFile(path, []byte("  s3cret\n"), 0o644)
	t.Setenv("HEIMDALL_ENTRA_SECRET_FILE", path)
	if _, err := entraSecret(); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world-readable secret: %v", err)
	}
	os.Chmod(path, 0o600)
	if s, err := entraSecret(); err != nil || s != "s3cret" {
		t.Fatalf("secret = %q, %v", s, err)
	}
	// systemd credentials are found by name.
	os.WriteFile(filepath.Join(dir, entraCredential), []byte("from-systemd"), 0o644)
	t.Setenv("HEIMDALL_ENTRA_SECRET_FILE", "")
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if s, err := entraSecret(); err != nil || s != "from-systemd" {
		t.Fatalf("credential = %q, %v", s, err)
	}
}

func TestBackupRoundTrip(t *testing.T) {
	c := newCLI(t)
	c.ok("init")
	c.ok("org", "create", "acme")
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(filepath.Dir(c.config), "b.age")
	c.ok("backup", "--to", out, "--age-recipient", id.Recipient().String())
	if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup file: %v %v", fi, err)
	}
	if _, _, err := c.run("backup", "--to", out, "--age-recipient", id.Recipient().String()); err == nil {
		t.Error("overwrote an existing backup")
	}
	f, _ := os.Open(out)
	defer f.Close()
	r, err := age.Decrypt(f, id)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	if !bytes.HasPrefix(b, []byte("SQLite format 3\x00")) {
		t.Error("decrypted backup isn't a SQLite database")
	}
	if entries, _ := filepath.Glob(filepath.Join(filepath.Dir(c.config), ".heimdall-backup-*")); len(entries) != 0 {
		t.Errorf("plaintext temp left behind: %v", entries)
	}
}

func TestWriteQR(t *testing.T) {
	var buf bytes.Buffer
	uri := "otpauth://totp/Heimdall:you@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Heimdall&algorithm=SHA1&digits=6&period=30"
	if err := writeQR(&buf, uri); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	// Square: rows of half blocks cover two modules each.
	cells := strings.Count(lines[0], "▀")
	if cells < 25 || len(lines) != (cells+1)/2 {
		t.Errorf("%d lines × %d cells", len(lines), cells)
	}
	if !strings.Contains(buf.String(), "\x1b[30;") || !strings.HasSuffix(lines[0], "\x1b[0m") {
		t.Error("expected explicit colours and a reset at line end")
	}
}
