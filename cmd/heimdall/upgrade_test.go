// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/netx"
)

func stub[T any](t *testing.T, p *T, v T) {
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

func TestUpgrade(t *testing.T) {
	script := []byte("#!/bin/sh\necho installer\n")
	sum := sha256.Sum256(script)
	sums := hex.EncodeToString(sum[:]) + "  install-hub.sh\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/latest":
			w.Write([]byte(`{"tag_name":"v9.0.0","html_url":"https://github.com/realmwatch/heimdall/releases/tag/v9.0.0"}`))
		case strings.HasSuffix(r.URL.Path, "/SHA256SUMS"):
			w.Write([]byte(sums))
		case strings.HasSuffix(r.URL.Path, "/install-hub.sh"):
			w.Write(script)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	stub(t, &upgradeHTTP, func() *netx.Client { return netx.NewForTest(srv.Client()) })
	stub(t, &latestURL, srv.URL+"/latest")
	stub(t, &releaseBase, srv.URL+"/dl/")
	stub(t, &version, "v0.4.3")
	var ran []string
	stub(t, &runShell, func(a *app, path string, args []string) error {
		b, _ := os.ReadFile(path)
		if !bytes.Equal(b, script) {
			t.Error("ran a different script")
		}
		ran = args
		return nil
	})
	root := false
	stub(t, &isRoot, func() bool { return root })

	var out, errb bytes.Buffer
	if err := run(t.Context(), []string{"upgrade", "--check"}, &out, &errb); err != nil || !strings.Contains(out.String(), "v9.0.0 is available") {
		t.Fatalf("check: %v %q", err, out.String())
	}
	if err := run(t.Context(), []string{"upgrade"}, &out, &errb); err == nil || !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("non-root upgrade: %v", err)
	}
	root = true
	if err := run(t.Context(), []string{"upgrade", "--", "--ingest-host", "h.example.com"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	if strings.Join(ran, " ") != "--version v9.0.0 --ingest-host h.example.com" {
		t.Errorf("installer args = %q", ran)
	}
	// A tampered script is never run.
	sums = strings.Repeat("0", 64) + "  install-hub.sh\n"
	ran = nil
	if err := run(t.Context(), []string{"upgrade"}, &out, &errb); err == nil || ran != nil {
		t.Fatalf("tampered script: err=%v ran=%v", err, ran)
	}
	// Already current.
	stub(t, &version, "v9.0.0")
	errb.Reset()
	if err := run(t.Context(), []string{"upgrade"}, &out, &errb); err != nil || !strings.Contains(errb.String(), "Already on the latest") {
		t.Fatalf("current: %v %q", err, errb.String())
	}
}

func TestSetTOMLKeys(t *testing.T) {
	src := config.Template("heimdall.db")
	src = append(src, []byte("\n[extra]\nallowed_tenants = [\n  \"x\",\n]\n")...)
	out := string(setTOMLKeys(src, "auth.entra", [][2]string{{"enabled", "true"}, {"tenant", `"t"`}, {"allowed_tenants", `["t"]`}, {"new_key", "1"}}))
	if !strings.Contains(out, "[auth.entra]\nenabled = true") || !strings.Contains(out, `allowed_tenants = ["t"]`) || !strings.Contains(out, "new_key = 1") {
		t.Errorf("section not updated:\n%s", out)
	}
	if !strings.Contains(out, "[extra]\nallowed_tenants = [\n  \"x\",\n]") {
		t.Error("another section's key was changed")
	}
	// Multi-line arrays are replaced whole; a missing section is appended.
	out = string(setTOMLKeys([]byte("[a]\nk = [\n 1,\n 2,\n]\nz = 1\n"), "a", [][2]string{{"k", "[3]"}}))
	if out != "[a]\nk = [3]\nz = 1\n" {
		t.Errorf("multi-line: %q", out)
	}
	if out = string(setTOMLKeys([]byte("x = 1\n"), "b", [][2]string{{"k", "2"}})); out != "x = 1\n\n[b]\nk = 2\n" {
		t.Errorf("new section: %q", out)
	}
}

func TestSSOSetup(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/heimdall.toml"
	if err := os.WriteFile(cfgPath, config.TemplateWith(config.Setup{Database: "heimdall.db", UIBaseURL: "https://hub.example.ts.net"}), 0o600); err != nil {
		t.Fatal(err)
	}
	unit := dir + "/heimdall.service"
	os.WriteFile(unit, []byte("[Service]\nExecStart=/usr/local/bin/heimdall serve\n#LoadCredential=heimdall-entra:/etc/heimdall/entra-secret\n"), 0o644)
	stub(t, &isRoot, func() bool { return true })
	var calls []string
	stub(t, &systemctl, func(a *app, args ...string) error { calls = append(calls, strings.Join(args, " ")); return nil })
	stub(t, &stdin, any(strings.NewReader("my~secret.value\n")).(interface{ Read([]byte) (int, error) }))
	const tid, cid = "11111111-2222-3333-4444-555555555555", "66666666-7777-8888-9999-000000000000"
	var out, errb bytes.Buffer
	err := run(t.Context(), []string{"-c", cfgPath, "sso", "setup", "--tenant", tid, "--client-id", cid, "--secret-stdin",
		"--secret-file", dir + "/entra-secret", "--unit", unit, "--restart"}, &out, &errb)
	if err != nil {
		t.Fatal(err, errb.String())
	}
	if !strings.Contains(errb.String(), "https://hub.example.ts.net/auth/callback") {
		t.Error("redirect URI not shown")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil || !cfg.Auth.Entra.Enabled || cfg.Auth.Entra.Tenant != tid || cfg.Auth.Entra.ClientID != cid || len(cfg.Auth.Entra.AllowedTenants) != 1 {
		t.Fatalf("config: %+v %v", cfg.Auth.Entra, err)
	}
	if fi, _ := os.Stat(cfgPath); fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode changed to %v", fi.Mode().Perm())
	}
	t.Setenv("HEIMDALL_ENTRA_SECRET_FILE", dir+"/entra-secret")
	if s, err := entraSecret(); err != nil || s != "my~secret.value" {
		t.Errorf("secret = %q %v", s, err)
	}
	if b, _ := os.ReadFile(unit); !strings.Contains(string(b), "\nLoadCredential=heimdall-entra:"+dir+"/entra-secret") || strings.Contains(string(b), "#LoadCredential") {
		t.Errorf("unit:\n%s", b)
	}
	if strings.Join(calls, ";") != "daemon-reload;restart heimdall;is-active --quiet heimdall" {
		t.Errorf("systemctl calls = %q", calls)
	}
	// A secret ID pasted instead of its value is refused.
	stub(t, &stdin, any(strings.NewReader(tid+"\n")).(interface{ Read([]byte) (int, error) }))
	if err := run(t.Context(), []string{"-c", cfgPath, "sso", "setup", "--tenant", tid, "--client-id", cid, "--secret-stdin",
		"--secret-file", dir + "/entra-secret", "--unit", unit, "--no-restart"}, &out, &errb); err == nil {
		t.Error("secret ID accepted as the secret")
	}
}
