// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
		case strings.HasSuffix(r.URL.Path, "/SHA256SUMS.sigstore.json"):
			w.Write([]byte(`{"bundle":1}`))
		case r.URL.Path == "/cosign/v3.1.4/cosign-linux-amd64":
			w.Write(fakeCosign)
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
	sigOK := true
	stubCosign(t, srv.URL+"/cosign/", func(args []string) bool { return sigOK })

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
	// A bad signature: never run.
	sums = hex.EncodeToString(sum[:]) + "  install-hub.sh\n"
	sigOK = false
	if err := run(t.Context(), []string{"upgrade"}, &out, &errb); err == nil || ran != nil || !strings.Contains(err.Error(), "signature verification FAILED") {
		t.Fatalf("bad signature: err=%v ran=%v", err, ran)
	}
	// ...unless told to skip it; the installer is told too.
	if err := run(t.Context(), []string{"upgrade", "--skip-signature-check"}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	if strings.Join(ran, " ") != "--version v9.0.0 --skip-signature-check" {
		t.Errorf("installer args = %q", ran)
	}
	// Already current.
	stub(t, &version, "v9.0.0")
	errb.Reset()
	if err := run(t.Context(), []string{"upgrade"}, &out, &errb); err != nil || !strings.Contains(errb.String(), "Already on the latest") {
		t.Fatalf("current: %v %q", err, errb.String())
	}
}

func TestSetTOMLKeys(t *testing.T) {
	t.Parallel()
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

var fakeCosign = []byte("#!/bin/sh\n# not really cosign\n")

// stubCosign serves fakeCosign from base and pins its hash; verify decides
// each verify-blob call.
func stubCosign(t *testing.T, base string, verify func(args []string) bool) {
	sum := sha256.Sum256(fakeCosign)
	stub(t, &cosignDir, t.TempDir())
	stub(t, &cosignBase, base)
	stub(t, &cosignArch, "amd64")
	stub(t, &cosignSHA256, map[string]string{"amd64": hex.EncodeToString(sum[:])})
	stub(t, &runCosign, func(_ context.Context, bin, _ string, args ...string) ([]byte, error) {
		if b, err := os.ReadFile(bin); err != nil || !bytes.Equal(b, fakeCosign) {
			t.Errorf("ran %s, not the pinned cosign", bin)
		}
		if len(args) < 6 || args[0] != "verify-blob" || !slices.Contains(args, releaseSigner) || !slices.Contains(args, releaseIssuer) {
			t.Errorf("cosign args = %q", args)
		}
		if !verify(args) {
			return []byte("Error: invalid signature\n"), errors.New("exit status 1")
		}
		return []byte("Verified OK\n"), nil
	})
}

func TestPinnedCosign(t *testing.T) {
	served := fakeCosign
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write(served)
	}))
	defer srv.Close()
	stubCosign(t, srv.URL+"/", func([]string) bool { return true })
	hc := netx.NewForTest(srv.Client())
	var errb bytes.Buffer
	a := &app{ctx: t.Context(), stdout: &errb, stderr: &errb}
	bin, err := pinnedCosign(a, hc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pinnedCosign(a, hc); err != nil || hits != 1 {
		t.Fatalf("second call fetched again (hits %d): %v", hits, err)
	}
	// A swapped cached copy is fetched again.
	os.WriteFile(bin, []byte("evil"), 0o755)
	if _, err := pinnedCosign(a, hc); err != nil || hits != 2 {
		t.Fatalf("swapped copy kept (hits %d): %v", hits, err)
	}
	// A download that doesn't match the pin is never used.
	os.Remove(bin)
	served = []byte("evil")
	if _, err := pinnedCosign(a, hc); err == nil || !strings.Contains(err.Error(), "pinned hash") {
		t.Fatalf("bad download: %v", err)
	}
	if _, err := os.Stat(bin); err == nil {
		t.Error("bad download installed")
	}
	stub(t, &cosignArch, "s390x")
	if _, err := pinnedCosign(a, hc); err == nil || !strings.Contains(err.Error(), "--skip-signature-check") {
		t.Fatalf("unknown arch: %v", err)
	}
}

// TestSignaturePinsMatch: the cosign pins and the signer identity are the
// same in every installer as here.
func TestSignaturePinsMatch(t *testing.T) {
	t.Parallel()
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", p))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	block := func(s string) string {
		i, j := strings.Index(s, "# ── Release signature ──"), strings.Index(s, "printf '==> Sigstore signature verified\\n' >&2\n}\n")
		if i < 0 || j < i {
			t.Fatal("no release signature block")
		}
		return s[i:j]
	}
	sh := []string{"collector/collect.sh", "collector/install.sh", "deploy/install-hub.sh"}
	first := block(read(sh[0]))
	for _, p := range sh[1:] {
		if block(read(p)) != first {
			t.Errorf("%s's release signature block differs from %s's", p, sh[0])
		}
	}
	ps := read("collector/install-windows.ps1")
	for name, want := range map[string]string{
		"COSIGN_VERSION=" + cosignVersion:                       first,
		"RELEASE_SIGNER='" + releaseSigner + "'":                first,
		"c=amd64 s=" + cosignSHA256["amd64"]:                    first,
		"c=arm64 s=" + cosignSHA256["arm64"]:                    first,
		"$CosignVersion = '" + cosignVersion + "'":              ps,
		"$ReleaseSigner = '" + releaseSigner + "'":              ps,
		"'linux-amd64'       = '" + cosignSHA256["amd64"] + "'": ps,
	} {
		if !strings.Contains(want, name) {
			t.Errorf("pin %q missing", name)
		}
	}
	for _, p := range append(sh, "collector/install-windows.ps1") {
		if strings.Contains(read(p), "have cosign") {
			t.Errorf("%s still makes the signature check optional", p)
		}
		if strings.Contains(read(p), "chrisreedio") {
			t.Errorf("%s still accepts the old repo's signatures", p)
		}
	}
	// Only this repo's release workflow, for a v* tag, signs a release.
	re := regexp.MustCompile(releaseSigner)
	for id, want := range map[string]bool{
		"https://github.com/realmwatch/heimdall/.github/workflows/release.yml@refs/tags/v0.4.41":                true,
		"https://github.com/chrisreedio/heimdall/.github/workflows/release.yml@refs/tags/v0.4.31":               false,
		"https://github.com/realmwatch/heimdall/.github/workflows/ci.yml@refs/tags/v0.4.41":                     false,
		"https://github.com/realmwatch/heimdall/.github/workflows/release.yml@refs/heads/main":                  false,
		"https://github.com/realmwatch/heimdall-fork/.github/workflows/release.yml@refs/tags/v1":                false,
		"https://example.com/https://github.com/realmwatch/heimdall/.github/workflows/release.yml@refs/tags/v1": false,
	} {
		if re.MatchString(id) != want {
			t.Errorf("signer %q accepted = %v, want %v", id, !want, want)
		}
	}
}
