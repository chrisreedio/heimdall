// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPServicesSetKey(t *testing.T) {
	dir := t.TempDir()
	path, unit := filepath.Join(dir, "ploi-token"), filepath.Join(dir, "heimdall.service")
	os.WriteFile(unit, []byte("[Service]\nUser=heimdall-hub\n"), 0o644)
	old := stdin
	defer func() { stdin = old }()
	stdin = strings.NewReader("  tok-0123456789abcdef \n")
	var out, errb bytes.Buffer
	if err := run(t.Context(), []string{"ip-services", "set-key", "--stdin", "--file", path, "--unit", unit, "ploi"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(unit); !strings.Contains(string(b), "\nLoadCredential=heimdall-ploi:"+path+"\n") {
		t.Errorf("unit:\n%s", b)
	}
	if strings.Contains(out.String()+errb.String(), "tok-0123456789abcdef") {
		t.Error("token echoed")
	}
	t.Setenv("HEIMDALL_PLOI_TOKEN_FILE", path)
	if got, _, err := serviceToken("ploi", false); err != nil || got != "tok-0123456789abcdef" {
		t.Errorf("round trip = %q, %v", got, err)
	}
	os.Chmod(path, 0o644)
	if _, _, err := serviceToken("ploi", false); err == nil || !strings.Contains(err.Error(), "readable by other users") {
		t.Errorf("world-readable token: %v", err)
	}
	// Only services with a token list take one.
	stdin = strings.NewReader("x\n")
	if err := run(t.Context(), []string{"ip-services", "set-key", "--stdin", "--file", path, "--unit", unit, "forge"}, &out, &errb); err == nil {
		t.Error("forge took a token")
	}
}

// status and sync with no network: custom services with fixed ranges only.
func TestIPServicesStatusSync(t *testing.T) {
	t.Setenv("HEIMDALL_PLOI_TOKEN_FILE", "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	c := newCLI(t)
	c.init()
	b, err := os.ReadFile(c.config)
	if err != nil {
		t.Fatal(err)
	}
	src := strings.Replace(string(b), `services = ["forge", "ploi"]`, `services = ["ploi"]
[[deploy_services.custom]]
name  = "Acme Deploy"
cidrs = ["203.0.113.10", "203.0.113.16/28"]
users = ["deploy"]`, 1)
	if src == string(b) {
		t.Fatal("template has no services line")
	}
	os.WriteFile(c.config, []byte(src), 0o600)
	c.ok("migrate")

	out := c.ok("ip-services", "status")
	if !strings.Contains(out, "custom-acme-deploy") || !strings.Contains(out, "not synced yet") ||
		!strings.Contains(out, "no API token") {
		t.Errorf("status before:\n%s", out)
	}
	if _, errOut, err := c.run("ip-services", "sync"); err != nil || !strings.Contains(errOut, "custom-acme-deploy: synced") ||
		!strings.Contains(errOut, "ploi: skipped") {
		t.Fatalf("sync: %v\n%s", err, errOut)
	}
	out = c.ok("ip-services", "status")
	if !strings.Contains(out, "Acme Deploy  2 ") || !strings.Contains(out, " ok") || !strings.Contains(out, "deploy") {
		t.Errorf("status after:\n%s", out)
	}
	if _, _, err := c.run("ip-services", "sync", "forge"); err == nil {
		t.Error("synced a service that isn't configured")
	}
}
