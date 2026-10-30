// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/netx"
	"github.com/realmwatch/heimdall/internal/tailscale"
)

// Obviously fake credentials.
const (
	fakeTSSecret = "tskey-client-kFAKE-notarealsecret"
	fakeTSKey    = "tskey-api-kFAKEKEY-notarealsecret"
)

func TestTailscaleSetKey(t *testing.T) {
	dir := t.TempDir()
	path, unit := filepath.Join(dir, "tailscale-key"), filepath.Join(dir, "heimdall.service")
	os.WriteFile(unit, []byte("[Service]\nUser=heimdall-hub\n"), 0o644)
	old := stdin
	defer func() { stdin = old }()
	setKey := func(input string, extra ...string) (string, error) {
		t.Helper()
		stdin = strings.NewReader(input)
		c := newCLI(t)
		_, errOut, err := c.run(append([]string{"tailscale", "set-key", "--stdin", "--file", path, "--unit", unit}, extra...)...)
		return errOut, err
	}

	out, err := setKey(" "+fakeTSSecret+" \n", "--client-id", "kFAKE")
	if err != nil {
		t.Fatal(err, out)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("credential file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(unit); !strings.Contains(string(b), "\nLoadCredential=heimdall-tailscale:"+path+"\n") {
		t.Errorf("unit:\n%s", b)
	}
	if strings.Contains(out, fakeTSSecret) {
		t.Error("secret echoed")
	}
	t.Setenv("HEIMDALL_TAILSCALE_KEY_FILE", path)
	if cred, _, err := tailscaleCred(false); err != nil || cred.ClientID != "kFAKE" || cred.ClientSecret != fakeTSSecret {
		t.Errorf("round trip = %+v, %v", cred, err)
	}

	if out, err = setKey(fakeTSKey + "\n"); err != nil || !strings.Contains(out, "expire") {
		t.Fatalf("API key: %v %s", err, out)
	}
	if cred, _, err := tailscaleCred(false); err != nil || cred.APIKey != fakeTSKey || cred.Kind() != tailscale.KindAPIKey {
		t.Errorf("API key round trip = %+v, %v", cred, err)
	}

	for _, bad := range []string{"", "two words\n", fakeTSSecret + "\n" /* no client ID */, "tskey-auth-kX-notreal\n"} {
		if _, err := setKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	os.Chmod(path, 0o644)
	if _, _, err := tailscaleCred(false); err == nil || !strings.Contains(err.Error(), "readable by other users") {
		t.Errorf("world-readable credential: %v", err)
	}
}

func TestTailscaleSyncAndStatus(t *testing.T) {
	var fail bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case fail:
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/api/v2/tailnet/-/devices" && r.Header.Get("Authorization") == "Bearer "+fakeTSKey:
			io.WriteString(w, `{"devices":[{"nodeId":"nWEB01","addresses":["100.64.0.5"],"name":"web-01.tail1234.ts.net","hostname":"web-01",
				"os":"linux","tags":["tag:server"],"connectedToControl":true,"keyExpiryDisabled":true},
				{"nodeId":"nLAPTOP","addresses":["100.101.102.103","fd7a:115c:a1e0::1"],"user":"alice@example.com","name":"laptop-01.tail1234.ts.net","hostname":"laptop-01"}]}`)
		case r.URL.Path == "/api/v2/tailnet/-/keys/kFAKEKEY":
			io.WriteString(w, `{"expires":"`+time.Now().Add(5*24*time.Hour).UTC().Format(time.RFC3339)+`"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	old := newTailscaleClient
	defer func() { newTailscaleClient = old }()
	newTailscaleClient = func(cred tailscale.Credential, tailnet string) *tailscale.Client {
		return &tailscale.Client{Cred: cred, Tailnet: tailnet, HTTP: netx.NewForTest(srv.Client()), BaseURL: srv.URL + "/api/v2", Now: time.Now}
	}

	c := newCLI(t)
	c.init()
	if out := c.ok("tailscale", "status"); !strings.Contains(out, "Tailscale: off") {
		t.Errorf("status when off: %s", out)
	}
	b, _ := os.ReadFile(c.config)
	cfg := string(b)
	i := strings.Index(cfg, "[tailscale]")
	cfg = cfg[:i] + strings.Replace(cfg[i:], "enabled    = false", "enabled    = true", 1)
	os.WriteFile(c.config, []byte(cfg), 0o600)
	keyPath := filepath.Join(t.TempDir(), "tailscale-key")
	os.WriteFile(keyPath, []byte(tailscale.Credential{APIKey: fakeTSKey}.Encode()), 0o600)
	t.Setenv("HEIMDALL_TAILSCALE_KEY_FILE", keyPath)
	c.ok("org", "create", "acme")
	c.ok("env", "create", "--org", "acme", "prod")
	c.ok("host", "add", "web-01", "--org", "acme", "--env", "prod")
	c.ok("host", "add", "db-01", "--org", "acme", "--env", "prod")

	out := c.ok("tailscale", "sync")
	if !strings.Contains(out, "OK: 2 devices, 3 address labels, 1 of your hosts on the tailnet") {
		t.Errorf("sync: %s", out)
	}
	fail = true
	if _, _, err := c.run("tailscale", "sync"); err == nil || !strings.Contains(err.Error(), "last good labels stay") {
		t.Errorf("failed sync: %v", err)
	}
	out = c.ok("tailscale", "status")
	for _, want := range []string{"Tailscale:   on", "Credential:  api-key", "(2 devices, api-key)", "Last error:", "HTTP 401",
		"Hosts:       1 of 2 on the tailnet", "Not on the tailnet: db-01", "Warning: the API access token expires in"} {
		if !strings.Contains(out, want) {
			t.Errorf("status missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "notarealsecret") {
		t.Error("status prints the secret")
	}
}
