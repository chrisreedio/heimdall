// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/config"
)

func TestAISetKey(t *testing.T) {
	dir := t.TempDir()
	path, unit := filepath.Join(dir, "ai-key"), filepath.Join(dir, "heimdall.service")
	os.WriteFile(unit, []byte("[Service]\nUser=heimdall-hub\n#LoadCredential=heimdall-ai:/etc/heimdall/ai-key\n"), 0o644)
	old := stdin
	defer func() { stdin = old }()
	stdin = strings.NewReader("  0123456789abcdefKEY \n")
	var out, errb bytes.Buffer
	if err := run(t.Context(), []string{"ai", "set-key", "--stdin", "--file", path, "--unit", unit}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(unit); !strings.Contains(string(b), "\nLoadCredential=heimdall-ai:"+path+"\n") || strings.Contains(string(b), "#LoadCredential") {
		t.Errorf("unit:\n%s", b)
	}
	if strings.Contains(out.String()+errb.String(), "0123456789abcdefKEY") {
		t.Error("key echoed")
	}
	t.Setenv("HEIMDALL_AI_KEY_FILE", path)
	if got, _, err := aiKey(false); err != nil || got != "0123456789abcdefKEY" {
		t.Errorf("round trip = %q, %v", got, err)
	}
	for _, bad := range []string{"two words\n", "a\nb\n", ""} {
		stdin = strings.NewReader(bad)
		if err := run(t.Context(), []string{"ai", "set-key", "--stdin", "--file", path, "--unit", unit}, &out, &errb); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	os.Chmod(path, 0o644)
	if _, _, err := aiKey(false); err == nil || !strings.Contains(err.Error(), "readable by other users") {
		t.Errorf("world-readable key: %v", err)
	}
}

func TestAITestAndStatus(t *testing.T) {
	var gotKey string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("api-key")
		if r.URL.Path != "/openai/v1/responses" {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `{"status":"completed","model":"gpt-sol","output":[{"type":"message","content":[{"type":"output_text","text":"{\"ok\":true}"}]}],"usage":{"input_tokens":30,"output_tokens":5}}`)
	}))
	defer srv.Close()
	old := aiHTTPClient
	defer func() { aiHTTPClient = old }()
	aiHTTPClient = func(config.AI) *http.Client { return srv.Client() }

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "heimdall.toml")
	// httptest serves https on 127.0.0.1, which validation accepts.
	os.WriteFile(cfgPath, []byte("database = \"h.db\"\n[ai]\nenabled = true\nendpoint = \""+srv.URL+"\"\ndeployment = \"my-deployment\"\n"), 0o600)
	var out, errb bytes.Buffer
	keyPath := filepath.Join(dir, "ai-key")
	os.WriteFile(keyPath, []byte("sekret-key\n"), 0o600)
	t.Setenv("HEIMDALL_AI_KEY_FILE", keyPath)
	if err := run(t.Context(), []string{"-c", cfgPath, "ai", "test"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	if gotKey != "sekret-key" || !strings.Contains(out.String(), "OK: HTTP 200") || strings.Contains(out.String()+errb.String(), "sekret-key") {
		t.Errorf("test output: %s / %s", out.String(), errb.String())
	}

	// A wrong deployment path is reported with its status, calmly.
	aiHTTPClient = func(config.AI) *http.Client {
		c := srv.Client()
		c.Transport = rewrite{c.Transport}
		return c
	}
	out.Reset()
	err := run(t.Context(), []string{"-c", cfgPath, "ai", "test"}, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") || strings.Contains(err.Error(), "sekret-key") {
		t.Errorf("404: %v", err)
	}
}

type rewrite struct{ next http.RoundTripper }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Path = "/nope"
	return r.next.RoundTrip(req)
}
