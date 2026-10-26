// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/store"
)

const cfTestToken = "cf-test-token-0123456789abcdef"

func TestCloudflareSetToken(t *testing.T) {
	dir := t.TempDir()
	path, unit := filepath.Join(dir, "cloudflare-token"), filepath.Join(dir, "heimdall.service")
	os.WriteFile(unit, []byte("[Service]\nUser=heimdall-hub\n"), 0o644)
	old := stdin
	defer func() { stdin = old }()
	stdin = strings.NewReader("  " + cfTestToken + " \n")
	var out, errb bytes.Buffer
	if err := run(t.Context(), []string{"cloudflare", "set-token", "--stdin", "--file", path, "--unit", unit}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(unit); !strings.Contains(string(b), "\nLoadCredential=heimdall-cloudflare:"+path+"\n") {
		t.Errorf("unit:\n%s", b)
	}
	if strings.Contains(out.String()+errb.String(), cfTestToken) {
		t.Error("token echoed")
	}
	t.Setenv("HEIMDALL_CLOUDFLARE_TOKEN_FILE", path)
	if got, _, err := cloudflareToken(false); err != nil || got != cfTestToken {
		t.Errorf("round trip = %q, %v", got, err)
	}
	for _, bad := range []string{"two words here and more\n", "short\n", ""} {
		stdin = strings.NewReader(bad)
		if err := run(t.Context(), []string{"cloudflare", "set-token", "--stdin", "--file", path, "--unit", unit}, &out, &errb); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	os.Chmod(path, 0o644)
	if _, _, err := cloudflareToken(false); err == nil || !strings.Contains(err.Error(), "readable by other users") {
		t.Errorf("world-readable token: %v", err)
	}
}

func TestCloudflareStatusAndSync(t *testing.T) {
	const zone = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var gotAuth []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		ok := func(result string) {
			io.WriteString(w, `{"success":true,"errors":[],"result":`+result+`,"result_info":{"page":1,"total_pages":1}}`)
		}
		switch r.URL.Path {
		case "/ips-v4":
			io.WriteString(w, "173.245.48.0/20\n103.21.244.0/22\n104.16.0.0/13\n")
		case "/ips-v6":
			io.WriteString(w, "2400:cb00::/32\n2606:4700::/32\n2a06:98c0::/29\n")
		case "/api/user/tokens/verify":
			ok(`{"id":"abc","status":"active"}`)
		case "/api/zones":
			ok(`[{"id":"` + zone + `","name":"example.com","status":"active","plan":{"name":"Free Website"}}]`)
		case "/api/zones/" + zone + "/dns_records":
			ok(`[{"name":"example.com","type":"A","content":"192.0.2.99","proxied":false,"ttl":1}]`)
		case "/api/radar/entities/asns/ip":
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)
		case "/api/graphql":
			b, _ := io.ReadAll(r.Body)
			switch {
			case bytes.Contains(b, []byte("settings")) && bytes.Contains(b, []byte("firewallEventsAdaptiveGroups")):
				io.WriteString(w, `{"data":{"viewer":{"zones":[{"settings":{"firewallEventsAdaptiveGroups":{"enabled":false}}}]}}}`)
			case bytes.Contains(b, []byte("settings")):
				ds := regexp.MustCompile(`settings \{ (\w+)`).FindSubmatch(b)[1]
				io.WriteString(w, `{"data":{"viewer":{"zones":[{"settings":{"`+string(ds)+`":{"enabled":true,"notOlderThan":259200}}}]}}}`)
			default:
				io.WriteString(w, `{"data":null,"errors":[{"message":"zone does not have access to the path"}]}`)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	oldHC, oldURLs := cloudflareHTTPClient, cloudflareEdgeURLs
	defer func() { cloudflareHTTPClient, cloudflareEdgeURLs = oldHC, oldURLs }()
	cloudflareHTTPClient = func(config.Cloudflare) *http.Client { return srv.Client() }
	cloudflareEdgeURLs = []string{srv.URL + "/ips-v4", srv.URL + "/ips-v6"}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "heimdall.toml")
	os.WriteFile(cfgPath, []byte("database = \"h.db\"\n[cloudflare]\nenabled = true\napi_base = \""+srv.URL+"/api\"\n"), 0o600)
	var out, errb bytes.Buffer
	store.Create(filepath.Join(dir, "h.db"))
	if err := run(t.Context(), []string{"-c", cfgPath, "migrate"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	keyPath := filepath.Join(dir, "cloudflare-token")
	os.WriteFile(keyPath, []byte(cfTestToken+"\n"), 0o600)
	t.Setenv("HEIMDALL_CLOUDFLARE_TOKEN_FILE", keyPath)

	out.Reset()
	if err := run(t.Context(), []string{"-c", cfgPath, "cloudflare", "sync"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	out.Reset()
	if err := run(t.Context(), []string{"-c", cfgPath, "cloudflare", "status"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	o := out.String()
	for _, want := range []string{"Cloudflare:  on", "Token check: active", "example.com", "Free Website", "events:no", "events-raw:3d",
		"Radar:       no permission", "edge", "zones"} {
		if !strings.Contains(o, want) {
			t.Errorf("status missing %q:\n%s", want, o)
		}
	}
	if strings.Contains(o+errb.String(), cfTestToken) {
		t.Error("token printed")
	}
	for _, a := range gotAuth {
		if a != "" && a != "Bearer "+cfTestToken {
			t.Errorf("auth header %q", a)
		}
	}

	// serve's wiring: the edge set is trusted only with connecting_ip.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(t.Context(), cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer func() { cloudflareEdge = nil }()
	r, syncers := newIPResolver(cfg, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Cloudflare's own: edge, zones and radar syncers; the radar source.
	cf := func(name string) bool { return strings.HasPrefix(name, "cloudflare") }
	var nSync, nSrc int
	for _, x := range syncers {
		if cf(x.Name()) {
			nSync++
		}
	}
	for _, x := range r.Sources {
		if cf(x.Name()) {
			nSrc++
		}
	}
	if nSync != 3 || nSrc != 1 {
		t.Errorf("cloudflare syncers %d sources %d", nSync, nSrc)
	}
	if f := cloudflareTrustedEdge(); f == nil || !f(netip.MustParseAddr("104.16.0.1")) || f(netip.MustParseAddr("192.0.2.1")) {
		t.Error("edge trust")
	}
	cfg.Cloudflare.ConnectingIP = false
	newIPResolver(cfg, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if cloudflareTrustedEdge() != nil {
		t.Error("connecting_ip = false still trusts the edge")
	}
}
