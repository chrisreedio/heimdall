// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/notify"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/store/storetest"
)

const (
	testSlackURL   = "https://hooks.slack.com/services/T0000/B0000/XXXXsecretXXXX"
	testDiscordURL = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz_SECRET-1"
)

// fakeHooks stands in for Slack and Discord: notifyHTTPClient is rewired
// so every request lands here, whatever host it names (no real webhooks).
type fakeHooks struct {
	mu     sync.Mutex
	got    map[string][][]byte // by original host
	failOn string              // host answering 404
}

func newFakeHooks(t *testing.T) *fakeHooks {
	f := &fakeHooks{got: map[string][][]byte{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.got[r.Host] = append(f.got[r.Host], b)
		fail := f.failOn == r.Host
		f.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	base := srv.Client().Transport
	old, oldRetry := notifyHTTPClient, notifyRetry
	t.Cleanup(func() { notifyHTTPClient, notifyRetry = old, oldRetry })
	notifyRetry = notify.Retry{Sleep: func(context.Context, time.Duration) error { return nil }}
	notifyHTTPClient = func(hosts []string) *http.Client {
		return &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
			if !slices.Contains(hosts, r.URL.Hostname()) {
				t.Errorf("request to %s outside the allowlist %v", r.URL.Host, hosts)
			}
			r = r.Clone(r.Context())
			r.Host = r.URL.Host
			r.URL.Host = target.Host
			return base.RoundTrip(r)
		})}
	}
	return f
}

func (f *fakeHooks) bodies(host string) [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.got[host]
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// storeDestSecret writes a destination URL file and points the hub at it,
// as LoadCredential would.
func storeDestSecret(t *testing.T, kind, name, raw string) {
	path := filepath.Join(t.TempDir(), kind+"-"+name)
	os.WriteFile(path, []byte(raw+"\n"), 0o600)
	t.Setenv("HEIMDALL_NOTIFY_"+strings.ToUpper(kind)+"_"+strings.ToUpper(strings.ReplaceAll(name, "-", "_"))+"_FILE", path)
}

func TestNotifySetWebhook(t *testing.T) {
	dir := t.TempDir()
	old := notifySecretDir
	defer func() { notifySecretDir = old }()
	notifySecretDir = dir
	unit, cfgPath := filepath.Join(dir, "heimdall.service"), filepath.Join(dir, "heimdall.toml")
	os.WriteFile(unit, []byte("[Service]\nUser=heimdall-hub\n"), 0o644)
	os.WriteFile(cfgPath, []byte("database = \"h.db\"\n\n[notify]\n# chat\nevery = \"0\"\n\n[ai]\n"), 0o600)
	oldIn := stdin
	defer func() { stdin = oldIn }()
	var out, errb bytes.Buffer
	set := func(kind, name, raw string) error {
		stdin = strings.NewReader("  " + raw + " \n")
		out.Reset()
		errb.Reset()
		return run(t.Context(), []string{"-c", cfgPath, "notify", "set-webhook", "--stdin", "--unit", unit, kind, name}, &out, &errb)
	}
	if err := set("slack", "ops", testSlackURL); err != nil {
		t.Fatal(err, errb.String())
	}
	if strings.Contains(out.String()+errb.String(), "XXXXsecretXXXX") {
		t.Errorf("URL echoed: %s", errb.String())
	}
	path := filepath.Join(dir, "notify-slack-ops")
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("secret file: %v %v", fi, err)
	}
	// Discord URLs are stored in canonical form.
	if err := set("discord", "alerts", strings.Replace(testDiscordURL, "discord.com", "ptb.discord.com", 1)); err != nil {
		t.Fatal(err, errb.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "notify-discord-alerts")); string(b) != testDiscordURL+"\n" {
		t.Errorf("discord secret = %q", b)
	}
	b, _ := os.ReadFile(unit)
	for _, want := range []string{"LoadCredential=heimdall-notify-slack-ops:" + path, "LoadCredential=heimdall-notify-discord-alerts:"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("unit lacks %q:\n%s", want, b)
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil || !slices.Equal(cfg.Notify.Destinations, []string{"slack:ops", "discord:alerts"}) {
		t.Errorf("destinations = %v (%v)", cfg.Notify.Destinations, err)
	}
	if raw, _ := os.ReadFile(cfgPath); strings.Contains(string(raw), "hooks.slack.com") || !strings.Contains(string(raw), "# chat") {
		t.Errorf("config:\n%s", raw)
	}

	// Wrong kind, bad names, http, other hosts: refused, nothing echoed.
	for _, c := range [][3]string{
		{"slack", "ops", testDiscordURL}, {"discord", "x", testSlackURL}, {"slack", "Ops!", testSlackURL},
		{"teams", "x", testSlackURL}, {"webhook", "siem", "http://siem.example.com/hook"}, {"slack", "ops", ""},
	} {
		if err := set(c[0], c[1], c[2]); err == nil {
			t.Errorf("%v accepted", c)
		} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("error echoes the URL: %v", err)
		}
	}

	// The hub reads it back as a credential, and the CLI as root from the file.
	t.Setenv("HEIMDALL_NOTIFY_SLACK_OPS_FILE", path)
	dests, err := destinations(config.Config{Notify: config.Notify{Destinations: []string{"slack:ops"}}}, false)
	if err != nil || len(dests) != 1 || dests[0].(*notify.Slack).URL != testSlackURL {
		t.Errorf("load = %v, %v", dests, err)
	}
	t.Setenv("HEIMDALL_NOTIFY_SLACK_OPS_FILE", "")
	if _, err := destinations(config.Config{Notify: config.Notify{Destinations: []string{"slack:ops"}}}, false); err == nil ||
		!strings.Contains(err.Error(), "notify set-webhook slack ops") {
		t.Errorf("missing credential: %v", err)
	}
	if dests, err := destinations(config.Config{Notify: config.Notify{Destinations: []string{"slack:ops"}}}, true); err != nil || len(dests) != 1 {
		t.Errorf("root fallback: %v", err)
	}
	os.Chmod(path, 0o644)
	if _, err := destinations(config.Config{Notify: config.Notify{Destinations: []string{"slack:ops"}}}, true); err == nil ||
		!strings.Contains(err.Error(), "readable by other users") {
		t.Errorf("world-readable secret: %v", err)
	}
}

func TestNotifyTestAndPreview(t *testing.T) {
	hooks := newFakeHooks(t)
	hooks.failOn = "discord.com"
	storeDestSecret(t, "slack", "ops", testSlackURL)
	storeDestSecret(t, "discord", "alerts", testDiscordURL)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "heimdall.toml")
	os.WriteFile(cfgPath, []byte("database = \"h.db\"\n[ui]\nbase_url = \"https://heimdall.example.ts.net\"\n"+
		"[notify]\ndestinations = [\"slack:ops\", \"discord:alerts\"]\n"), 0o600)
	var out, errb bytes.Buffer
	err := run(t.Context(), []string{"-c", cfgPath, "notify", "test"}, &out, &errb)
	if err == nil || !strings.Contains(out.String(), "OK    slack:ops") || !strings.Contains(out.String(), "FAIL  discord:alerts: notify: discord:alerts: HTTP 404") {
		t.Fatalf("test: %v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), "SECRET") || strings.Contains(out.String(), "secret") {
		t.Errorf("output leaks a URL: %s", out.String())
	}
	sent := hooks.bodies("hooks.slack.com")
	if len(sent) != 1 || !strings.Contains(string(sent[0]), "Heimdall: test message") {
		t.Errorf("slack got %s", sent)
	}
	// A failing 404 isn't retried.
	if n := len(hooks.bodies("discord.com")); n != 1 {
		t.Errorf("discord tried %d times", n)
	}

	// One destination by name or kind.
	out.Reset()
	if err := run(t.Context(), []string{"-c", cfgPath, "notify", "test", "slack"}, &out, &errb); err != nil || strings.Contains(out.String(), "discord") {
		t.Errorf("test slack: %v %s", err, out.String())
	}
	if err := run(t.Context(), []string{"-c", cfgPath, "notify", "test", "email"}, &out, &errb); err == nil {
		t.Error("unknown destination accepted")
	}

	out.Reset()
	if err := run(t.Context(), []string{"-c", cfgPath, "notify", "preview", "--alert", "anomaly"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	s := out.String()
	for _, want := range []string{"── slack:ops → https://hooks.slack.com/services/…", "── discord:alerts → https://discord.com/api/webhooks/…",
		`"allowed_mentions"`, `"blocks"`, "privilege watch disabled"} {
		if !strings.Contains(s, want) {
			t.Errorf("preview lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "SECRET") || strings.Contains(s, "XXXXsecretXXXX") {
		t.Errorf("preview leaks a URL:\n%s", s)
	}
	if len(hooks.bodies("hooks.slack.com")) != 2 {
		t.Error("preview sent something")
	}
}

func TestAnomalyAlerts(t *testing.T) {
	hooks := newFakeHooks(t)
	storeDestSecret(t, "slack", "ops", testSlackURL)
	storeDestSecret(t, "discord", "alerts", testDiscordURL)
	ctx := t.Context()
	st := storetest.New(t)
	st.CreateOrg(ctx, "test", "acme", "")
	st.CreateEnv(ctx, "test", "acme", "prod", "")
	st.AddHost(ctx, "test", "acme", "prod", "web-01", nil)
	st.AddHost(ctx, "test", "acme", "prod", "db-01", nil)
	web, _ := st.HostByName(ctx, "acme", "web-01")
	db, _ := st.HostByName(ctx, "acme", "db-01")
	now := time.Now()
	add := func(h store.IngestHost, rule, sev, summary string) {
		t.Helper()
		if _, err := st.AddAnomaly(ctx, h.ID, 0, store.Anomaly{Rule: rule, Severity: sev, Summary: summary}, now); err != nil {
			t.Fatal(err)
		}
	}
	add(web, "privilege_watch_disabled", "high", "already open at startup")

	var cfg config.Config
	cfg.UI.BaseURL = "https://heimdall.example.ts.net/"
	cfg.Notify.Destinations = []string{"slack:ops", "discord:alerts"}
	w := &anomalyAlerts{cfg: cfg, s: st, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := w.start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.check(ctx); err != nil || len(hooks.bodies("discord.com")) != 0 {
		t.Fatalf("an anomaly open at startup was sent (%v)", err)
	}

	add(db, "privileged_access", "medium", "3 privileged accesses by user mallory: sudo apt install netcat")
	add(web, "unexpected_reboot", "low", "rebooted")
	add(web, "package_downgrade", "high", "openssl 3.0.15 -> 3.0.2")
	if err := w.check(ctx); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"discord.com", "hooks.slack.com"} {
		got := hooks.bodies(host)
		if len(got) != 1 {
			t.Fatalf("%s got %d messages", host, len(got))
		}
		s := string(got[0])
		for _, want := range []string{"acme/db-01", "acme/web-01", "privileged access outside a maintenance window", "package downgraded",
			"https://heimdall.example.ts.net/anomalies", "2 new anomalies"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: lacks %q: %s", host, want, s)
			}
		}
		for _, leak := range []string{"mallory", "netcat", "openssl", "rebooted", "already open"} {
			if strings.Contains(s, leak) {
				t.Errorf("%s: leaks %q: %s", host, leak, s)
			}
		}
	}
	var discord map[string]any
	json.Unmarshal(hooks.bodies("discord.com")[0], &discord)
	if discord["allowed_mentions"] == nil {
		t.Error("discord payload lacks allowed_mentions")
	}
	// Nothing new: nothing sent.
	if err := w.check(ctx); err != nil || len(hooks.bodies("discord.com")) != 1 {
		t.Errorf("re-sent (%v)", err)
	}

	// One destination failing doesn't stop the other, and isn't re-sent to
	// the one that got it.
	hooks.failOn = "discord.com"
	add(db, "trigger_disabled", "high", "Change reporting disabled")
	if err := w.check(ctx); err == nil || !strings.Contains(err.Error(), "discord:alerts") {
		t.Errorf("failure not reported: %v", err)
	}
	if err := w.check(ctx); err != nil || len(hooks.bodies("hooks.slack.com")) != 2 {
		t.Errorf("slack got %d (%v)", len(hooks.bodies("hooks.slack.com")), err)
	}
	if !strings.Contains(string(hooks.bodies("hooks.slack.com")[1]), "change reporting disabled") {
		t.Errorf("slack: %s", hooks.bodies("hooks.slack.com")[1])
	}
}
