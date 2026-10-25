// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/store"
)

const bansTestToken = "cf-bans-test-token-0123456789abcdef"

func TestBansSetToken(t *testing.T) {
	dir := t.TempDir()
	path, unit := filepath.Join(dir, "cloudflare-bans-token"), filepath.Join(dir, "heimdall.service")
	os.WriteFile(unit, []byte("[Service]\nUser=heimdall-hub\n"), 0o644)
	old := stdin
	defer func() { stdin = old }()
	stdin = strings.NewReader(bansTestToken + "\n")
	var out, errb bytes.Buffer
	if err := run(t.Context(), []string{"bans", "set-token", "--stdin", "--file", path, "--unit", unit}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(unit); !strings.Contains(string(b), "\nLoadCredential=heimdall-cloudflare-bans:"+path+"\n") {
		t.Errorf("unit:\n%s", b)
	}
	if strings.Contains(out.String()+errb.String(), bansTestToken) {
		t.Error("token echoed")
	}
	t.Setenv("HEIMDALL_CLOUDFLARE_BANS_TOKEN_FILE", path)
	if got, _, err := bansToken(false); err != nil || got != bansTestToken {
		t.Errorf("round trip = %q, %v", got, err)
	}
	stdin = strings.NewReader("short\n")
	if err := run(t.Context(), []string{"bans", "set-token", "--stdin", "--file", path, "--unit", unit}, &out, &errb); err == nil {
		t.Error("short token accepted")
	}
	os.Chmod(path, 0o644)
	if _, _, err := bansToken(false); err == nil || !strings.Contains(err.Error(), "readable by other users") {
		t.Errorf("world-readable token: %v", err)
	}
}

func TestBansCommands(t *testing.T) {
	c := newCLI(t)
	c.ok("init")
	c.ok("migrate")
	c.ok("org", "create", "acme")
	c.ok("env", "create", "--org", "acme", "prod")
	for _, h := range []string{"web-01", "web-02", "web-03"} {
		c.ok("host", "add", "--org", "acme", "--env", "prod", h)
	}

	u := c.ok("bans", "token-url")
	if !strings.HasPrefix(u, "https://dash.cloudflare.com/?to=/:account/api-tokens&permissionGroupKeys=") {
		t.Errorf("token-url: %s", u)
	}
	if out := c.ok("bans", "status"); !strings.Contains(out, "Mode:     off") || !strings.Contains(out, "Paused:   no") {
		t.Errorf("status:\n%s", out)
	}

	cfg, err := config.Load(c.config)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(t.Context(), cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	for _, name := range []string{"web-01", "web-02", "web-03"} {
		h, _ := s.HostByName(t.Context(), "acme", name)
		day := store.LoginDay{Day: at.Format(time.DateOnly), Failures: 40, Addresses: 1, Rows: []store.LoginFailure{
			{IP: "203.0.113.9", Failures: 40, Usernames: 6, First: at, Last: at}}}
		if err := s.RecordLogins(t.Context(), h.ID, store.LoginReport{Source: "journal", Days: []store.LoginDay{day}}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	id, err := s.AddBan(t.Context(), store.Ban{Target: "203.0.113.9", Kind: "address", Action: "block", Status: store.BanProposed,
		Mode: "propose", Score: 20, Duration: 7 * 24 * time.Hour}, "heimdall", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	sid := strconv.FormatInt(id, 10)

	// Candidates, with their breakdown.
	out := c.ok("bans", "list", "--candidates")
	if !strings.Contains(out, "203.0.113.9") || !strings.Contains(out, "hosts 3→6.0") || !strings.Contains(out, "over") {
		t.Errorf("candidates:\n%s", out)
	}
	// Off (and shadow) never approve into Cloudflare.
	if _, _, err := c.run("bans", "approve", sid); err == nil || !strings.Contains(err.Error(), "writes nothing") {
		t.Errorf("approve while off: %v", err)
	}
	src, _ := os.ReadFile(c.config)
	cfgText := strings.Replace(string(src), "[cloudflare]\n", "[cloudflare]\nenabled = true\n", 1)
	cfgText = strings.Replace(cfgText, "enabled         = false\nzones", "zones", 1)
	cfgText = strings.Replace(cfgText, `mode           = "off"`, `mode           = "propose"`, 1)
	os.WriteFile(c.config, []byte(cfgText), 0o600)

	c.ok("bans", "approve", "--note", "seen it", sid)
	var list []banJSON
	if err := json.Unmarshal([]byte(c.ok("bans", "list", "--json", "--status", "pending")), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Target != "203.0.113.9" || list[0].Days != 7 || !strings.HasPrefix(list[0].DecidedBy, "cli:") {
		t.Errorf("pending: %+v", list)
	}
	c.ok("bans", "pause", "--note", "incident")
	var st struct {
		Mode   string
		Paused store.BanPause
		Counts map[string]int
	}
	if err := json.Unmarshal([]byte(c.ok("bans", "status", "--json")), &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode != "propose" || !st.Paused.Paused || st.Counts["pending"] != 1 {
		t.Errorf("status: %+v", st)
	}
	c.ok("bans", "resume")
	c.ok("bans", "unban", sid)
	if out := c.ok("bans", "list"); !strings.Contains(out, "ended") {
		t.Errorf("after unban:\n%s", out)
	}
	if _, _, err := c.run("bans", "reject", "nope"); err == nil {
		t.Error("bad ID accepted")
	}
}
