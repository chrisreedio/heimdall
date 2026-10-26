// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestAsHubUser(t *testing.T) {
	fi, err := os.Stat(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	uid, _, _ := fileOwner(fi)
	if uid == 0 {
		t.Skip("running as root: the test file's owner is root")
	}
	cfg := t.TempDir() + "/heimdall.toml"
	os.WriteFile(cfg, []byte(""), 0o600)
	wd, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(wd) })
	stub(t, &euid, func() int { return 0 })
	var got []string
	errExec := errors.New("exec")
	stub(t, &execve, func(_ string, argv []string, _ []string) error { got = argv; return errExec })

	if _, err := asHubUser(cfg, []string{"user", "list"}); err != errExec {
		t.Fatalf("want exec, got %v", err)
	}
	if got[0] != "runuser" || got[1] != "-u" || !slices.Equal(got[len(got)-4:], []string{"-c", cfg, "user", "list"}) {
		t.Errorf("argv = %q", got)
	}
	got = nil
	for _, args := range [][]string{{"upgrade"}, {"restart"}, {"sso", "setup"}, {"ingest", "cert"}, {"ai", "set-key"}, {"ai", "test"}, {"notify", "set-webhook"}, {"notify", "test"}, {"tailscale", "set-key"}, {"cloudflare", "set-token"}, {"ip-services", "set-key", "ploi"}, {"bans", "set-token"}, {}} {
		if _, err := asHubUser(cfg, args); err != nil || got != nil {
			t.Errorf("%v should run as root: %v %q", args, err, got)
		}
	}
	if _, err := asHubUser(t.TempDir()+"/missing.toml", []string{"user", "list"}); err != nil || got != nil {
		t.Error("no hub config: should run as is")
	}
	stub(t, &euid, func() int { return 1000 })
	if _, err := asHubUser(cfg, []string{"user", "list"}); err != nil || got != nil {
		t.Error("not root: should run as is")
	}
}

func TestAsHubUserKeyCommands(t *testing.T) {
	fi, err := os.Stat(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	uid, _, _ := fileOwner(fi)
	if uid == 0 {
		t.Skip("running as root: the test file's owner is root")
	}
	cfg := t.TempDir() + "/heimdall.toml"
	os.WriteFile(cfg, []byte(""), 0o600)
	wd, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(wd) })
	stub(t, &euid, func() int { return 0 })
	stub(t, &execve, func(string, []string, []string) error { t.Error("key command exec'd runuser"); return nil })
	var gotUID, gotGID = -1, -1
	stub(t, &setgroups, func([]int) error { return nil })
	stub(t, &setgid, func(g int) error { gotGID = g; return nil })
	stub(t, &setuid, func(u int) error { gotUID = u; return nil })
	for _, args := range [][]string{{"tailscale", "status"}, {"cloudflare", "sync"}, {"ip-services", "status"}, {"bans", "status"}} {
		gotUID = -1
		path, err := asHubUser(cfg, args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if path != cfg { // absolute already; runs on from /
			t.Errorf("%v: config path %q, want %q", args, path, cfg)
		}
		if gotUID != uid || gotGID < 0 {
			t.Errorf("%v: setuid(%d) setgid(%d), want uid %d", args, gotUID, gotGID, uid)
		}
	}
}

func TestReadKeyFilePreloaded(t *testing.T) {
	path := t.TempDir() + "/missing-key"
	t.Cleanup(func() { delete(preloadedKeys, path) })
	if _, _, err := readKeyFile(path); err == nil {
		t.Fatal("missing file read")
	}
	if keyFallback(false) {
		t.Fatal("fallback with nothing preloaded")
	}
	preloadedKeys[path] = preloadedKey{perm: 0o600, b: []byte("secret\n")}
	perm, b, err := readKeyFile(path)
	if err != nil || perm != 0o600 || string(b) != "secret\n" || !keyFallback(false) {
		t.Fatalf("preloaded = %v %q %v", perm, b, err)
	}
}

// hubUserCommands run as the hub user under sudo: they read the config and
// database only, never a root-owned key file.
var hubUserCommands = map[string]bool{
	"ai status": true, "anomaly ack": true, "anomaly list": true, "anomaly suppress": true, "backup": true,
	"bans approve": true, "bans list": true, "bans pause": true, "bans reject": true, "bans resume": true,
	"bans token-url": true, "bans unban": true, "cloudflare token-url": true, "collector list": true,
	"collector trust": true, "config update": true, "drift": true, "enroll approve": true, "enroll create": true,
	"enroll list": true, "enroll pending": true, "enroll revoke": true, "env create": true, "env list": true,
	"feeds status": true, "feeds sync": true, "host add": true, "host diff": true, "host history": true,
	"host list": true, "host rename": true, "host rm": true, "host show": true, "host token": true,
	"import": true, "init": true, "ip label": true, "ip policy": true, "ip show": true, "migrate": true,
	"notify preview": true, "offenders": true, "org create": true, "org list": true, "plan add": true,
	"plan close": true, "plan create": true, "plan done": true, "plan list": true, "plan rm": true,
	"plan show": true, "plan undo": true, "report": true, "sbom": true, "serve": true, "surface": true,
	"user create": true, "user delete": true, "user disable": true, "user enable": true, "user grant": true, "user list": true,
	"user mcp-token": true, "user passwd": true, "user reset-totp": true, "user revoke": true,
	"window add": true, "window list": true, "window rm": true,
}

// TestEveryCommandRunsAsTheRightUser: `sudo heimdall <command>` runs as
// root (rootCommands), reads key files as root and then drops
// (keyCommands), or runs as the hub user. A new command must be put in one
// of the three on purpose: a key-reading command left as the hub user
// can't read its root-owned file on an installed hub.
func TestEveryCommandRunsAsTheRightUser(t *testing.T) {
	for name := range commands {
		paths := []string{name}
		if subs, ok := groupSubs[name]; ok {
			paths = paths[:0]
			for _, s := range subs {
				paths = append(paths, name+" "+s)
			}
		}
		for _, p := range paths {
			root := rootCommands[p] || rootCommands[strings.Fields(p)[0]]
			n := 0
			for _, in := range []bool{root, keyCommands[p], hubUserCommands[p]} {
				if in {
					n++
				}
			}
			if n != 1 {
				t.Errorf("%q is in %d of rootCommands, keyCommands and hubUserCommands; put it in exactly one "+
					"(root: needs root itself; key: reads a root-owned key file, then uses the database; "+
					"hub user: everything else)", p, n)
			}
		}
	}
}
