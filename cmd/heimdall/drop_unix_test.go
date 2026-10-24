// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import (
	"errors"
	"os"
	"slices"
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

	if err := asHubUser(cfg, []string{"user", "list"}); err != errExec {
		t.Fatalf("want exec, got %v", err)
	}
	if got[0] != "runuser" || got[1] != "-u" || !slices.Equal(got[len(got)-4:], []string{"-c", cfg, "user", "list"}) {
		t.Errorf("argv = %q", got)
	}
	got = nil
	for _, args := range [][]string{{"upgrade"}, {"restart"}, {"sso", "setup"}, {"ingest", "cert"}, {"ai", "set-key"}, {"ai", "test"}, {}} {
		if err := asHubUser(cfg, args); err != nil || got != nil {
			t.Errorf("%v should run as root: %v %q", args, err, got)
		}
	}
	if err := asHubUser(t.TempDir()+"/missing.toml", []string{"user", "list"}); err != nil || got != nil {
		t.Error("no hub config: should run as is")
	}
	stub(t, &euid, func() int { return 1000 })
	if err := asHubUser(cfg, []string{"user", "list"}); err != nil || got != nil {
		t.Error("not root: should run as is")
	}
}
