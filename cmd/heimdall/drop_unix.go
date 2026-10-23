// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// rootCommands need root themselves; everything else runs as the hub user.
var rootCommands = map[string]bool{"upgrade": true, "restart": true, "sso": true, "ingest": true, "version": true}

// Seams for tests.
var (
	euid   = os.Geteuid
	execve = syscall.Exec
)

// asHubUser makes `sudo heimdall <command>` on an installed hub run as the
// user that owns its config (and database), so files never end up owned by
// root and nobody has to type `runuser -u heimdall-hub -- ...`. It replaces
// the process and only returns if that isn't possible or needed.
func asHubUser(configPath string, args []string) error {
	if euid() != 0 || len(args) == 0 || rootCommands[args[0]] {
		return nil
	}
	path := hubConfigPath(configPath)
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	uid, _, ok := fileOwner(fi)
	if !ok || uid == 0 {
		return nil
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return nil
	}
	runuser, err := exec.LookPath("runuser")
	if err != nil {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	// The hub user usually can't enter the caller's directory.
	if err := os.Chdir("/"); err != nil {
		return err
	}
	argv := append([]string{"runuser", "-u", u.Username, "--", self, "-c", path}, args...)
	return execve(runuser, argv, os.Environ())
}
