// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// rootCommands need root themselves; everything else runs as the hub user.
var rootCommands = map[string]bool{"upgrade": true, "restart": true, "sso": true, "ingest": true, "version": true,
	"ai set-key": true, "ai test": true, // "ai test" reads the root-owned key file
	// set-webhook adds a LoadCredential line to the unit; test reads the
	// root-owned files it stores.
	"notify set-webhook": true, "notify test": true,
	// Store a root-owned key file and add its LoadCredential line.
	"tailscale set-key": true, "cloudflare set-token": true, "ip-services set-key": true, "bans set-token": true,
	"mcp set-name": true} // edits the root-owned config, as sso setup does

// keyCommands read a root-owned key file and then use the hub's database:
// they read the key files as root, then drop to the hub user in-process,
// so the database never gets a root-owned file.
var keyCommands = map[string]bool{"tailscale status": true, "tailscale sync": true,
	"cloudflare status": true, "cloudflare sync": true, "ip-services status": true, "ip-services sync": true,
	"bans status": true, "notify send": true}

// Seams for tests.
var (
	euid   = os.Geteuid
	execve = syscall.Exec
)

// asHubUser makes `sudo heimdall <command>` on an installed hub run as the
// user that owns its config (and database), so files never end up owned by
// root and nobody has to type `runuser -u heimdall-hub -- ...`. It replaces
// the process and only returns if that isn't possible or needed, with the
// config path to use (a keyCommand runs on in this process, from /).
func asHubUser(configPath string, args []string) (string, error) {
	if euid() != 0 || len(args) == 0 || rootCommands[args[0]] || (len(args) > 1 && rootCommands[args[0]+" "+args[1]]) {
		return configPath, nil
	}
	path := hubConfigPath(configPath)
	fi, err := os.Stat(path)
	if err != nil {
		return configPath, nil
	}
	uid, _, ok := fileOwner(fi)
	if !ok || uid == 0 {
		return configPath, nil
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return configPath, nil
	}
	if len(args) > 1 && keyCommands[args[0]+" "+args[1]] {
		if path, err = filepath.Abs(path); err != nil {
			return configPath, err
		}
		return path, dropInProcess(u)
	}
	runuser, err := exec.LookPath("runuser")
	if err != nil {
		return configPath, nil
	}
	self, err := os.Executable()
	if err != nil {
		return configPath, err
	}
	// The hub user usually can't enter the caller's directory.
	if err := os.Chdir("/"); err != nil {
		return configPath, err
	}
	argv := append([]string{"runuser", "-u", u.Username, "--", self, "-c", path}, args...)
	return configPath, execve(runuser, argv, os.Environ())
}

// dropInProcess keeps a copy of each key file root can read (see
// readKeyFile), then becomes u: groups, then gid, then uid.
func dropInProcess(u *user.User) error {
	paths := []string{defaultCloudflareTokenFile, defaultTailscaleKeyFile, defaultBansTokenFile}
	for _, id := range tokenServices() {
		paths = append(paths, serviceTokenFile(id))
	}
	if ps, err := filepath.Glob(filepath.Join(notifySecretDir, "notify-*")); err == nil {
		paths = append(paths, ps...)
	}
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Size() <= 4096 {
			if b, err := os.ReadFile(p); err == nil {
				preloadedKeys[p] = preloadedKey{perm: fi.Mode().Perm(), b: b}
			}
		}
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	groups := []int{gid}
	if ids, err := u.GroupIds(); err == nil {
		for _, g := range ids {
			if n, err := strconv.Atoi(g); err == nil && n != gid {
				groups = append(groups, n)
			}
		}
	}
	if err := setgroups(groups); err != nil {
		return err
	}
	if err := setgid(gid); err != nil {
		return err
	}
	if err := setuid(uid); err != nil {
		return err
	}
	return os.Chdir("/")
}

var (
	setgroups = syscall.Setgroups
	setgid    = syscall.Setgid
	setuid    = syscall.Setuid
)
