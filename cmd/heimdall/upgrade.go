// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/realmwatch/heimdall/internal/netx"
	"github.com/realmwatch/heimdall/internal/updates"
)

// releaseBase is where release assets are downloaded from.
var releaseBase = "https://github.com/realmwatch/heimdall/releases/download/"

// Seams for tests.
var (
	upgradeHTTP = func() *netx.Client { return netx.New(netx.UpgradeHosts, "heimdall/"+version) }
	latestURL   = updates.LatestURL
	runShell    = func(a *app, script string, args []string) error {
		cmd := exec.CommandContext(a.ctx, "sh", append([]string{script}, args...)...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, a.stderr, a.stderr
		return cmd.Run()
	}
	isRoot = func() bool { return os.Geteuid() == 0 }
)

// cmdUpgrade upgrades this hub to the latest (or a given) release by
// running that release's install-hub.sh, after checking it against the
// release's SHA256SUMS. The installer then verifies the rest (and the
// Sigstore signature, when cosign is installed), stops the hub, migrates,
// restarts and rolls back on failure.
func cmdUpgrade(a *app, args []string) error {
	fs := a.flags("upgrade", "[--version vX.Y.Z] [--check] [-- install-hub.sh flags]")
	want := fs.String("version", "", "release to install (default: the latest)")
	check := fs.Bool("check", false, "only report whether a newer release exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	extra := fs.Args()
	hc := upgradeHTTP()

	tag := *want
	if tag == "" {
		r, err := updates.Latest(a.ctx, hc, latestURL)
		if err != nil {
			return fmt.Errorf("finding the latest release: %w", err)
		}
		tag = r.Version
	} else if !updates.IsTag(tag) {
		return fmt.Errorf("--version must look like v1.2.3, not %q", tag)
	}

	newer := updates.Newer(tag, version)
	switch {
	case *check && newer:
		fmt.Fprintf(a.stdout, "%s is available (running %s). Upgrade with: sudo heimdall upgrade\n", tag, version)
		return nil
	case *check:
		fmt.Fprintf(a.stdout, "Up to date (%s; latest %s).\n", version, tag)
		return nil
	case *want == "" && !newer && updates.IsTag(version):
		fmt.Fprintf(a.stderr, "Already on the latest release (%s).\n", version)
		return nil
	}
	if !isRoot() {
		return errors.New("upgrading replaces /usr/local/bin/heimdall and restarts the service: run it with sudo")
	}

	fmt.Fprintf(a.stderr, "Fetching install-hub.sh for %s\n", tag)
	sums, _, err := hc.Get(a.ctx, releaseBase+tag+"/SHA256SUMS", 1<<16, nil)
	if err != nil {
		return err
	}
	script, _, err := hc.Get(a.ctx, releaseBase+tag+"/install-hub.sh", 1<<20, nil)
	if err != nil {
		return err
	}
	if err := checkSum(sums, "install-hub.sh", script); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "heimdall-upgrade-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "install-hub.sh")
	if err := os.WriteFile(path, script, 0o700); err != nil {
		return err
	}
	return runShell(a, path, append([]string{"--version", tag}, extra...))
}

// checkSum verifies data against name's entry in a SHA256SUMS file.
func checkSum(sums []byte, name string, data []byte) error {
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			if f[0] != got {
				return fmt.Errorf("%s doesn't match the release's SHA256SUMS; not running it", name)
			}
			return nil
		}
	}
	return fmt.Errorf("%s isn't listed in the release's SHA256SUMS", name)
}
