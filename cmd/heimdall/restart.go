// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/realmwatch/heimdall/internal/config"
)

// Seams for tests.
var (
	showJournal = func(a *app) {
		cmd := exec.CommandContext(a.ctx, "journalctl", "-u", "heimdall", "-n", "15", "--no-pager", "-o", "cat")
		cmd.Stdout, cmd.Stderr = a.stderr, a.stderr
		_ = cmd.Run()
	}
	restartWait = 30 * time.Second
)

// cmdRestart restarts the hub's service (picking up config and unit
// changes) and waits until the UI answers, showing the log if it doesn't.
func cmdRestart(a *app, args []string) error {
	fs := a.flags("restart", "")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	if !isRoot() {
		return errors.New("restarting the hub's service needs root: run it with sudo")
	}
	cfg, err := config.Load(hubConfigPath(a.configPath))
	if err != nil {
		return fmt.Errorf("%w (not restarting: the hub would fail to start with this config)", err)
	}
	if err := systemctl(a, "daemon-reload"); err != nil {
		return err
	}
	fmt.Fprintln(a.stderr, "Restarting heimdall...")
	if err := systemctl(a, "restart", "heimdall"); err != nil {
		showJournal(a)
		return errors.New("the restart failed; the hub's log is above")
	}
	hc := &http.Client{Timeout: 2 * time.Second}
	for deadline := time.Now().Add(restartWait); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		if systemctl(a, "is-active", "--quiet", "heimdall") != nil {
			continue
		}
		if resp, err := hc.Get("http://" + cfg.UI.Listen + "/login"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				fmt.Fprintf(a.stderr, "Heimdall is running and answering at %s\n", cfg.UI.BaseURL)
				return nil
			}
		}
	}
	showJournal(a)
	return errors.New("the hub didn't come up; its log is above")
}
