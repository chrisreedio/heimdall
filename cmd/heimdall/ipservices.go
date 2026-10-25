// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/ipinfo"
	"github.com/chrisreedio/heimdall/internal/ipinfo/services"
	"github.com/chrisreedio/heimdall/internal/store"
)

// Deploy services whose list needs the customer's API token (Ploi) keep it
// like the AI key: an owner-only file loaded as systemd credential
// "heimdall-<id>", never in the config.
func serviceCredential(id string) string { return "heimdall-" + id }
func serviceTokenFile(id string) string  { return "/etc/heimdall/" + id + "-token" }
func serviceTokenEnv(id string) string {
	return "HEIMDALL_" + strings.ToUpper(strings.ReplaceAll(id, "-", "_")) + "_TOKEN_FILE"
}

// deployServices builds the configured deploy services' user hints and
// syncers for newIPResolver.
func deployServices(cfg config.Config, s *store.Store, log *slog.Logger) ([]ipinfo.UserHint, []ipinfo.Syncer) {
	b := newDeployServices(cfg, s, false)
	for _, id := range b.NoToken {
		log.Info("deploy service known by account name only: its address list needs an API token",
			"service", id, "fix", "sudo heimdall ip-services set-key "+id)
	}
	syncers := make([]ipinfo.Syncer, 0, len(b.Syncers)+1)
	for _, sy := range b.Syncers {
		syncers = append(syncers, sy)
	}
	syncers = append(syncers, &services.Pruner{Store: s, Keep: b.Sources})
	return b.Hints, syncers
}

func newDeployServices(cfg config.Config, s *store.Store, fallback bool) services.Built {
	return services.New(cfg.DeployServices, services.Setup{Store: s, UserAgent: "heimdall/" + version,
		Token: func(id string) (string, error) {
			t, _, err := serviceToken(id, fallback)
			return t, err
		}})
}

// cmdIPServicesSetKey stores a service's API token exactly like `ai
// set-key` stores the AI key.
func cmdIPServicesSetKey(a *app, args []string) error {
	fs := a.flags("ip-services set-key", "<service> [--file path] [--stdin] [--unit path]")
	path := fs.String("file", "", "where to store the token (default /etc/heimdall/<service>-token, the unit's LoadCredential source)")
	fromStdin := fs.Bool("stdin", false, "read the token from stdin instead of a terminal prompt")
	unitFile := fs.String("unit", hubUnitFile, "the hub's systemd unit (gets the LoadCredential line)")
	rest, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	id := rest[0]
	if svc, ok := services.Lookup(id); !ok || !svc.Token {
		return fmt.Errorf("%q has no API token to store (only: %s)", id, strings.Join(tokenServices(), ", "))
	}
	svc, _ := services.Lookup(id)
	if *path == "" {
		*path = serviceTokenFile(id)
	}
	var key string
	if *fromStdin {
		b, err := io.ReadAll(io.LimitReader(stdin, 4097))
		if err != nil {
			return err
		}
		key = strings.TrimSpace(string(b))
	} else {
		in, err := newInput(a, false)
		if err != nil {
			return errors.New("stdin is not a terminal; use --stdin to pipe the token")
		}
		if key, err = in.line(svc.Name+" API token (input hidden): ", true); err != nil {
			return err
		}
		key = strings.TrimSpace(key)
	}
	if key == "" {
		return errors.New("empty token")
	}
	if len(key) > 4096 || strings.ContainsFunc(key, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errors.New("that doesn't look like an API token")
	}
	if err := writePrivate(*path, key+"\n"); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Stored the %s API token in %s (owner-only).\n", svc.Name, *path)
	cred := serviceCredential(id)
	if *path == serviceTokenFile(id) || *unitFile != hubUnitFile {
		changed, err := enableCredential(*unitFile, cred, *path)
		switch {
		case err != nil:
			fmt.Fprintf(a.stderr, "Couldn't update the unit (%v).\nAdd `LoadCredential=%s:%s` to it yourself, then: sudo heimdall restart\n", err, cred, *path)
			return nil
		case changed:
			fmt.Fprintf(a.stderr, "Added LoadCredential=%s to %s.\n", cred, *unitFile)
			if *unitFile == hubUnitFile {
				if err := systemctl(a, "daemon-reload"); err != nil {
					fmt.Fprintf(a.stderr, "systemctl daemon-reload failed: %v\n", err)
				}
			}
		}
	}
	fmt.Fprintf(a.stderr, "Check it with `sudo heimdall ip-services sync %s`, then apply with: sudo heimdall restart\n", id)
	return nil
}

func tokenServices() []string {
	var out []string
	for _, s := range services.Catalog {
		if s.Token {
			out = append(out, s.ID)
		}
	}
	return out
}

// serviceToken reads a service's API token from its systemd credential,
// or from HEIMDALL_<ID>_TOKEN_FILE; with fallback (CLI as root), from the
// default file. Never from the config file.
func serviceToken(id string, fallback bool) (string, string, error) {
	cred := serviceCredential(id)
	path, fromSystemd := os.Getenv(serviceTokenEnv(id)), false
	if path == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			if _, err := os.Stat(filepath.Join(dir, cred)); err == nil {
				path, fromSystemd = filepath.Join(dir, cred), true
			}
		}
	}
	if path == "" && fallback {
		path = serviceTokenFile(id)
	}
	if path == "" {
		return "", "", fmt.Errorf("no %s API token: run `sudo heimdall ip-services set-key %s`", id, id)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", path, fmt.Errorf("%s API token: %w", id, err)
	}
	if !fromSystemd && fi.Mode().Perm()&0o077 != 0 {
		return "", path, fmt.Errorf("%s API token %s is readable by other users; run `chmod 600 %s`", id, path, path)
	}
	if fi.Size() > 4096 {
		return "", path, fmt.Errorf("%s API token %s is suspiciously large", id, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", path, err
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", path, fmt.Errorf("%s API token %s is empty", id, path)
	}
	return tok, path, nil
}

// cmdIPServicesStatus lists the configured services, their last sync and
// how they're recognized.
func cmdIPServicesStatus(a *app, args []string) error {
	if _, err := parse(a.flags("ip-services status", ""), args, 0); err != nil {
		return err
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	states, err := s.IPSourceStates(a.ctx)
	if err != nil {
		return err
	}
	b := newDeployServices(cfg, s, isRoot())
	if len(b.Sources) == 0 {
		fmt.Fprintln(a.stderr, "No deploy services configured (services under [deploy_services] in heimdall.toml).")
		return nil
	}
	var rows [][]string
	for _, sy := range b.Syncers {
		rows = append(rows, statusRow(sy.Service, sy.Name(), states, ""))
	}
	for _, id := range b.NoToken {
		svc, _ := services.Lookup(id)
		rows = append(rows, statusRow(svc, services.Source(id), states, "account name only: no API token (sudo heimdall ip-services set-key "+id+")"))
	}
	return table(a, "SERVICE\tNAME\tRANGES\tLAST SUCCESS\tLAST ATTEMPT\tUSERS\tSTATUS", rows)
}

func statusRow(svc services.Service, source string, states []store.IPSourceState, note string) []string {
	users := strings.Join(svc.Users, ",")
	if users == "" {
		users = "-"
	}
	i := slices.IndexFunc(states, func(st store.IPSourceState) bool { return st.Source == source })
	if i < 0 {
		if note == "" {
			note = "not synced yet"
		}
		return []string{strings.TrimPrefix(source, "service:"), svc.Name, "0", "never", "never", users, note}
	}
	st := states[i]
	status := "ok"
	switch {
	case note != "":
		status = note
	case st.LastError != "":
		status = "error: " + st.LastError
	}
	return []string{strings.TrimPrefix(source, "service:"), svc.Name, strconv.Itoa(st.Labels),
		formatTime(st.LastSuccess), formatTime(st.LastAttempt), users, status}
}

// cmdIPServicesSync fetches every configured service's list now (or just
// the named ones).
func cmdIPServicesSync(a *app, args []string) error {
	rest, err := parseAtLeast(a.flags("ip-services sync", "[service...]"), args, 0)
	if err != nil {
		return err
	}
	cfg, err := config.Load(hubConfigPath(a.configPath))
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	b := newDeployServices(cfg, s, isRoot())
	for _, id := range rest {
		if !slices.ContainsFunc(b.Syncers, func(sy *services.Syncer) bool { return sy.Service.ID == id }) {
			return fmt.Errorf("%q isn't a configured service with a list to sync", id)
		}
	}
	var failed []string
	for _, sy := range b.Syncers {
		if len(rest) > 0 && !slices.Contains(rest, sy.Service.ID) {
			continue
		}
		if err := sy.Sync(a.ctx); err != nil {
			fmt.Fprintf(a.stderr, "%s: failed, kept the last good list: %v\n", sy.Service.ID, err)
			failed = append(failed, sy.Service.ID)
			continue
		}
		fmt.Fprintf(a.stderr, "%s: synced\n", sy.Service.ID)
	}
	for _, id := range b.NoToken {
		if len(rest) == 0 {
			fmt.Fprintf(a.stderr, "%s: skipped, no API token (sudo heimdall ip-services set-key %s)\n", id, id)
		}
	}
	if len(rest) == 0 {
		if err := (&services.Pruner{Store: s, Keep: b.Sources}).Sync(a.ctx); err != nil {
			return err
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d service(s) failed: %s", len(failed), strings.Join(failed, ", "))
	}
	return nil
}
