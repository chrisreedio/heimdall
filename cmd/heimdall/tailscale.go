// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/tailscale"
)

// tailscaleCredential is the systemd credential name holding the
// Tailscale OAuth client or API access token.
const tailscaleCredential = "heimdall-tailscale"

// defaultTailscaleKeyFile is where the unit's LoadCredential line reads it.
const defaultTailscaleKeyFile = "/etc/heimdall/tailscale-key"

// newTailscaleClient builds the API client. A seam for tests.
var newTailscaleClient = func(cred tailscale.Credential, tailnet string) *tailscale.Client {
	return tailscale.NewClient(cred, tailnet, "heimdall/"+version)
}

// cmdTailscaleSetKey stores the credential exactly like `ai set-key`
// stores the AI key: read with echo off (or from stdin), written
// owner-only and atomically, and loaded by the hub as a systemd
// credential. An OAuth client secret (tskey-client-…) also needs its
// client ID, which isn't secret.
func cmdTailscaleSetKey(a *app, args []string) error {
	fs := a.flags("tailscale set-key", "[--client-id ID] [--file path] [--stdin] [--unit path]")
	clientID := fs.String("client-id", "", "the OAuth client's ID (for an OAuth client secret; asked for if needed)")
	path := fs.String("file", defaultTailscaleKeyFile, "where to store the credential (the unit's LoadCredential source)")
	fromStdin := fs.Bool("stdin", false, "read the secret from stdin instead of a terminal prompt")
	unitFile := fs.String("unit", hubUnitFile, "the hub's systemd unit (gets the LoadCredential line)")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	var secret string
	var in *input
	if *fromStdin {
		b, err := io.ReadAll(io.LimitReader(stdin, 4097))
		if err != nil {
			return err
		}
		secret = strings.TrimSpace(string(b))
	} else {
		var err error
		if in, err = newInput(a, false); err != nil {
			return errors.New("stdin is not a terminal; use --stdin to pipe the secret")
		}
		fmt.Fprintf(a.stderr, "Create an OAuth client here with only the Devices > Core > Read scope (%s):\n\n  %s\n\n", tailscale.Scope, tailscale.OAuthClientsURL)
		if secret, err = in.line("Tailscale OAuth client secret or API access token (input hidden): ", true); err != nil {
			return err
		}
		secret = strings.TrimSpace(secret)
	}
	if secret == "" {
		return errors.New("empty secret")
	}
	var cred tailscale.Credential
	switch {
	case strings.HasPrefix(secret, "tskey-api-"):
		cred.APIKey = secret
	case strings.HasPrefix(secret, "tskey-auth-"):
		return errors.New("that's an auth key (for adding devices), not an API credential; create an OAuth client with the " +
			tailscale.Scope + " scope instead (see docs/tailscale.md)")
	default: // an OAuth client secret (tskey-client-…)
		cred.ClientSecret, cred.ClientID = secret, strings.TrimSpace(*clientID)
		if cred.ClientID == "" && in != nil {
			id, err := in.line("OAuth client ID: ", false)
			if err != nil {
				return err
			}
			cred.ClientID = strings.TrimSpace(id)
		}
		if cred.ClientID == "" {
			return errors.New("an OAuth client secret needs its client ID: pass --client-id")
		}
	}
	if err := cred.Check(); err != nil {
		return err
	}
	if err := writePrivate(*path, "# Tailscale credential for Heimdall (read only: "+tailscale.Scope+")\n"+cred.Encode()); err != nil {
		return err
	}
	kind := map[string]string{tailscale.KindOAuth: "OAuth client", tailscale.KindAPIKey: "API access token"}[cred.Kind()]
	fmt.Fprintf(a.stderr, "Stored the Tailscale %s in %s (owner-only).\n", kind, *path)
	if cred.Kind() == tailscale.KindAPIKey {
		fmt.Fprintln(a.stderr, "Note: API access tokens expire (90 days at most); an OAuth client doesn't. `heimdall tailscale status` warns before it does.")
	}
	if *path == defaultTailscaleKeyFile || *unitFile != hubUnitFile {
		changed, err := enableCredential(*unitFile, tailscaleCredential, *path)
		switch {
		case err != nil:
			fmt.Fprintf(a.stderr, "Couldn't update the unit (%v).\nAdd `LoadCredential=%s:%s` to it yourself, then: sudo heimdall restart\n", err, tailscaleCredential, *path)
			return nil
		case changed:
			fmt.Fprintf(a.stderr, "Added LoadCredential=%s to %s.\n", tailscaleCredential, *unitFile)
			if *unitFile == hubUnitFile {
				if err := systemctl(a, "daemon-reload"); err != nil {
					fmt.Fprintf(a.stderr, "systemctl daemon-reload failed: %v\n", err)
				}
			}
		}
	}
	fmt.Fprintln(a.stderr, "Check it with `sudo heimdall tailscale sync`, then apply with: sudo heimdall restart")
	return nil
}

// tailscaleCred reads the credential from the systemd credential, or from
// HEIMDALL_TAILSCALE_KEY_FILE. It is never read from the config file. With
// fallback (CLI as root), the default file is used directly.
func tailscaleCred(fallback bool) (tailscale.Credential, string, error) {
	path, fromSystemd := os.Getenv("HEIMDALL_TAILSCALE_KEY_FILE"), false
	if path == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			if _, err := os.Stat(filepath.Join(dir, tailscaleCredential)); err == nil {
				path, fromSystemd = filepath.Join(dir, tailscaleCredential), true
			}
		}
	}
	if path == "" && keyFallback(fallback) {
		path = defaultTailscaleKeyFile
	}
	if path == "" {
		return tailscale.Credential{}, "", errors.New("no Tailscale credential: run `sudo heimdall tailscale set-key` (it adds `LoadCredential=" +
			tailscaleCredential + ":" + defaultTailscaleKeyFile + "` to the unit), or set HEIMDALL_TAILSCALE_KEY_FILE")
	}
	perm, b, err := readKeyFile(path)
	if err != nil {
		return tailscale.Credential{}, path, fmt.Errorf("tailscale credential: %w", err)
	}
	if !fromSystemd && perm&0o077 != 0 {
		return tailscale.Credential{}, path, fmt.Errorf("tailscale credential %s is readable by other users; run `chmod 600 %s`", path, path)
	}
	if len(b) > 4096 {
		return tailscale.Credential{}, path, fmt.Errorf("tailscale credential %s is suspiciously large", path)
	}
	cred, err := tailscale.ParseCredential(string(b))
	if err != nil {
		return tailscale.Credential{}, path, fmt.Errorf("%s: %w", path, err)
	}
	return cred, path, nil
}

// newTailscaleSyncer builds serve's Tailscale syncer (nil when
// [tailscale] is off). A missing credential doesn't stop the hub: the
// sync fails and status says why.
func newTailscaleSyncer(cfg config.Config, s *store.Store, log *slog.Logger, fallback bool) (*tailscale.Syncer, error) {
	if !cfg.Tailscale.Enabled {
		return nil, nil
	}
	cred, _, err := tailscaleCred(fallback)
	if err != nil {
		return nil, err
	}
	return &tailscale.Syncer{Store: s, Client: newTailscaleClient(cred, cfg.Tailscale.Tailnet), Period: cfg.Tailscale.SyncEvery.Duration,
		Now: time.Now, Log: log.With("component", "tailscale")}, nil
}

// keyExpiresSoon is when status starts warning about an API access token.
const keyExpiresSoon = 14 * 24 * time.Hour

func cmdTailscaleStatus(a *app, args []string) error {
	if _, err := parse(a.flags("tailscale status", ""), args, 0); err != nil {
		return err
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	c, out := cfg.Tailscale, a.stdout
	if !c.Enabled {
		fmt.Fprintln(out, "Tailscale: off (set enabled = true under [tailscale] in heimdall.toml)")
		return nil
	}
	fmt.Fprintf(out, "Tailscale:   on, tailnet %q, sync every %s\n", c.Tailnet, c.SyncEvery.Duration)
	switch cred, path, err := tailscaleCred(isRoot()); {
	case err == nil:
		fmt.Fprintf(out, "Credential:  %s, loaded from %s\n", cred.Kind(), path)
	default:
		if fi, serr := os.Stat(defaultTailscaleKeyFile); serr == nil && fi.Mode().IsRegular() {
			fmt.Fprintf(out, "Credential:  stored in %s (the hub loads it as credential %q)\n", defaultTailscaleKeyFile, tailscaleCredential)
		} else {
			fmt.Fprintln(out, "Credential:  not set (run `sudo heimdall tailscale set-key`)")
		}
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.TailnetSyncState(a.ctx)
	if err != nil {
		return err
	}
	var warnings []string
	fmt.Fprintf(out, "Last sync:   %s", formatTime(st.SyncedAt))
	if !st.SyncedAt.IsZero() {
		fmt.Fprintf(out, " (%d devices, %s)", st.Devices, st.Credential)
	}
	fmt.Fprintln(out)
	if st.Error != "" {
		fmt.Fprintf(out, "Last error:  %s (at %s)\n", st.Error, formatTime(st.AttemptedAt))
	}
	if !st.KeyExpires.IsZero() {
		fmt.Fprintf(out, "Key expires: %s\n", formatTime(st.KeyExpires))
		if left := time.Until(st.KeyExpires); left < keyExpiresSoon {
			warnings = append(warnings, fmt.Sprintf("the API access token expires %s; switch to an OAuth client (it doesn't expire), see docs/tailscale.md",
				map[bool]string{true: "in " + left.Round(time.Hour).String(), false: "(it has expired)"}[left > 0]))
		}
	}
	if !st.SyncedAt.IsZero() && time.Since(st.SyncedAt) > 3*c.SyncEvery.Duration+time.Hour {
		warnings = append(warnings, "the last good sync is old; the labels may be out of date")
	}
	devs, err := s.TailnetDevices(a.ctx)
	if err != nil {
		return err
	}
	if len(devs) > 0 {
		hosts, err := s.TailnetHosts(a.ctx)
		if err != nil {
			return err
		}
		matched := tailscale.MatchHosts(hosts, devs)
		var off []string
		for _, h := range hosts {
			if _, ok := matched[h.ID]; !ok {
				off = append(off, h.Name)
			}
		}
		fmt.Fprintf(out, "Hosts:       %d of %d on the tailnet\n", len(matched), len(hosts))
		if len(off) > 0 {
			fmt.Fprintf(out, "Not on the tailnet: %s\n", strings.Join(off, ", "))
		}
		for _, d := range devs {
			if !d.KeyExpiry.IsZero() && time.Until(d.KeyExpiry) < keyExpiresSoon {
				warnings = append(warnings, fmt.Sprintf("device %s's node key expires %s", tailscale.DeviceName(d), formatTime(d.KeyExpiry)))
			}
		}
	}
	for _, w := range warnings {
		fmt.Fprintln(out, "Warning:", w)
	}
	return nil
}

// cmdTailscaleSync syncs once now and prints a summary (never the
// credential).
func cmdTailscaleSync(a *app, args []string) error {
	if _, err := parse(a.flags("tailscale sync", ""), args, 0); err != nil {
		return err
	}
	cfg, err := config.Load(hubConfigPath(a.configPath))
	if err != nil {
		return err
	}
	if !cfg.Tailscale.Enabled {
		return errors.New("[tailscale] is off; set enabled = true in heimdall.toml first")
	}
	a.configPath = hubConfigPath(a.configPath)
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	sy, err := newTailscaleSyncer(cfg, s, slog.New(slog.NewTextHandler(io.Discard, nil)), isRoot())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
	defer cancel()
	res, err := sy.Run(ctx)
	if err != nil {
		return fmt.Errorf("sync failed (the last good labels stay): %w", err)
	}
	fmt.Fprintf(a.stdout, "OK: %d devices, %d address labels, %d of your hosts on the tailnet\n", res.Devices, res.Labels, res.Hosts)
	if !res.KeyExpires.IsZero() {
		fmt.Fprintf(a.stdout, "The API access token expires %s.\n", formatTime(res.KeyExpires))
	}
	return nil
}
