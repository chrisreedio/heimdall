// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/auth/entra"
	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/netx"
)

// entraCredential is the systemd credential name holding the client secret.
const entraCredential = "heimdall-entra"

// defaultEntraSecretFile is where the unit's LoadCredential line reads it.
const defaultEntraSecretFile = "/etc/heimdall/entra-secret"

// cmdSSOSetSecret stores the Entra client secret without it touching shell
// history or the process list: it's read with echo off (or from stdin) and
// written owner-only, atomically.
func cmdSSOSetSecret(a *app, args []string) error {
	fs := a.flags("sso set-secret", "[--file path] [--stdin]")
	path := fs.String("file", defaultEntraSecretFile, "where to store the secret (the unit's LoadCredential source)")
	fromStdin := fs.Bool("stdin", false, "read the secret from stdin instead of a terminal prompt")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	var secret string
	if *fromStdin {
		b, err := io.ReadAll(io.LimitReader(stdin, 4097))
		if err != nil {
			return err
		}
		secret = strings.TrimSpace(string(b))
	} else {
		in, err := newInput(a, false)
		if err != nil {
			return errors.New("stdin is not a terminal; use --stdin to pipe the secret")
		}
		if secret, err = in.line("Entra client secret (input hidden): ", true); err != nil {
			return err
		}
		secret = strings.TrimSpace(secret)
	}
	if secret == "" {
		return errors.New("empty secret")
	}
	if len(secret) > 4096 || strings.ContainsAny(secret, "\r\n") {
		return errors.New("that doesn't look like a client secret (paste the secret's Value)")
	}
	if err := writePrivate(*path, secret+"\n"); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Stored the client secret in %s (owner-only).\n", *path)
	if *path == defaultEntraSecretFile {
		fmt.Fprintln(a.stderr, "Make sure the unit has `LoadCredential="+entraCredential+":"+defaultEntraSecretFile+
			"` (uncomment it in /etc/systemd/system/heimdall.service), then: sudo heimdall restart")
	}
	return nil
}

// writePrivate replaces path with data via a 0600 temp file and rename, so
// the secret is never briefly readable and a crash can't leave half a file.
func writePrivate(path, data string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// newEntraClient builds the SSO client when auth.entra is enabled.
func newEntraClient(cfg config.Config) (*entra.Client, error) {
	secret, err := entraSecret()
	if err != nil {
		return nil, err
	}
	return entra.New(entra.Config{
		Tenant:         cfg.Auth.Entra.Tenant,
		ClientID:       cfg.Auth.Entra.ClientID,
		ClientSecret:   secret,
		RedirectURL:    strings.TrimSuffix(cfg.UI.BaseURL, "/") + "/auth/callback",
		AllowedTenants: cfg.Auth.Entra.AllowedTenants,
		HTTP:           netx.New(netx.EntraHosts, "heimdall/"+version),
		Now:            time.Now,
	})
}

// entraSecret reads the client secret from the systemd credential, or from
// HEIMDALL_ENTRA_SECRET_FILE. It is never read from the config file.
func entraSecret() (string, error) {
	path, fromSystemd := os.Getenv("HEIMDALL_ENTRA_SECRET_FILE"), false
	if path == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			path, fromSystemd = filepath.Join(dir, entraCredential), true
		}
	}
	if path == "" {
		return "", errors.New("auth.entra is enabled but no client secret was provided: add " +
			"`LoadCredential=" + entraCredential + ":/etc/heimdall/entra-secret` to the unit, or set HEIMDALL_ENTRA_SECRET_FILE")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("entra client secret: %w", err)
	}
	// systemd credentials are already private; a plain file must be too.
	if !fromSystemd && fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("entra client secret %s is readable by other users; run `chmod 600 %s`", path, path)
	}
	if fi.Size() > 4096 {
		return "", fmt.Errorf("entra client secret %s is suspiciously large", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(b))
	if secret == "" {
		return "", fmt.Errorf("entra client secret %s is empty", path)
	}
	return secret, nil
}
