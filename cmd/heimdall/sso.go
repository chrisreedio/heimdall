// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/auth/entra"
	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/netx"
)

// entraCredential is the systemd credential name holding the client secret.
const entraCredential = "heimdall-entra"

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
