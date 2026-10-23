// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
)

// Seams for tests.
var (
	caddyDir    = "/etc/caddy"
	reloadCaddy = func(a *app) error {
		cmd := exec.CommandContext(a.ctx, "systemctl", "reload-or-restart", "caddy")
		cmd.Stdout, cmd.Stderr = a.stderr, a.stderr
		return cmd.Run()
	}
)

// cmdIngestCert installs a certificate for the public ingest endpoint,
// e.g. a Cloudflare Origin certificate when ingest sits behind Cloudflare's
// proxy (where Caddy can't get one from Let's Encrypt itself). The pair is
// checked before anything is written; the key is pasted with echo off.
func cmdIngestCert(a *app, args []string) error {
	fs := a.flags("ingest cert", "[--cert-file path] [--key-file path] [--host name]")
	certFile := fs.String("cert-file", "", "PEM certificate (default: paste it)")
	keyFile := fs.String("key-file", "", "PEM private key (default: paste it, hidden)")
	host := fs.String("host", "", "ingest host name (default: from ingest.public_url)")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	if !isRoot() {
		return errors.New("this writes Caddy's certificate and reloads it: run it with sudo")
	}
	if *host == "" {
		cfg, err := config.Load(hubConfigPath(a.configPath))
		if err != nil {
			return err
		}
		u, err := url.Parse(cfg.Ingest.PublicURL)
		if err != nil || u.Hostname() == "" {
			return errors.New("ingest.public_url isn't set; pass --host")
		}
		*host = u.Hostname()
	}

	var in *input
	if *certFile == "" || *keyFile == "" {
		var err error
		if in, err = newInput(a, false); err != nil {
			return errors.New("stdin is not a terminal; pass --cert-file and --key-file")
		}
	}
	certPEM, err := pemInput(a, in, *certFile, false, "Paste the certificate (ends with -----END CERTIFICATE-----):",
		func(l string) bool { return strings.TrimSpace(l) == "-----END CERTIFICATE-----" })
	if err != nil {
		return err
	}
	keyPEM, err := pemInput(a, in, *keyFile, true, "Paste the private key (input hidden; ends with -----END PRIVATE KEY-----):",
		func(l string) bool {
			l = strings.TrimSpace(l)
			return strings.HasPrefix(l, "-----END ") && strings.HasSuffix(l, "PRIVATE KEY-----")
		})
	if err != nil {
		return err
	}

	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("the certificate and key don't form a valid pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if err := leaf.VerifyHostname(*host); err != nil {
		return fmt.Errorf("the certificate doesn't cover %s (it covers %s)", *host, strings.Join(leaf.DNSNames, ", "))
	}
	if time.Now().After(leaf.NotAfter) {
		return fmt.Errorf("the certificate expired on %s", leaf.NotAfter.Format(time.DateOnly))
	}

	certPath := filepath.Join(caddyDir, "heimdall-origin.pem")
	keyPath := filepath.Join(caddyDir, "heimdall-origin.key")
	if err := writePrivate(certPath, certPEM); err != nil {
		return err
	}
	if err := os.Chmod(certPath, 0o644); err != nil {
		return err
	}
	if err := writePrivate(keyPath, keyPEM); err != nil {
		return err
	}
	// Caddy runs as its own user: the key is root-owned, readable by that group.
	if g, err := user.LookupGroup("caddy"); err == nil {
		gid, _ := strconv.Atoi(g.Gid)
		if err := os.Chown(keyPath, 0, gid); err != nil {
			return err
		}
		if err := os.Chmod(keyPath, 0o640); err != nil {
			return err
		}
	}
	if err := setCaddyTLS(filepath.Join(caddyDir, "Caddyfile"), *host, certPath, keyPath); err != nil {
		return err
	}
	if err := reloadCaddy(a); err != nil {
		return fmt.Errorf("reloading Caddy: %w (see journalctl -u caddy)", err)
	}
	fmt.Fprintf(a.stderr, "Installed the certificate for %s (expires %s) and reloaded Caddy.\n", *host, leaf.NotAfter.Format(time.DateOnly))
	if strings.Contains(leaf.Issuer.String(), "CloudFlare") {
		fmt.Fprintln(a.stderr, "This is a Cloudflare Origin certificate: keep the DNS record proxied and set SSL/TLS to \"Full (strict)\".")
	}
	return nil
}

// pemInput reads a PEM block from a file, or from the terminal.
func pemInput(a *app, in *input, path string, hidden bool, prompt string, done func(string) bool) (string, error) {
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	fmt.Fprintln(a.stderr, prompt)
	if hidden && in.terminal {
		s, err := readHiddenBlock(stdin.(*os.File), in.r, done)
		fmt.Fprintln(a.stderr)
		return s, err
	}
	return readBlock(in.r, done)
}

// readBlock reads lines until done reports true for one (at most 64 KiB).
func readBlock(r *bufio.Reader, done func(string) bool) (string, error) {
	var b strings.Builder
	for b.Len() < 64<<10 {
		l, err := r.ReadString('\n')
		b.WriteString(l)
		if done(l) {
			return b.String(), nil
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return "", errors.New("input ended before the PEM END line")
}

// setCaddyTLS points the host's site block in the Caddyfile at the
// certificate, replacing any existing tls line.
func setCaddyTLS(caddyfile, host, certPath, keyPath string) error {
	b, err := os.ReadFile(caddyfile)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	var out []string
	in, found := false, false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case !in && t == host+" {":
			in, found = true, true
			out = append(out, l, "\ttls "+certPath+" "+keyPath)
			continue
		case in && l == "}":
			in = false
		case in && strings.HasPrefix(t, "tls "):
			continue
		}
		out = append(out, l)
	}
	if !found {
		return fmt.Errorf("no site block for %s in %s; run install-hub.sh with --ingest-host %s first", host, caddyfile, host)
	}
	return os.WriteFile(caddyfile, []byte(strings.Join(out, "\n")), 0o644)
}
