// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/chrisreedio/heimdall/internal/config"
)

const (
	hubConfigFile = "/etc/heimdall/heimdall.toml"
	hubUnitFile   = "/etc/systemd/system/heimdall.service"
)

var guidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Seams for tests.
var (
	systemctl = func(a *app, args ...string) error {
		cmd := exec.CommandContext(a.ctx, "systemctl", args...)
		cmd.Stdout, cmd.Stderr = a.stderr, a.stderr
		return cmd.Run()
	}
	// runAsOwner runs this binary as the given user (the database owner).
	runAsOwner = func(a *app, uid int, args []string) error {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(a.ctx, self, args...)
		if uid != os.Geteuid() {
			u, err := user.LookupId(strconv.Itoa(uid))
			if err != nil {
				return err
			}
			cmd = exec.CommandContext(a.ctx, "runuser", append([]string{"-u", u.Username, "--", self}, args...)...)
		}
		cmd.Dir = "/"
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, a.stderr, a.stderr
		return cmd.Run()
	}
)

// hubConfigPath uses the installed hub's config when -c wasn't given and
// there's no heimdall.toml here (the usual case under sudo).
func hubConfigPath(p string) string {
	if p == "heimdall.toml" {
		if _, err := os.Stat(p); err != nil {
			if _, err := os.Stat(hubConfigFile); err == nil {
				return hubConfigFile
			}
		}
	}
	return p
}

// cmdSSOSetup asks for the Entra app's details and wires them up: the
// [auth.entra] config, the client secret (owner-only, never echoed), the
// unit's LoadCredential line, optionally a first SSO admin, and a restart.
func cmdSSOSetup(a *app, args []string) error {
	fs := a.flags("sso setup", "[--tenant ID] [--client-id ID] [--secret-stdin] [--admin email] [--restart | --no-restart]")
	tenant := fs.String("tenant", "", "Directory (tenant) ID")
	clientID := fs.String("client-id", "", "Application (client) ID")
	secretStdin := fs.Bool("secret-stdin", false, "read the client secret from stdin (then every other value must be a flag)")
	admin := fs.String("admin", "", "provision this Entra user as an admin")
	restart := fs.Bool("restart", false, "restart the hub without asking")
	noRestart := fs.Bool("no-restart", false, "don't restart the hub")
	secretFile := fs.String("secret-file", defaultEntraSecretFile, "where to store the client secret")
	unitFile := fs.String("unit", hubUnitFile, "the hub's systemd unit")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	if !isRoot() {
		return errors.New("this writes the client secret and the systemd unit: run it with sudo")
	}
	cfgPath := hubConfigPath(a.configPath)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	redirect := strings.TrimSuffix(cfg.UI.BaseURL, "/") + "/auth/callback"
	fmt.Fprintf(a.stderr, `Entra ID single sign-on for this hub (%s).

In the Azure portal: Entra ID -> App registrations -> New registration
  - Supported account types: accounts in this organizational directory only
  - Redirect URI: platform "Web", %s
Then copy the Directory (tenant) ID and Application (client) ID from the
app's Overview, and create a secret under Certificates & secrets.

`, cfgPath, redirect)
	if !strings.HasPrefix(redirect, "https://") && !strings.Contains(redirect, "://127.0.0.1") && !strings.Contains(redirect, "://localhost") {
		fmt.Fprintln(a.stderr, "Warning: Entra only accepts https redirect URIs (or localhost); set ui.base_url to the https address you browse to.")
	}

	var in *input
	if *secretStdin {
		if *tenant == "" || *clientID == "" {
			return errors.New("with --secret-stdin, --tenant and --client-id are required")
		}
	} else if in, err = newInput(a, false); err != nil {
		return errors.New("stdin is not a terminal; pass --tenant, --client-id and --secret-stdin")
	}
	ask := func(v *string, prompt, def string) error {
		if *v != "" || in == nil {
			return nil
		}
		if def != "" {
			prompt += " [" + def + "]"
		}
		s, err := in.line(prompt+": ", false)
		if s = strings.TrimSpace(s); s == "" {
			s = def
		}
		*v = s
		return err
	}
	if err := ask(tenant, "Directory (tenant) ID", cfg.Auth.Entra.Tenant); err != nil {
		return err
	}
	if !guidRe.MatchString(*tenant) {
		return fmt.Errorf("tenant ID %q isn't a GUID (copy \"Directory (tenant) ID\" from the app's Overview)", *tenant)
	}
	if err := ask(clientID, "Application (client) ID", cfg.Auth.Entra.ClientID); err != nil {
		return err
	}
	if !guidRe.MatchString(*clientID) {
		return fmt.Errorf("client ID %q isn't a GUID (copy \"Application (client) ID\" from the app's Overview)", *clientID)
	}
	var secret string
	if *secretStdin {
		b, err := io.ReadAll(io.LimitReader(stdin, 4097))
		if err != nil {
			return err
		}
		secret = strings.TrimSpace(string(b))
	} else if secret, err = in.line("Client secret Value (input hidden): ", true); err != nil {
		return err
	}
	secret = strings.TrimSpace(secret)
	if secret == "" || len(secret) > 4096 || strings.ContainsAny(secret, "\r\n") {
		return errors.New("that doesn't look like a client secret (paste the secret's Value, not its ID)")
	}
	if guidRe.MatchString(secret) {
		return errors.New("that looks like the secret's ID; paste its Value")
	}
	if in != nil && *admin == "" {
		if err := ask(admin, "Entra user to make an admin (email, blank to skip)", ""); err != nil {
			return err
		}
	}

	if err := writePrivate(*secretFile, secret+"\n"); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Stored the client secret in %s (owner-only).\n", *secretFile)
	if err := updateEntraConfig(cfgPath, *tenant, *clientID); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Enabled [auth.entra] in %s.\n", cfgPath)
	changed, err := enableCredential(*unitFile, entraCredential, *secretFile)
	if err != nil {
		return err
	}
	if changed {
		fmt.Fprintf(a.stderr, "Added LoadCredential=%s to %s.\n", entraCredential, *unitFile)
	}

	if *admin != "" {
		uid := os.Geteuid()
		if fi, err := os.Stat(cfgPath); err == nil {
			if u, _, ok := fileOwner(fi); ok {
				uid = u
			}
		}
		if err := runAsOwner(a, uid, []string{"-c", cfgPath, "user", "create", "--entra", "--tenant", *tenant, "--admin", *admin}); err != nil {
			fmt.Fprintf(a.stderr, "Couldn't provision %s (%v); do it later with `heimdall user create --entra --tenant %s --admin %s`.\n", *admin, err, *tenant, *admin)
		}
	}

	do := *restart
	if !do && !*noRestart && in != nil {
		ans, err := in.line("Restart the hub now to apply? [Y/n]: ", false)
		if err != nil {
			return err
		}
		do = !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ans)), "n")
	}
	if !do {
		fmt.Fprintln(a.stderr, "Apply with: sudo heimdall restart")
		return nil
	}
	if err := systemctl(a, "daemon-reload"); err != nil {
		return err
	}
	if err := systemctl(a, "restart", "heimdall"); err != nil {
		return fmt.Errorf("restart failed (%w); see journalctl -u heimdall", err)
	}
	if err := systemctl(a, "is-active", "--quiet", "heimdall"); err != nil {
		return errors.New("the hub didn't come back up; see journalctl -u heimdall")
	}
	fmt.Fprintf(a.stderr, "Done. Sign in at %s with \"Sign in with Microsoft\".\n", strings.TrimSuffix(cfg.UI.BaseURL, "/"))
	fmt.Fprintln(a.stderr, "Once it works you can set [auth] local_login = false (break-glass stays available from the CLI).")
	return nil
}

// updateEntraConfig turns on [auth.entra] for one tenant, keeping the rest
// of the file (comments included), its owner and its mode.
func updateEntraConfig(path, tenant, clientID string) error {
	return updateConfigKeys(path, "auth.entra", [][2]string{
		{"enabled", "true"},
		{"tenant", strconv.Quote(tenant)},
		{"client_id", strconv.Quote(clientID)},
		{"allowed_tenants", "[" + strconv.Quote(tenant) + "]"},
	}, func(cfg config.Config) bool {
		return cfg.Auth.Entra.Enabled && cfg.Auth.Entra.Tenant == tenant && cfg.Auth.Entra.ClientID == clientID
	})
}

// updateConfigKeys sets keys in one section of the config, keeping the
// rest of the file (comments included), its owner and its mode. The new
// file must load and pass check, or the old one is left unchanged.
func updateConfigKeys(path, section string, kv [][2]string, check func(config.Config) bool) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	out := setTOMLKeys(src, section, kv)
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-heimdall-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(out); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	cfg, err := config.Load(tmp)
	if err != nil {
		return fmt.Errorf("the updated config doesn't load (left unchanged): %w", err)
	}
	if !check(cfg) {
		return fmt.Errorf("couldn't update [%s] in the config (left unchanged); edit it by hand", section)
	}
	if err := os.Chmod(tmp, fi.Mode().Perm()); err != nil {
		return err
	}
	if uid, gid, ok := fileOwner(fi); ok && os.Geteuid() == 0 {
		if err := os.Chown(tmp, uid, gid); err != nil {
			return err
		}
	}
	return os.Rename(tmp, path)
}

// setTOMLKeys sets keys in one [section] of a TOML file, replacing
// existing assignments (including multi-line arrays) and appending missing
// ones at the end of the section, or a new section at the end of the file.
func setTOMLKeys(src []byte, section string, kv [][2]string) []byte {
	lines := strings.Split(strings.TrimRight(string(src), "\n"), "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "["+section+"]" {
			start = i
			break
		}
	}
	if start < 0 {
		lines = append(lines, "", "["+section+"]")
		for _, p := range kv {
			lines = append(lines, p[0]+" = "+p[1])
		}
		return []byte(strings.Join(lines, "\n") + "\n")
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "[") && !strings.Contains(lines[i], "=") {
			end = i
			break
		}
	}
	var out []string
	out = append(out, lines[:start+1]...)
	done := map[string]bool{}
	for i := start + 1; i < end; i++ {
		l := lines[i]
		key, val, isAssign := strings.Cut(strings.TrimSpace(l), "=")
		key = strings.TrimSpace(key)
		replaced := false
		if isAssign && !strings.HasPrefix(key, "#") {
			for _, p := range kv {
				if key != p[0] {
					continue
				}
				out = append(out, p[0]+" = "+p[1])
				done[p[0]] = true
				replaced = true
				// Skip the rest of a multi-line array.
				if v := strings.TrimSpace(val); strings.HasPrefix(v, "[") && !strings.Contains(v, "]") {
					for i+1 < end && !strings.Contains(lines[i], "]") {
						i++
					}
				}
			}
		}
		if !replaced {
			out = append(out, l)
		}
	}
	// Missing keys go after the section's last non-blank line.
	at := len(out)
	for at > start+1 && strings.TrimSpace(out[at-1]) == "" {
		at--
	}
	var add []string
	for _, p := range kv {
		if !done[p[0]] {
			add = append(add, p[0]+" = "+p[1])
		}
	}
	out = append(out[:at], append(add, out[at:]...)...)
	out = append(out, lines[end:]...)
	return []byte(strings.Join(out, "\n") + "\n")
}

// enableCredential makes sure the unit loads a credential, reporting
// whether it changed the file.
func enableCredential(unit, credential, secretFile string) (bool, error) {
	b, err := os.ReadFile(unit)
	if errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("%s not found; add `LoadCredential=%s:%s` to the hub's unit yourself", unit, credential, secretFile)
	}
	if err != nil {
		return false, err
	}
	want := "LoadCredential=" + credential + ":" + secretFile
	lines := strings.Split(string(b), "\n")
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "LoadCredential="+credential+":") {
			return false, nil
		}
	}
	changed := false
	for i, l := range lines {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "#") && strings.HasPrefix(strings.TrimSpace(strings.TrimLeft(t, "#")), "LoadCredential="+credential+":") {
			lines[i], changed = want, true
			break
		}
	}
	if !changed {
		for i, l := range lines {
			if strings.TrimSpace(l) == "[Service]" {
				lines = append(lines[:i+1], append([]string{want}, lines[i+1:]...)...)
				changed = true
				break
			}
		}
	}
	if !changed {
		return false, fmt.Errorf("no [Service] section in %s; add `%s` yourself", unit, want)
	}
	return true, os.WriteFile(unit, []byte(strings.Join(lines, "\n")), 0o644)
}
