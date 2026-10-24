// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/netx"
	"github.com/chrisreedio/heimdall/internal/notify"
	"github.com/chrisreedio/heimdall/internal/report"
	"github.com/chrisreedio/heimdall/internal/store"
)

// credential reads a systemd credential (or HEIMDALL_<NAME>_FILE).
func credential(name string) (string, error) {
	v, _, err := credentialFile(name, "")
	return v, err
}

// credentialFile reads a systemd credential (or HEIMDALL_<NAME>_FILE),
// falling back to the file itself when given (the CLI, run as root, reads
// the file the unit's LoadCredential line points at). It returns the value
// and where it came from.
func credentialFile(name, fallback string) (string, string, error) {
	env := "HEIMDALL_" + strings.ToUpper(strings.ReplaceAll(strings.TrimPrefix(name, "heimdall-"), "-", "_")) + "_FILE"
	path, fromSystemd := os.Getenv(env), false
	if path == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil || fallback == "" {
				path, fromSystemd = p, true
			}
		}
	}
	if path == "" {
		path = fallback
	}
	if path == "" {
		return "", "", fmt.Errorf("missing secret: add `LoadCredential=%s:<file>` to the unit, or set %s", name, env)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", path, err
	}
	if !fromSystemd && fi.Mode().Perm()&0o077 != 0 {
		return "", path, fmt.Errorf("%s is readable by other users; run `chmod 600 %s`", path, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", path, err
	}
	v := strings.TrimSpace(string(b))
	if v == "" || len(v) > 4096 {
		return "", path, fmt.Errorf("%s: secret is empty or too large", path)
	}
	return v, path, nil
}

// notifySecretDir is where `notify set-webhook` stores destination URLs.
var notifySecretDir = "/etc/heimdall"

// destCredential names a destination's systemd credential and its file:
// slack:ops is credential "heimdall-notify-slack-ops", read from
// /etc/heimdall/notify-slack-ops (or HEIMDALL_NOTIFY_SLACK_OPS_FILE).
func destCredential(kind, name string) (cred, file string) {
	return "heimdall-notify-" + kind + "-" + name, filepath.Join(notifySecretDir, "notify-"+kind+"-"+name)
}

// notifyHTTPClient builds a destination's client: HTTPS to the given
// hosts only. A seam for tests.
var notifyHTTPClient = func(hosts []string) *http.Client {
	return netx.New(hosts, "heimdall/"+version).HTTPClient()
}

// notifyRetry is the destinations' retry policy (zero = the defaults:
// 4 attempts with backoff, honouring 429 Retry-After). A seam for tests.
var notifyRetry notify.Retry

// senders builds the hub's configured destinations.
func senders(cfg config.Config) ([]notify.Destination, error) { return destinations(cfg, false) }

// destinations builds every configured destination it can. A destination
// that can't be built (a missing secret, say) is left out and reported in
// the error, so it never stops the others. With fallback (the CLI as
// root), stored secrets are read straight from their files.
func destinations(cfg config.Config, fallback bool) ([]notify.Destination, error) {
	n := cfg.Notify
	var out []notify.Destination
	var errs []error
	if len(n.EmailTo) > 0 {
		e := &notify.Email{Host: n.SMTPHost, Port: n.SMTPPort, Username: n.SMTPUsername, From: n.EmailFrom, To: n.EmailTo}
		pw := ""
		var err error
		if n.SMTPUsername != "" {
			pw, err = credential("heimdall-smtp")
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("email: %w", err))
		} else {
			e.Password = pw
			out = append(out, e)
		}
	}
	if n.Webhook { // the original generic webhook, credential "heimdall-webhook"
		raw, err := credential("heimdall-webhook")
		if err == nil {
			_, err = notify.WebhookURL(raw)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("webhook: %w", err))
		} else {
			u, _ := url.Parse(raw)
			// The webhook's own host is the only one this client may reach.
			out = append(out, &notify.Webhook{URL: raw, Format: n.WebhookFormat, Retry: notifyRetry,
				Client: notifyHTTPClient([]string{strings.ToLower(u.Hostname())})})
		}
	}
	for _, spec := range n.Destinations {
		d, err := buildDestination(spec, fallback)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, d)
	}
	return out, errors.Join(errs...)
}

func buildDestination(spec string, fallback bool) (notify.Destination, error) {
	kind, name, ok := config.NotifyDestination(spec)
	if !ok {
		return nil, fmt.Errorf("%s: not a destination", spec)
	}
	cred, file := destCredential(kind, name)
	if !fallback {
		file = ""
	}
	raw, _, err := credentialFile(cred, file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (store the URL with `sudo heimdall notify set-webhook %s %s`)", spec, err, kind, name)
	}
	return newDestination(spec, kind, raw)
}

// newDestination checks a stored URL for its kind and builds the
// destination, with a client that may reach only that kind's host.
func newDestination(spec, kind, raw string) (notify.Destination, error) {
	switch kind {
	case "slack":
		u, err := notify.SlackURL(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", spec, err)
		}
		return &notify.Slack{Label: spec, URL: u, Client: notifyHTTPClient(netx.SlackHosts), Retry: notifyRetry}, nil
	case "discord":
		u, err := notify.DiscordURL(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", spec, err)
		}
		return &notify.Discord{Label: spec, URL: u, Client: notifyHTTPClient(netx.DiscordHosts), Retry: notifyRetry}, nil
	case "webhook":
		u, err := notify.WebhookURL(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", spec, err)
		}
		pu, _ := url.Parse(u)
		return &notify.Webhook{Label: spec, URL: u, Format: "json", Retry: notifyRetry,
			Client: notifyHTTPClient([]string{strings.ToLower(pu.Hostname())})}, nil
	}
	return nil, fmt.Errorf("%s: unknown destination kind %q", spec, kind)
}

// sendResults counts successes and collects failures from notify.SendAll.
// Errors name the destination, never its URL.
func sendResults(res []notify.Result) (ok int, errs []error) {
	for _, r := range res {
		if r.Err != nil {
			errs = append(errs, r.Err)
		} else {
			ok++
		}
	}
	return ok, errs
}

// buildDigest summarizes the whole install for the digest.
func buildDigest(ctx context.Context, cfg config.Config, s *store.Store, now time.Time) (notify.Digest, error) {
	r, err := report.Build(ctx, s, report.Filter{Scope: store.AllScope}, now)
	if err != nil {
		return notify.Digest{}, err
	}
	since, err := s.LastAuditAt(ctx, "notify.sent")
	if err != nil {
		return notify.Digest{}, err
	}
	anomalies, err := s.CountOpenAnomalies(ctx)
	if err != nil {
		return notify.Digest{}, err
	}
	return report.Digest(r, "", strings.TrimSuffix(cfg.UI.BaseURL, "/")+"/", since, cfg.Hosts.StaleAfter.Duration, anomalies), nil
}

// sendDigest sends to every destination at once and records it if any
// got it. A destination that fails doesn't stop the others.
func sendDigest(ctx context.Context, cfg config.Config, s *store.Store, now time.Time) error {
	dests, cerr := senders(cfg)
	if len(dests) == 0 {
		if cerr != nil {
			return cerr
		}
		return errors.New("no digest destination configured ([notify] email_to, webhook or destinations)")
	}
	d, err := buildDigest(ctx, cfg, s, now)
	if err != nil {
		return err
	}
	ok, errs := sendResults(notify.SendAll(ctx, dests, func(ctx context.Context, x notify.Destination) error {
		return x.Send(ctx, d)
	}))
	if ok > 0 {
		errs = append(errs, s.Audit(ctx, store.AuditEntry{Actor: "heimdall", Action: "notify.sent",
			Detail: map[string]any{"channels": ok, "failed": len(dests) - ok, "kev": d.KEV, "critical": d.Critical}}))
	}
	return errors.Join(append([]error{cerr}, errs...)...)
}

// sampleAlert is what `notify preview --alert` shows (example hosts).
func sampleAlert(kind, baseURL string) (notify.Alert, error) {
	a := notify.Alert{Kind: kind, GeneratedAt: time.Now().UTC(), URL: strings.TrimSuffix(baseURL, "/") + "/anomalies",
		Hosts: []string{"example/web-01", "example/db-01"}, Count: 2}
	switch kind {
	case notify.KindSilent:
		a.AlertAfter = "3h0m0s"
	case notify.KindBack:
	case notify.KindAnomaly:
		a.Anomalies = []notify.AlertAnomaly{{Host: "example/web-01", Rule: "privilege_watch_disabled", Severity: "high"},
			{Host: "example/db-01", Rule: "privileged_access", Severity: "medium"}}
	case notify.KindTest:
		a.Hosts, a.Count, a.URL = nil, 0, strings.TrimSuffix(baseURL, "/")+"/"
	default:
		return a, fmt.Errorf("--alert must be %s, %s, %s or %s", notify.KindSilent, notify.KindBack, notify.KindAnomaly, notify.KindTest)
	}
	return a, nil
}

func cmdNotifyPreview(a *app, args []string) error {
	fs := a.flags("notify preview", "[--alert silent|back|anomaly|test]")
	alertKind := fs.String("alert", "", "preview an alert with example hosts instead of the digest")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	var d notify.Digest
	var al notify.Alert
	if *alertKind != "" {
		if al, err = sampleAlert(*alertKind, cfg.UI.BaseURL); err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "Subject: %s\n\n%s", al.Subject(), al.Text())
	} else {
		s, err := a.openStore()
		if err != nil {
			return err
		}
		defer s.Close()
		if d, err = buildDigest(a.ctx, cfg, s, time.Now()); err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "Subject: %s\n\n%s", d.Subject(), d.Text())
	}
	// Each destination's payload. A URL that can't be read (not root, or
	// not stored yet) doesn't matter here: the payload doesn't contain it.
	dests, derr := destinations(cfg, isRoot())
	names := map[string]bool{}
	for _, x := range dests {
		names[x.Name()] = true
	}
	for _, spec := range cfg.Notify.Destinations {
		if names[spec] {
			continue
		}
		kind, _, _ := config.NotifyDestination(spec)
		placeholder := map[string]string{"slack": "https://hooks.slack.com/services/T0/B0/x",
			"discord": "https://discord.com/api/webhooks/1000000000/" + strings.Repeat("x", 20), "webhook": "https://example.invalid/x"}[kind]
		if x, err := newDestination(spec, kind, placeholder); err == nil {
			dests = append(dests, x)
		}
	}
	for _, x := range dests {
		p, ok := x.(notify.Previewer)
		if !ok {
			continue
		}
		target := p.Target()
		if !names[x.Name()] {
			target = "URL not readable here (run as root, or store it with `sudo heimdall notify set-webhook`)"
		}
		fmt.Fprintf(a.stdout, "\n── %s → %s\n", x.Name(), target)
		var payload any
		if *alertKind != "" {
			payload = p.PreviewAlert(al)
		} else {
			payload = p.PreviewDigest(d)
		}
		if _, ok := payload.(string); ok {
			fmt.Fprintln(a.stdout, "(the message above)")
			continue
		}
		enc := json.NewEncoder(a.stdout) // readable: no < for Slack's <link|text>
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			return err
		}
	}
	if len(dests) == 0 {
		fmt.Fprintln(a.stdout, "\nNo destinations configured ([notify] email_to, webhook or destinations).")
	}
	if derr != nil && isRoot() {
		fmt.Fprintf(a.stderr, "\nWarning: %v\n", derr)
	}
	return nil
}

func cmdNotifySend(a *app, args []string) error {
	if _, err := parse(a.flags("notify send", ""), args, 0); err != nil {
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
	if err := sendDigest(a.ctx, cfg, s, time.Now()); err != nil {
		return err
	}
	fmt.Fprintln(a.stderr, "Digest sent.")
	return nil
}

// cmdNotifyTest sends a clearly labelled test message to every destination,
// or to one ("slack:ops", "email", or a kind like "discord").
func cmdNotifyTest(a *app, args []string) error {
	rest, err := parseAtLeast(a.flags("notify test", "[destination]"), args, 0)
	if err != nil {
		return err
	}
	if len(rest) > 1 {
		return errors.New("usage: heimdall notify test [destination]")
	}
	cfg, err := config.Load(hubConfigPath(a.configPath))
	if err != nil {
		return err
	}
	dests, derr := destinations(cfg, isRoot())
	if len(rest) == 1 {
		want := rest[0]
		dests = slices.DeleteFunc(dests, func(x notify.Destination) bool {
			n := x.Name()
			return n != want && !strings.HasPrefix(n, want+":")
		})
		if len(dests) == 0 {
			if derr != nil {
				return derr
			}
			return fmt.Errorf("no configured destination matches %q", want)
		}
	} else if derr != nil {
		fmt.Fprintf(a.stderr, "Skipped: %v\n", derr)
	}
	if len(dests) == 0 {
		return errors.New("no destinations configured ([notify] email_to, webhook or destinations)")
	}
	al, _ := sampleAlert(notify.KindTest, cfg.UI.BaseURL)
	res := notify.SendAll(a.ctx, dests, func(ctx context.Context, x notify.Destination) error { return x.SendAlert(ctx, al) })
	failed := 0
	for _, r := range res {
		if r.Err != nil {
			failed++
			fmt.Fprintf(a.stdout, "FAIL  %s: %v\n", r.Name, r.Err)
		} else {
			fmt.Fprintf(a.stdout, "OK    %s\n", r.Name)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d destinations failed", failed, len(res))
	}
	return nil
}

// cmdNotifySetWebhook stores a Slack, Discord or generic webhook URL
// exactly like `ai set-key` stores the API key: read with echo off (or
// from stdin), checked, written owner-only and atomically, and loaded by
// the hub as a systemd credential. The URL is a credential and never goes
// in heimdall.toml; the config only lists the destination as on.
func cmdNotifySetWebhook(a *app, args []string) error {
	fs := a.flags("notify set-webhook", "<slack|discord|webhook> <name> [--stdin] [--file path] [--unit path]")
	path := fs.String("file", "", "where to store the URL (default /etc/heimdall/notify-<kind>-<name>)")
	fromStdin := fs.Bool("stdin", false, "read the URL from stdin instead of a terminal prompt")
	unitFile := fs.String("unit", hubUnitFile, "the hub's systemd unit (gets the LoadCredential line)")
	rest, err := parse(fs, args, 2)
	if err != nil {
		return err
	}
	kind, name := rest[0], rest[1]
	spec := kind + ":" + name
	if _, _, ok := config.NotifyDestination(spec); !ok {
		return errors.New("usage: heimdall notify set-webhook <slack|discord|webhook> <name> (name: lowercase letters, digits and -, e.g. ops)")
	}
	cred, defaultFile := destCredential(kind, name)
	if *path == "" {
		*path = defaultFile
	}
	var raw string
	if *fromStdin {
		b, err := io.ReadAll(io.LimitReader(stdin, 4097))
		if err != nil {
			return err
		}
		raw = strings.TrimSpace(string(b))
	} else {
		in, err := newInput(a, false)
		if err != nil {
			return errors.New("stdin is not a terminal; use --stdin to pipe the URL")
		}
		prompt := map[string]string{"slack": "Slack incoming webhook URL", "discord": "Discord webhook URL", "webhook": "Webhook URL"}[kind]
		if raw, err = in.line(prompt+" (input hidden): ", true); err != nil {
			return err
		}
		raw = strings.TrimSpace(raw)
	}
	if raw == "" {
		return errors.New("empty URL")
	}
	if len(raw) > 4096 || strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errors.New("that doesn't look like a webhook URL")
	}
	var canon string
	switch kind {
	case "slack":
		canon, err = notify.SlackURL(raw)
	case "discord":
		canon, err = notify.DiscordURL(raw)
	default:
		canon, err = notify.WebhookURL(raw)
	}
	if err != nil {
		return err // the messages never echo the URL
	}
	if err := writePrivate(*path, canon+"\n"); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Stored the %s URL in %s (owner-only): %s\n", spec, *path, notify.RedactURL(canon))
	if *path == defaultFile || *unitFile != hubUnitFile {
		changed, err := enableCredential(*unitFile, cred, *path)
		switch {
		case err != nil:
			fmt.Fprintf(a.stderr, "Couldn't update the unit (%v).\nAdd `LoadCredential=%s:%s` to it yourself.\n", err, cred, *path)
		case changed:
			fmt.Fprintf(a.stderr, "Added LoadCredential=%s to %s.\n", cred, *unitFile)
			if *unitFile == hubUnitFile {
				if err := systemctl(a, "daemon-reload"); err != nil {
					fmt.Fprintf(a.stderr, "systemctl daemon-reload failed: %v\n", err)
				}
			}
		}
	}
	// Turn the destination on in [notify] destinations.
	cfgPath := hubConfigPath(a.configPath)
	cfg, err := config.Load(cfgPath)
	switch {
	case err != nil:
		fmt.Fprintf(a.stderr, "Couldn't read %s (%v).\nAdd %q to destinations under [notify] yourself.\n", cfgPath, err, spec)
	case slices.Contains(cfg.Notify.Destinations, spec):
	default:
		list := append(slices.Clone(cfg.Notify.Destinations), spec)
		quoted := make([]string, len(list))
		for i, d := range list {
			quoted[i] = strconv.Quote(d)
		}
		err := updateConfigKeys(cfgPath, "notify", [][2]string{{"destinations", "[" + strings.Join(quoted, ", ") + "]"}},
			func(c config.Config) bool { return slices.Contains(c.Notify.Destinations, spec) })
		if err != nil {
			fmt.Fprintf(a.stderr, "Couldn't update %s (%v).\nAdd %q to destinations under [notify] yourself.\n", cfgPath, err, spec)
		} else {
			fmt.Fprintf(a.stderr, "Turned on %s in %s ([notify] destinations).\n", spec, cfgPath)
		}
	}
	fmt.Fprintf(a.stderr, "Check it with `sudo heimdall notify test %s`, then apply with: sudo heimdall restart\n", spec)
	return nil
}
