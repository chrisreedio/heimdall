// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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
	env := "HEIMDALL_" + strings.ToUpper(strings.ReplaceAll(strings.TrimPrefix(name, "heimdall-"), "-", "_")) + "_FILE"
	path, fromSystemd := os.Getenv(env), false
	if path == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			path, fromSystemd = filepath.Join(dir, name), true
		}
	}
	if path == "" {
		return "", fmt.Errorf("missing secret: add `LoadCredential=%s:<file>` to the unit, or set %s", name, env)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !fromSystemd && fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s is readable by other users; run `chmod 600 %s`", path, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" || len(v) > 4096 {
		return "", fmt.Errorf("%s: secret is empty or too large", path)
	}
	return v, nil
}

// senders builds the configured digest channels.
func senders(cfg config.Config) ([]notify.Sender, error) {
	n := cfg.Notify
	var out []notify.Sender
	if len(n.EmailTo) > 0 {
		e := &notify.Email{Host: n.SMTPHost, Port: n.SMTPPort, Username: n.SMTPUsername, From: n.EmailFrom, To: n.EmailTo}
		if n.SMTPUsername != "" {
			pw, err := credential("heimdall-smtp")
			if err != nil {
				return nil, err
			}
			e.Password = pw
		}
		out = append(out, e)
	}
	if n.Webhook {
		raw, err := credential("heimdall-webhook")
		if err != nil {
			return nil, err
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			return nil, errors.New("heimdall-webhook must be an https URL")
		}
		// The webhook's own host is the only one this client may reach.
		hc := netx.New([]string{strings.ToLower(u.Hostname())}, "heimdall/"+version).HTTPClient()
		out = append(out, &notify.Webhook{URL: raw, Format: n.WebhookFormat, Client: hc})
	}
	return out, nil
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

// sendDigest sends to every channel and records it.
func sendDigest(ctx context.Context, cfg config.Config, s *store.Store, now time.Time) error {
	chans, err := senders(cfg)
	if err != nil {
		return err
	}
	if len(chans) == 0 {
		return errors.New("no digest channel configured ([notify] email_to or webhook)")
	}
	d, err := buildDigest(ctx, cfg, s, now)
	if err != nil {
		return err
	}
	var errs []error
	for _, c := range chans {
		if err := c.Send(ctx, d); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return s.Audit(ctx, store.AuditEntry{Actor: "heimdall", Action: "notify.sent",
		Detail: map[string]any{"channels": len(chans), "kev": d.KEV, "critical": d.Critical}})
}

func cmdNotifyPreview(a *app, args []string) error {
	if _, err := parse(a.flags("notify preview", ""), args, 0); err != nil {
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
	d, err := buildDigest(a.ctx, cfg, s, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Subject: %s\n\n%s", d.Subject(), d.Text())
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
