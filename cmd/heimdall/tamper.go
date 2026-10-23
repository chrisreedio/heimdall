// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/anomaly"
	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/ingest"
	"github.com/chrisreedio/heimdall/internal/notify"
	"github.com/chrisreedio/heimdall/internal/store"
)

// startTamperChecks makes a switched-off collector loud. It runs, in one
// goroutine:
//
//   - the fast silence check (hosts.alert_after) on a short ticker, which
//     notifies right away through the [notify] channels, once per silence,
//     with a "back" notice when the host reports again;
//   - the reboot and kernel rules for unchanged reports, which are stored
//     as heartbeats and don't go through the findings queue.
func startTamperChecks(ctx context.Context, cfg config.Config, s *store.Store, h *ingest.Handler,
	tripwires *anomaly.Engine, log *slog.Logger) {
	seen := make(chan store.IngestHost, 256)
	h.OnSeen = func(host store.IngestHost) {
		select {
		case seen <- host:
		default: // queue full; the host's next report runs the rules
		}
	}
	alertAfter := cfg.Hosts.AlertAfter.Duration
	go func() {
		var tick <-chan time.Time
		if alertAfter > 0 {
			t := time.NewTicker(silenceTick(alertAfter))
			defer t.Stop()
			tick = t.C
		}
		for {
			select {
			case <-ctx.Done():
				return
			case host := <-seen:
				raised, err := tripwires.OnSnapshot(ctx, host)
				if err != nil {
					log.Warn("anomaly rules failed", "host", host.Name, "err", err)
				}
				for _, an := range raised {
					log.Warn("anomaly", "host", host.Name, "rule", an.Rule, "severity", an.Severity, "summary", an.Summary)
				}
			case <-tick:
				if err := checkSilence(ctx, cfg, tripwires, s, log); err != nil {
					log.Warn("silence alert failed", "err", err)
				}
			}
		}
	}()
}

// silenceTick is how often the fast silence check runs: every 5 minutes,
// or more often for a short alert_after (as in tests).
func silenceTick(alertAfter time.Duration) time.Duration {
	return min(max(alertAfter/4, 15*time.Second), 5*time.Minute)
}

// checkSilence raises silence anomalies for quiet hosts and sends the
// immediate notices. A notice that fails is retried on the next tick.
func checkSilence(ctx context.Context, cfg config.Config, tripwires *anomaly.Engine, s *store.Store, log *slog.Logger) error {
	found, err := tripwires.CheckFastSilence(ctx, cfg.Hosts.AlertAfter.Duration)
	if err != nil || len(found.Silent)+len(found.Back) == 0 {
		return err
	}
	for _, h := range found.Silent {
		log.Warn("host went silent", "org", h.OrgSlug, "host", h.Name, "last_seen", h.LastSeenAt)
	}
	for _, h := range found.Back {
		log.Info("host reporting again", "org", h.OrgSlug, "host", h.Name)
	}

	all, err := senders(cfg)
	if err != nil {
		return err // misconfigured channel: retry next tick, loudly
	}
	var chans []notify.AlertSender
	for _, c := range all {
		if a, ok := c.(notify.AlertSender); ok {
			chans = append(chans, a)
		}
	}
	var errs []error
	send := func(kind string, hosts []store.SilentHost) bool {
		if len(hosts) == 0 || len(chans) == 0 {
			return true // nothing to send, or no channel: the anomaly is the record
		}
		a := notify.Alert{Kind: kind, GeneratedAt: time.Now().UTC(), Count: len(hosts),
			URL: strings.TrimSuffix(cfg.UI.BaseURL, "/") + "/anomalies"}
		if kind == "silent" {
			a.AlertAfter = cfg.Hosts.AlertAfter.Duration.String()
		}
		for _, h := range hosts {
			a.Hosts = append(a.Hosts, h.OrgSlug+"/"+h.Name)
		}
		ok := true
		for _, c := range chans {
			if err := c.SendAlert(ctx, a); err != nil {
				errs, ok = append(errs, err), false
			}
		}
		if ok {
			errs = append(errs, s.Audit(ctx, store.AuditEntry{Actor: "heimdall", Action: "notify.alert",
				Detail: map[string]any{"kind": kind, "hosts": len(hosts), "channels": len(chans)}}))
		}
		return ok
	}
	if !send("silent", found.Silent) {
		found.Silent = nil // not marked, so the next tick tries again
	}
	if !send("back", found.Back) {
		found.Back = nil
	}
	errs = append(errs, tripwires.MarkSilenceAlerts(ctx, found))
	return errors.Join(errs...)
}
