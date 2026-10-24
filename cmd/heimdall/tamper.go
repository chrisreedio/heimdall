// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/anomaly"
	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/ingest"
	"github.com/chrisreedio/heimdall/internal/notify"
	"github.com/chrisreedio/heimdall/internal/store"
)

// startTamperChecks makes a switched-off collector loud. It runs:
//
//   - the reboot and kernel rules for unchanged reports, which are stored
//     as heartbeats and don't go through the findings queue;
//   - in a second goroutine, so a slow destination (retrying a 429, say)
//     never holds up the rules, the immediate notices: the fast silence
//     check (hosts.alert_after), once per silence with a "back" notice when
//     the host reports again, and new high-signal anomalies
//     ([notify] alert_anomalies).
//
// Ingest only ever hands hosts over on a buffered channel, without
// waiting, so neither goroutine can block it.
func startTamperChecks(ctx context.Context, cfg config.Config, s *store.Store, h *ingest.Handler,
	tripwires *anomaly.Engine, log *slog.Logger) {
	seen := make(chan store.IngestHost, 256)
	h.OnSeen = func(host store.IngestHost) {
		select {
		case seen <- host:
		default: // queue full; the host's next report runs the rules
		}
	}
	go func() {
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
			}
		}
	}()

	alertAfter := cfg.Hosts.AlertAfter.Duration
	var watch *anomalyAlerts
	if cfg.Notify.AlertAnomalies {
		watch = &anomalyAlerts{cfg: cfg, s: s, log: log}
		if err := watch.start(ctx); err != nil {
			log.Warn("anomaly alerts off: couldn't read anomalies", "err", err)
			watch = nil
		}
	}
	if alertAfter <= 0 && watch == nil {
		return
	}
	go func() {
		var silence, anomalies <-chan time.Time
		if alertAfter > 0 {
			t := time.NewTicker(silenceTick(alertAfter))
			defer t.Stop()
			silence = t.C
		}
		if watch != nil {
			t := time.NewTicker(anomalyTick)
			defer t.Stop()
			anomalies = t.C
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-silence:
				if err := checkSilence(ctx, cfg, tripwires, s, log); err != nil {
					log.Warn("silence alert failed", "err", err)
				}
			case <-anomalies:
				if err := watch.check(ctx); err != nil {
					log.Warn("anomaly alert failed", "err", err)
				}
			}
		}
	}()
}

// anomalyTick is how often new anomalies are looked for.
var anomalyTick = 30 * time.Second

// silenceTick is how often the fast silence check runs: every 5 minutes,
// or more often for a short alert_after (as in tests).
func silenceTick(alertAfter time.Duration) time.Duration {
	return min(max(alertAfter/4, 15*time.Second), 5*time.Minute)
}

// sendAlert sends one alert to every destination at once and records it
// when at least one got it. ok is false only when every destination failed.
func sendAlert(ctx context.Context, s *store.Store, dests []notify.Destination, a notify.Alert) (ok bool, err error) {
	n, errs := sendResults(notify.SendAll(ctx, dests, func(ctx context.Context, x notify.Destination) error {
		return x.SendAlert(ctx, a)
	}))
	if n > 0 {
		errs = append(errs, s.Audit(ctx, store.AuditEntry{Actor: "heimdall", Action: "notify.alert",
			Detail: map[string]any{"kind": a.Kind, "hosts": len(a.Hosts), "channels": n, "failed": len(dests) - n}}))
	}
	return n > 0, errors.Join(errs...)
}

// checkSilence raises silence anomalies for quiet hosts and sends the
// immediate notices. A notice no destination took is retried on the next
// tick; one that reached some destinations isn't resent (no duplicates).
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

	dests, cerr := senders(cfg)
	if len(dests) == 0 && cerr != nil {
		return cerr // misconfigured destination: retry next tick, loudly
	}
	errs := []error{cerr}
	send := func(kind string, hosts []store.SilentHost) bool {
		if len(hosts) == 0 || len(dests) == 0 {
			return true // nothing to send, or no destination: the anomaly is the record
		}
		a := notify.Alert{Kind: kind, GeneratedAt: time.Now().UTC(), Count: len(hosts),
			URL: strings.TrimSuffix(cfg.UI.BaseURL, "/") + "/anomalies"}
		if kind == notify.KindSilent {
			a.AlertAfter = cfg.Hosts.AlertAfter.Duration.String()
		}
		for _, h := range hosts {
			a.Hosts = append(a.Hosts, h.OrgSlug+"/"+h.Name)
		}
		ok, err := sendAlert(ctx, s, dests, a)
		errs = append(errs, err)
		return ok
	}
	if !send(notify.KindSilent, found.Silent) {
		found.Silent = nil // not marked, so the next tick tries again
	}
	if !send(notify.KindBack, found.Back) {
		found.Back = nil
	}
	errs = append(errs, tripwires.MarkSilenceAlerts(ctx, found))
	return errors.Join(errs...)
}

// anomalyAlerts sends new high-signal anomalies (notify.AlertRule) as one
// immediate alert per check, naming the host and a fixed label for the
// rule, never the anomaly's summary. It remembers the newest anomaly it
// has seen; anomalies open when the hub starts aren't re-sent.
type anomalyAlerts struct {
	cfg   config.Config
	s     *store.Store
	log   *slog.Logger
	last  int64 // newest anomaly ID handled
	fails int   // consecutive checks where every destination failed
}

// maxAlertRetries is how many checks retry an alert no destination took
// before it's dropped (it stays on the Anomalies page and in the digest).
const maxAlertRetries = 3

func (w *anomalyAlerts) start(ctx context.Context) error {
	open, err := w.s.OpenAnomalies(ctx, store.AllScope)
	if err != nil {
		return err
	}
	for _, v := range open {
		w.last = max(w.last, v.ID)
	}
	return nil
}

func (w *anomalyAlerts) check(ctx context.Context) error {
	open, err := w.s.OpenAnomalies(ctx, store.AllScope)
	if err != nil {
		return err
	}
	newest := w.last
	var fresh []store.AnomalyView
	for _, v := range open {
		if v.ID <= w.last {
			continue
		}
		newest = max(newest, v.ID)
		if notify.AlertRule(v.Rule, v.Severity) {
			fresh = append(fresh, v)
		}
	}
	if len(fresh) == 0 {
		w.last = newest
		return nil
	}
	slices.SortFunc(fresh, func(a, b store.AnomalyView) int { return int(a.ID - b.ID) })
	a := notify.Alert{Kind: notify.KindAnomaly, GeneratedAt: time.Now().UTC(), Count: len(fresh),
		URL: strings.TrimSuffix(w.cfg.UI.BaseURL, "/") + "/anomalies"}
	for _, v := range fresh {
		host := v.Host.OrgSlug + "/" + v.Host.Name
		a.Anomalies = append(a.Anomalies, notify.AlertAnomaly{Host: host, Rule: v.Rule, Severity: v.Severity})
		if !slices.Contains(a.Hosts, host) {
			a.Hosts = append(a.Hosts, host)
		}
		w.log.Warn("anomaly alert", "org", v.Host.OrgSlug, "host", v.Host.Name, "rule", v.Rule, "severity", v.Severity)
	}
	dests, cerr := senders(w.cfg)
	if len(dests) == 0 {
		w.last = newest // nothing to send to: the anomaly is the record
		return cerr
	}
	ok, err := sendAlert(ctx, w.s, dests, a)
	if ok || w.fails >= maxAlertRetries {
		w.last, w.fails = newest, 0
	} else {
		w.fails++
	}
	return errors.Join(cerr, err)
}
