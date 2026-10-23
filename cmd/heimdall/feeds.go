// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/feeds/eol"
	"github.com/chrisreedio/heimdall/internal/feeds/epss"
	"github.com/chrisreedio/heimdall/internal/feeds/osv"
	"github.com/chrisreedio/heimdall/internal/findings"
	"github.com/chrisreedio/heimdall/internal/netx"
	"github.com/chrisreedio/heimdall/internal/report"
	"github.com/chrisreedio/heimdall/internal/store"
)

// newSyncer wires feed sync to the allowlisted outbound client.
func newSyncer(cfg config.Config, s *store.Store, log *slog.Logger) *findings.Syncer {
	httpc := netx.New(netx.FeedHosts, "heimdall/"+version)
	engine := &findings.Engine{
		Store:       s,
		OSV:         &osv.Client{HTTP: httpc},
		Now:         time.Now,
		Log:         log,
		MaxAge:      cfg.Feeds.SyncInterval.Duration,
		Concurrency: 16,
	}
	s2 := &findings.Syncer{
		Store:  s,
		HTTP:   httpc,
		Engine: engine,
		EOL:    &eol.Client{HTTP: httpc},
		EPSS:   &epss.Client{HTTP: httpc},
		Feeds:  cfg.Feeds,
		Now:    time.Now,
		Log:    log,
	}
	s2.Retention.For, s2.Retention.Min = cfg.Hosts.KeepFor.Duration, cfg.Hosts.KeepMin
	return s2
}

func cmdFeedsSync(a *app, args []string) error {
	if _, err := parse(a.flags("feeds sync", ""), args, 0); err != nil {
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
	log := slog.New(slog.NewTextHandler(a.stderr, nil))
	return newSyncer(cfg, s, log).Run(a.ctx)
}

func cmdFeedsStatus(a *app, args []string) error {
	if _, err := parse(a.flags("feeds status", ""), args, 0); err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	states, err := s.FeedStates(a.ctx)
	if err != nil {
		return err
	}
	if len(states) == 0 {
		fmt.Fprintln(a.stderr, "No feeds synced yet; run `heimdall feeds sync`.")
		return nil
	}
	var rows [][]string
	for _, f := range states {
		status := "ok"
		if f.LastError != "" {
			status = "error: " + f.LastError
		}
		rows = append(rows, []string{f.Feed, formatTime(f.LastSuccess), formatTime(f.LastAttempt), status})
	}
	return table(a, "FEED\tLAST SUCCESS\tLAST ATTEMPT\tSTATUS", rows)
}

func cmdReport(a *app, args []string) error {
	fs := a.flags("report", "[--org <org>] [--format text|json|csv|html] [--limit N]")
	org := fs.String("org", "", "only hosts in this organization")
	format := fs.String("format", "text", "text, json, csv or html")
	limit := fs.Int("limit", 10, "findings shown per host in text format (0 = all)")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	switch *format {
	case "text", "json", "csv", "html":
	default:
		return fmt.Errorf("--format must be text, json, csv or html")
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	r, err := report.Build(a.ctx, s, report.Filter{Org: *org, Scope: store.AllScope}, time.Now())
	if err != nil {
		return err
	}
	switch *format {
	case "json":
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "csv":
		return report.WriteCSV(a.stdout, r)
	case "html":
		title := "Heimdall report"
		if *org != "" {
			title += " · " + *org
		}
		return report.WriteHTML(a.stdout, r, title)
	}
	n := *limit
	if n <= 0 {
		n = -1
	}
	report.WriteText(a.stdout, r, n)
	return nil
}
