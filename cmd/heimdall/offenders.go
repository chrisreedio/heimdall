// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/logins"
	"github.com/chrisreedio/heimdall/internal/store"
)

// Failed logins: the ranked repeat offenders (docs/failed-logins.md).

// offenderJSON is one offender in --json output.
type offenderJSON struct {
	IP        string    `json:"ip"`
	Hosts     []string  `json:"hosts"` // org/host
	Failures  int       `json:"failures"`
	Usernames int       `json:"usernames"` // distinct usernames tried, the most on one host and day
	First     time.Time `json:"first_seen"`
	Last      time.Time `json:"last_seen"`
	Succeeded []string  `json:"then_succeeded"` // hosts where a login from it then succeeded
	Network   string    `json:"network,omitempty"`
}

func cmdOffenders(a *app, args []string) error {
	fs := a.flags("offenders", "[--org <org>] [--since 24h] [--json]")
	org := fs.String("org", "", "only this org's hosts (default: every org)")
	since := fs.String("since", "24h", "how far back, e.g. 24h or 7d (at most 30d)")
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	d, err := parseDays(*since)
	if err != nil || d <= 0 || d > store.LoginRetention {
		return fmt.Errorf("--since: give a duration up to 30d, e.g. 24h or 7d")
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
	if *org != "" {
		orgs, err := s.ListOrgs(a.ctx)
		if err != nil {
			return err
		}
		found := false
		for _, o := range orgs {
			found = found || o.Slug == *org
		}
		if !found {
			return fmt.Errorf("org %q: %w", *org, store.ErrNotFound)
		}
	}
	r, _ := newIPResolver(cfg, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rk := &logins.Ranker{Store: s, IPs: r}
	list, err := rk.Offenders(a.ctx, store.AllScope, *org, time.Now().Add(-d))
	if err != nil {
		return err
	}
	if err := rk.Networks(a.ctx, list, 0); err != nil {
		return err
	}
	names := func(hs []store.IngestHost) []string {
		out := make([]string, len(hs))
		for i, h := range hs {
			out[i] = h.OrgSlug + "/" + h.Name
		}
		return out
	}
	if *asJSON {
		out := make([]offenderJSON, len(list))
		for i, o := range list {
			out[i] = offenderJSON{IP: o.IP, Hosts: names(o.Hosts), Failures: o.Failures, Usernames: o.Usernames,
				First: o.First, Last: o.Last, Succeeded: names(o.Succeeded), Network: o.Network}
		}
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	if len(list) == 0 {
		fmt.Fprintf(a.stderr, "No failed logins from unknown addresses in the last %s.\n", *since)
		return nil
	}
	rows := make([][]string, len(list))
	for i, o := range list {
		got := ""
		if len(o.Succeeded) > 0 {
			got = "THEN SUCCEEDED: " + strings.Join(names(o.Succeeded), ",")
		}
		rows[i] = []string{o.IP, strconv.Itoa(len(o.Hosts)), strconv.Itoa(o.Failures), strconv.Itoa(o.Usernames),
			formatTime(o.First), formatTime(o.Last), o.Network, got}
	}
	return table(a, "ADDRESS\tHOSTS\tFAILURES\tUSERNAMES\tFIRST\tLAST\tNETWORK\t", rows)
}
