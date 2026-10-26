// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

func cmdAnomalyList(a *app, args []string) error {
	if _, err := parse(a.flags("anomaly list", ""), args, 0); err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	list, err := s.OpenAnomalies(a.ctx, store.AllScope)
	if err != nil {
		return err
	}
	rows := make([][]string, len(list))
	for i, an := range list {
		rows[i] = []string{strconv.FormatInt(an.ID, 10), formatTime(an.DetectedAt), an.Host.OrgSlug + "/" + an.Host.Name,
			an.Severity, an.Rule, an.Summary}
	}
	return table(a, "ID\tDETECTED\tHOST\tSEVERITY\tRULE\tSUMMARY", rows)
}

func cmdAnomalyAck(a *app, args []string) error {
	fs := a.flags("anomaly ack", "--note \"what you found\" <id>")
	note := fs.String("note", "", "what you found (required)")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if err := required(fs, "note"); err != nil {
		return err
	}
	id, err := strconv.ParseInt(pos[0], 10, 64)
	if err != nil {
		return fmt.Errorf("anomaly ID must be a number")
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	return s.AckAnomaly(a.ctx, actor(), 0, id, *note, time.Now())
}

func cmdAnomalySuppress(a *app, args []string) error {
	fs := a.flags("anomaly suppress", "[--org <org>] --rule <rule> --for 7d --note \"why\" <hostname>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	rule := fs.String("rule", "", "rule to mute: "+strings.Join(store.AnomalyRules, ", "))
	dur := fs.String("for", "7d", "how long, e.g. 12h or 7d (max 1 year)")
	note := fs.String("note", "", "why (required)")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if err := required(fs, "rule", "note"); err != nil {
		return err
	}
	d, err := parseDays(*dur)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := a.defaultOrg(s, org); err != nil {
		return err
	}
	host, err := s.HostByName(a.ctx, *org, pos[0])
	if err != nil {
		return err
	}
	now := time.Now()
	return s.Suppress(a.ctx, actor(), 0, host, *rule, now.Add(d), *note, now)
}

// parseDays accepts Go durations plus a "d" suffix for days.
func parseDays(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func cmdWindowAdd(a *app, args []string) error {
	fs := a.flags("window add", "[--org <org>] [--env <env> | --host <host>] (--days sat,sun --at 02:00 --duration 3h --tz Europe/London | --from 2026-11-01T02:00:00Z --until 2026-11-01T05:00:00Z) [--name ...]")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	env := fs.String("env", "", "limit to one environment")
	host := fs.String("host", "", "limit to one host")
	name := fs.String("name", "", "label, e.g. \"weekly patching\"")
	days := fs.String("days", "", "weekly: days, e.g. sat,sun or mon-fri")
	at := fs.String("at", "", "weekly: local start time HH:MM")
	dur := fs.Duration("duration", 0, "weekly: length, e.g. 3h")
	tz := fs.String("tz", "UTC", "weekly: IANA timezone")
	from := fs.String("from", "", "one-off: start (RFC 3339)")
	until := fs.String("until", "", "one-off: end (RFC 3339)")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	w := store.Window{EnvSlug: *env, Host: *host, Name: *name}
	switch {
	case *days != "":
		mask, err := store.ParseWeekdays(*days)
		if err != nil {
			return err
		}
		w.Weekdays, w.StartTime, w.Duration, w.Timezone = mask, *at, *dur, *tz
	case *from != "":
		var err error
		if w.Starts, err = time.Parse(time.RFC3339, *from); err != nil {
			return fmt.Errorf("--from: %w", err)
		}
		if w.Ends, err = time.Parse(time.RFC3339, *until); err != nil {
			return fmt.Errorf("--until: %w", err)
		}
	default:
		fs.Usage()
		return errUsage
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := a.defaultOrg(s, org); err != nil {
		return err
	}
	w.OrgSlug = *org
	id, err := s.CreateWindow(a.ctx, actor(), w)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Added maintenance window %d.\n", id)
	return nil
}

func cmdWindowList(a *app, args []string) error {
	if _, err := parse(a.flags("window list", ""), args, 0); err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	ws, err := s.Windows(a.ctx, store.AllScope)
	if err != nil {
		return err
	}
	rows := make([][]string, len(ws))
	for i, w := range ws {
		scope := w.OrgSlug
		switch {
		case w.Host != "":
			scope += " host " + w.Host
		case w.EnvSlug != "":
			scope += " env " + w.EnvSlug
		}
		when := w.Starts.Format(time.RFC3339) + " → " + w.Ends.Format(time.RFC3339)
		if w.Weekly() {
			when = fmt.Sprintf("%s %s for %s (%s)", weekdayList(w.Weekdays), w.StartTime, w.Duration, w.Timezone)
		}
		rows[i] = []string{strconv.FormatInt(w.ID, 10), w.Name, scope, when}
	}
	return table(a, "ID\tNAME\tSCOPE\tWHEN", rows)
}

func weekdayList(mask int) string {
	names := []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}
	var out []string
	for i, n := range names {
		if mask&(1<<i) != 0 {
			out = append(out, n)
		}
	}
	return strings.Join(out, ",")
}

func cmdWindowRm(a *app, args []string) error {
	pos, err := parse(a.flags("window rm", "<id>"), args, 1)
	if err != nil {
		return err
	}
	id, err := strconv.ParseInt(pos[0], 10, 64)
	if err != nil {
		return fmt.Errorf("window ID must be a number")
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	return s.DeleteWindow(a.ctx, actor(), id)
}
