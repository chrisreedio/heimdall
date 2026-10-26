// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/history"
	"github.com/realmwatch/heimdall/internal/store"
)

func cmdHostDiff(a *app, args []string) error {
	fs := a.flags("host diff", "[--org <org>] [--from <snapshot-id> --to <snapshot-id>] <hostname>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	from := fs.Int64("from", 0, "older snapshot ID (default: second newest)")
	to := fs.Int64("to", 0, "newer snapshot ID (default: newest)")
	pos, err := parse(fs, args, 1)
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
	f, t, d, err := history.HostDiff(a.ctx, s, host, *from, *to)
	if errors.Is(err, store.ErrNotFound) {
		return errors.New("need two snapshots (see `heimdall host history`)")
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "%s: snapshot %d (%s) → %d (%s)\n", host.Name, f.ID, formatTime(f.ReceivedAt), t.ID, formatTime(t.ReceivedAt))
	if f.Kernel != t.Kernel {
		fmt.Fprintf(a.stdout, "kernel: %s → %s\n", f.Kernel, t.Kernel)
	}
	if d.Empty() {
		fmt.Fprintln(a.stdout, "no package changes")
	}
	for _, sec := range []struct {
		label string
		cs    []history.Change
	}{{"upgraded", d.Upgraded}, {"DOWNGRADED", d.Downgraded}, {"added", d.Added}, {"removed", d.Removed}} {
		for _, c := range sec.cs {
			fmt.Fprintf(a.stdout, "%-10s %s %s\n", sec.label, c.Name, strings.TrimSpace(c.From+" → "+c.To))
		}
	}
	return nil
}

func cmdHostHistory(a *app, args []string) error {
	fs := a.flags("host history", "[--org <org>] <hostname>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	pos, err := parse(fs, args, 1)
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
	snaps, err := s.Snapshots(a.ctx, host.ID, 50)
	if err != nil {
		return err
	}
	rows := make([][]string, len(snaps))
	for i, sn := range snaps {
		rows[i] = []string{strconv.FormatInt(sn.ID, 10), formatTime(sn.ReceivedAt), sn.Source, sn.Kernel,
			strconv.Itoa(sn.Packages), strconv.Itoa(sn.PendingUpdates)}
	}
	return table(a, "SNAPSHOT\tRECEIVED\tSOURCE\tKERNEL\tPACKAGES\tPENDING", rows)
}

func cmdDrift(a *app, args []string) error {
	pos, err := parse(a.flags("drift", "<tag>"), args, 1)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	hosts, rows, err := history.Drift(a.ctx, s, strings.ToLower(pos[0]), store.AllScope)
	if err != nil {
		return err
	}
	if len(hosts) < 2 {
		return fmt.Errorf("drift needs at least two reporting hosts tagged %q (found %d)", pos[0], len(hosts))
	}
	header := "PACKAGE\t" + strings.Join(hosts, "\t")
	out := make([][]string, len(rows))
	for i, r := range rows {
		cells := []string{r.Name}
		for _, h := range hosts {
			v := r.Versions[h]
			if v == "" {
				v = "—"
			}
			cells = append(cells, v)
		}
		out[i] = cells
	}
	if len(out) == 0 {
		fmt.Fprintf(a.stderr, "All %d hosts tagged %s have identical packages.\n", len(hosts), pos[0])
		return nil
	}
	return table(a, header, out)
}
