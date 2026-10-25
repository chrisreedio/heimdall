// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/surface"
)

// cmdSurface prints the attack-surface map (internal/surface): one row per
// public name, worst first; or, with --changes, the DNS change log.
func cmdSurface(a *app, args []string) error {
	fs := a.flags("surface", "[--org <org>] [--json] [--changes]")
	org := fs.String("org", "", "only names that lead to this organization's hosts or sites")
	asJSON := fs.Bool("json", false, "print JSON (the map, zones and the last 90 days of changes)")
	changes := fs.Bool("changes", false, "print the DNS change log instead of the map")
	if _, err := parse(fs, args, 0); err != nil {
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
	now := time.Now()
	m, err := surface.Load(a.ctx, s, cfg.Cloudflare.Enabled, now)
	if err != nil {
		return err
	}
	cs, err := s.SurfaceChanges(a.ctx, now.AddDate(0, 0, -store.SurfaceChangeKeepDays), 10000)
	if err != nil {
		return err
	}
	if *org != "" {
		orgs, err := s.ListOrgs(a.ctx)
		if err != nil {
			return err
		}
		id := int64(0)
		for _, o := range orgs {
			if o.Slug == *org {
				id = o.ID
			}
		}
		if id == 0 {
			return fmt.Errorf("no organization %q", *org)
		}
		can := func(x int64) bool { return x == id }
		m, cs = m.For(false, can), surface.ChangesFor(cs, false, can)
	}
	if *asJSON {
		out := struct {
			surface.Map
			Changes []store.SurfaceChange `json:"changes"`
		}{m, cs}
		if out.Rows == nil {
			out.Rows = []surface.Row{}
		}
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	if *changes {
		rows := make([][]string, 0, len(cs))
		for _, c := range cs {
			rows = append(rows, []string{c.At.Local().Format("2006-01-02 15:04"), c.Zone, c.Name, c.Kind, surfaceDash(c.Old), surfaceDash(c.New)})
		}
		if len(rows) == 0 {
			fmt.Fprintln(a.stderr, "No DNS changes recorded in the last 90 days.")
			return nil
		}
		return table(a, "AT\tZONE\tNAME\tCHANGE\tBEFORE\tAFTER", rows)
	}
	if !cfg.Cloudflare.Enabled {
		fmt.Fprintln(a.stderr, "Cloudflare is off: names come from the sites collectors report only.")
	}
	rows := make([][]string, 0, len(m.Rows))
	for _, r := range m.Rows {
		var hosts, sites, flags []string
		for _, h := range r.Hosts {
			hosts = append(hosts, h.Org+"/"+h.Name)
		}
		for _, x := range r.Sites {
			sites = append(sites, x.Root)
		}
		for _, f := range append(slices.Clone(r.Flags), r.ZoneFlags...) {
			flags = append(flags, f.Kind)
		}
		status := r.Status
		if r.Exposed {
			status += ",exposed"
		}
		rows = append(rows, []string{r.Name, surfaceDash(r.Zone), status, surfaceDash(strings.Join(r.Targets, " ")),
			surfaceDash(strings.Join(hosts, ",")), surfaceDash(strings.Join(sites, ",")),
			strconv.Itoa(r.Worst.KEV), strconv.Itoa(r.Worst.Critical), strconv.Itoa(r.Worst.High),
			strconv.Itoa(r.Worst.Medium), strconv.Itoa(r.Worst.Low), surfaceDash(strings.Join(flags, ","))})
	}
	if len(rows) == 0 {
		fmt.Fprintln(a.stderr, "No public names yet.")
		return nil
	}
	return table(a, "NAME\tZONE\tSTATUS\tRECORD\tHOST\tSITE\tKEV\tCRIT\tHIGH\tMED\tLOW\tFLAGS", rows)
}

func surfaceDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
