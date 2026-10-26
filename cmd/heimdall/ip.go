// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/store"
)

// IP awareness: labels, what's known about an address, and each org's SSH
// source policy (docs/ip-awareness.md).

var ipCommands = map[string]command{
	"label":  group("ip label", map[string]command{"add": cmdIPLabelAdd, "list": cmdIPLabelList, "rm": cmdIPLabelRm}),
	"show":   cmdIPShow,
	"policy": cmdIPPolicy,
}

// ipOrg resolves --org (optional with one org) or --all-orgs to an org ID
// (0 for every org).
func (a *app) ipOrg(s *store.Store, org string, all bool) (int64, string, error) {
	if all {
		if org != "" {
			return 0, "", fmt.Errorf("pass --org or --all-orgs, not both")
		}
		return 0, "", nil
	}
	if err := a.defaultOrg(s, &org); err != nil {
		return 0, "", err
	}
	orgs, err := s.ListOrgs(a.ctx)
	if err != nil {
		return 0, "", err
	}
	for _, o := range orgs {
		if o.Slug == org {
			return o.ID, o.Slug, nil
		}
	}
	return 0, "", fmt.Errorf("org %q: %w", org, store.ErrNotFound)
}

func cmdIPLabelAdd(a *app, args []string) error {
	fs := a.flags("ip label add", "[--org <org> | --all-orgs] --kind staff --name \"Office\" [--person x] [--note x] <addr|cidr>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	all := fs.Bool("all-orgs", false, "label it for every org")
	kind := fs.String("kind", "", "staff, automation, infra, tailnet or private")
	name := fs.String("name", "", "what it is, e.g. Office VPN (required)")
	person := fs.String("person", "", "whose it is, e.g. alice@example.com")
	note := fs.String("note", "", "anything else worth knowing")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if err := required(fs, "kind", "name"); err != nil {
		return err
	}
	if *kind == store.IPKindUnknown {
		return fmt.Errorf("--kind: pick staff, automation, infra, tailnet or private")
	}
	p, err := store.ParseIPPrefix(pos[0])
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	orgID, _, err := a.ipOrg(s, *org, *all)
	if err != nil {
		return err
	}
	id, err := s.AddIPLabel(a.ctx, actor(), store.IPLabel{OrgID: orgID, Prefix: p, Kind: *kind, Name: *name, Person: *person, Note: *note})
	if err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, id)
	resolveKnownCLI(a, s) // ipinfo.go
	return nil
}

func cmdIPLabelList(a *app, args []string) error {
	fs := a.flags("ip label list", "[--org <org>]")
	org := fs.String("org", "", "only labels that apply to this org (default: every label)")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	var labels []store.IPLabel
	if *org != "" {
		id, _, err := a.ipOrg(s, *org, false)
		if err != nil {
			return err
		}
		labels, err = s.IPLabels(a.ctx, id)
		if err != nil {
			return err
		}
	} else if labels, err = s.AllIPLabels(a.ctx); err != nil {
		return err
	}
	slugs, err := orgSlugs(a, s)
	if err != nil {
		return err
	}
	rows := make([][]string, len(labels))
	for i, l := range labels {
		rows[i] = []string{strconv.FormatInt(l.ID, 10), orDash(slugs[l.OrgID]), l.Prefix.String(), l.Kind, l.Name,
			orDash(l.Person), l.Source, formatTime(l.UpdatedAt)}
	}
	return table(a, "ID\tORG\tPREFIX\tKIND\tNAME\tPERSON\tSOURCE\tUPDATED", rows)
}

func orgSlugs(a *app, s *store.Store) (map[int64]string, error) {
	orgs, err := s.ListOrgs(a.ctx)
	if err != nil {
		return nil, err
	}
	m := map[int64]string{0: "(all)"}
	for _, o := range orgs {
		m[o.ID] = o.Slug
	}
	return m, nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func cmdIPLabelRm(a *app, args []string) error {
	fs := a.flags("ip label rm", "[--org <org> | --all-orgs] <id>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	all := fs.Bool("all-orgs", false, "the label is for every org")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	id, err := strconv.ParseInt(pos[0], 10, 64)
	if err != nil {
		return fmt.Errorf("label ID must be a number (see `heimdall ip label list`)")
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	orgID, _, err := a.ipOrg(s, *org, *all)
	if err != nil {
		return err
	}
	return s.RemoveIPLabel(a.ctx, actor(), orgID, id)
}

func cmdIPShow(a *app, args []string) error {
	fs := a.flags("ip show", "[--org <org>] <addr>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	user := fs.String("user", "", "the account a session used, for deploy services' account names")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if _, err := netip.ParseAddr(pos[0]); err != nil {
		return fmt.Errorf("%q isn't an IP address", pos[0])
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
	orgID, _, err := a.ipOrg(s, *org, false)
	if err != nil {
		return err
	}
	r, _ := newIPResolver(cfg, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	v := r.Resolve(a.ctx, orgID, pos[0], *user, time.Now())
	best := v.Best()
	fmt.Fprintf(a.stdout, "address  %s\nkind     %s\n", v.Addr, v.Kind())
	if !v.Unknown() {
		who := best.Name
		if best.Person != "" {
			who += " (" + best.Person + ")"
		}
		if best.Guess {
			who = "probably " + who
		}
		fmt.Fprintf(a.stdout, "best     %s\n", who)
	}
	if len(v.Labels) == 0 {
		fmt.Fprintln(a.stdout, "labels   none: label it with `heimdall ip label add` if it's yours")
		return nil
	}
	fmt.Fprintln(a.stdout)
	rows := make([][]string, len(v.Labels))
	for i, l := range v.Labels {
		prefix := "-"
		if l.Prefix.IsValid() {
			prefix = l.Prefix.String()
		}
		guess := ""
		if l.Guess {
			guess = "guess"
		}
		rows[i] = []string{l.Kind, l.Name, orDash(l.Person), l.Source, prefix, guess}
	}
	return table(a, "KIND\tNAME\tPERSON\tSOURCE\tPREFIX\t", rows)
}

func cmdIPPolicy(a *app, args []string) error {
	fs := a.flags("ip policy", "[--org <org>] [--tailnet-only on|off] [--allow-services on|off] [--count-services on|off]")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	tailnet := fs.String("tailnet-only", "", "on: alert on privileged SSH from anywhere but the tailnet or a private network")
	services := fs.String("allow-services", "", "on (the default): exempt deploy services' synced ranges from --tailnet-only")
	count := fs.String("count-services", "", "on: count sessions from deploy services' synced ranges as privileged access (off by default)")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	orgID, slug, err := a.ipOrg(s, *org, false)
	if err != nil {
		return err
	}
	p, err := s.IPPolicy(a.ctx, orgID)
	if err != nil {
		return err
	}
	if *tailnet != "" || *services != "" || *count != "" {
		for flag, v := range map[string]struct {
			s string
			b *bool
		}{"tailnet-only": {*tailnet, &p.TailnetOnly}, "allow-services": {*services, &p.AllowServices},
			"count-services": {*count, &p.CountServices}} {
			switch strings.ToLower(v.s) {
			case "":
			case "on", "true", "yes":
				*v.b = true
			case "off", "false", "no":
				*v.b = false
			default:
				return fmt.Errorf("--%s: want on or off, got %q", flag, v.s)
			}
		}
		if err := s.SetIPPolicy(a.ctx, actor(), p, time.Now()); err != nil {
			return err
		}
	}
	onOff := map[bool]string{true: "on", false: "off"}
	fmt.Fprintf(a.stdout, "org             %s\ntailnet-only    %s\nallow-services  %s\ncount-services  %s\n",
		slug, onOff[p.TailnetOnly], onOff[p.AllowServices], onOff[p.CountServices])
	return nil
}
