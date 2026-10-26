// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

func planID(s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("plan ID must be a positive number, got %q", s)
	}
	return id, nil
}

func cmdPlanCreate(a *app, args []string) error {
	fs := a.flags("plan create", "[--org <org> | --all-orgs] <name>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	allOrgs := fs.Bool("all-orgs", false, "a fleet-wide plan across every org")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if !*allOrgs {
		if err := a.defaultOrg(s, org); err != nil {
			return err
		}
	}
	p, err := s.CreatePlan(a.ctx, actor(), 0, *org, pos[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Created plan %d (%s). Add hosts with `heimdall plan add %d <host>...`.\n", p.ID, p.Name, p.ID)
	fmt.Fprintln(a.stdout, p.ID)
	return nil
}

func cmdPlanList(a *app, args []string) error {
	if _, err := parse(a.flags("plan list", ""), args, 0); err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	plans, err := s.ListPlans(a.ctx, store.AllScope)
	if err != nil {
		return err
	}
	rows := make([][]string, len(plans))
	for i, p := range plans {
		org, status := p.OrgSlug, "open"
		if org == "" {
			org = "(all orgs)"
		}
		if !p.ClosedAt.IsZero() {
			status = "closed"
		}
		rows[i] = []string{strconv.FormatInt(p.ID, 10), p.Name, org,
			fmt.Sprintf("%d/%d/%d", p.Hosts, p.Done, p.Verified), status, formatTime(p.CreatedAt)}
	}
	return table(a, "ID\tNAME\tORG\tHOSTS/DONE/VERIFIED\tSTATUS\tCREATED", rows)
}

func cmdPlanShow(a *app, args []string) error {
	pos, err := parse(a.flags("plan show", "<plan-id>"), args, 1)
	if err != nil {
		return err
	}
	id, err := planID(pos[0])
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	p, err := s.PlanByID(a.ctx, id)
	if err != nil {
		return err
	}
	items, err := s.PlanItems(a.ctx, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Plan %d: %s (%d hosts, %d done, %d verified)\n\n", p.ID, p.Name, p.Hosts, p.Done, p.Verified)
	rows := make([][]string, len(items))
	for i, it := range items {
		state := "to do"
		switch {
		case !it.VerifiedAt.IsZero():
			state = "verified " + formatTime(it.VerifiedAt)
		case !it.DoneAt.IsZero():
			state = "done, waiting for a clean check-in"
		}
		rows[i] = []string{strconv.Itoa(it.Batch), it.Host.OrgSlug, it.Host.Name, state, strconv.Itoa(it.PendingSecurity)}
	}
	return table(a, "BATCH\tORG\tHOST\tSTATE\tPENDING SECURITY", rows)
}

// planHosts resolves a plan and hostnames given on the command line.
func planHosts(a *app, s *store.Store, idArg, org string, names []string) (store.Plan, []store.IngestHost, error) {
	id, err := planID(idArg)
	if err != nil {
		return store.Plan{}, nil, err
	}
	p, err := s.PlanByID(a.ctx, id)
	if err != nil {
		return p, nil, err
	}
	if org == "" {
		org = p.OrgSlug
	}
	if org == "" {
		if err := a.defaultOrg(s, &org); err != nil {
			return p, nil, fmt.Errorf("plan %d spans orgs: %w", id, err)
		}
	}
	var hosts []store.IngestHost
	for _, n := range names {
		h, err := s.HostByName(a.ctx, org, n)
		if err != nil {
			return p, nil, err
		}
		hosts = append(hosts, h)
	}
	return p, hosts, nil
}

func cmdPlanAdd(a *app, args []string) error {
	fs := a.flags("plan add", "[--batch N] [--org <org>] <plan-id> <host>...")
	batch := fs.Int("batch", 1, "batch number (patch batch 1 first)")
	org := fs.String("org", "", "org of the hosts (defaults to the plan's org)")
	pos, err := parseAtLeast(fs, args, 2)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	p, hosts, err := planHosts(a, s, pos[0], *org, pos[1:])
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if err := s.AddToPlan(a.ctx, actor(), p.ID, h, *batch); err != nil {
			return err
		}
	}
	fmt.Fprintf(a.stderr, "Added %d host(s) to plan %d, batch %d.\n", len(hosts), p.ID, *batch)
	return nil
}

func cmdPlanRm(a *app, args []string) error {
	fs := a.flags("plan rm", "[--org <org>] <plan-id> <host>...")
	org := fs.String("org", "", "org of the hosts (defaults to the plan's org)")
	pos, err := parseAtLeast(fs, args, 2)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	p, hosts, err := planHosts(a, s, pos[0], *org, pos[1:])
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if err := s.RemoveFromPlan(a.ctx, actor(), p.ID, h); err != nil {
			return err
		}
	}
	return nil
}

func planDone(a *app, args []string, done bool) error {
	verb := map[bool]string{true: "done", false: "undo"}[done]
	fs := a.flags("plan "+verb, "[--org <org>] <plan-id> <host>...")
	org := fs.String("org", "", "org of the hosts (defaults to the plan's org)")
	pos, err := parseAtLeast(fs, args, 2)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	p, hosts, err := planHosts(a, s, pos[0], *org, pos[1:])
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if err := s.SetPlanItemDone(a.ctx, actor(), 0, p.ID, h, done, time.Now()); err != nil {
			return err
		}
	}
	if done {
		fmt.Fprintln(a.stderr, "Marked done. Each host is verified by its next check-in with no pending security updates.")
	}
	return nil
}

func cmdPlanDone(a *app, args []string) error { return planDone(a, args, true) }
func cmdPlanUndo(a *app, args []string) error { return planDone(a, args, false) }

func cmdPlanClose(a *app, args []string) error {
	pos, err := parse(a.flags("plan close", "<plan-id>"), args, 1)
	if err != nil {
		return err
	}
	id, err := planID(pos[0])
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	return s.ClosePlan(a.ctx, actor(), id, true, time.Now())
}
