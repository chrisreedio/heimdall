// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

func cmdEnrollCreate(a *app, args []string) error {
	fs := a.flags("enroll create", "--org <org> --env <env> [--tag t]... [--expires 24h] [--uses n] [--label text] [--no-approval]")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	env := fs.String("env", "", "environment slug (optional if the org has only one)")
	var tags multiFlag
	fs.Var(&tags, "tag", "tag each enrolled host gets, repeatable or comma-separated")
	expires := fs.String("expires", "24h", "how long the key works, e.g. 1h, 24h or 7d (at most 30d)")
	uses := fs.Int("uses", 0, "most servers it may enroll (0: no limit until it expires)")
	label := fs.String("label", "", "what the key is for, e.g. the rollout")
	noApproval := fs.Bool("no-approval", false, "enrolled hosts report at once, without waiting for an admin's approval")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	ttl, err := parseDays(*expires)
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
	if err := a.defaultEnv(s, *org, env); err != nil {
		return err
	}
	k, key, err := s.CreateEnrollKey(a.ctx, actor(), *org, *env, store.NewEnrollKey{Label: *label, Tags: tags, MaxUses: *uses,
		TTL: ttl, Approval: !*noApproval}, time.Now())
	if err != nil {
		return err
	}
	limit := "any number of servers"
	if k.MaxUses > 0 {
		limit = fmt.Sprintf("up to %d servers", k.MaxUses)
	}
	approval := "Each one waits for approval: heimdall enroll pending, then heimdall enroll approve.\n"
	if !k.Approval {
		approval = "They report at once, without approval.\n"
	}
	// Only the key goes to stdout, so `heimdall enroll create ... > key` works.
	fmt.Fprintf(a.stderr, "Created enrollment key %d: it adds %s to %s/%s until %s (shown once).\n%s"+
		"On each server: sudo sh install.sh --hub <ingest URL> --enroll, and paste the key when asked.\n"+
		"Revoke it early with: heimdall enroll revoke --org %s %d\n\n",
		k.ID, limit, k.OrgSlug, k.EnvSlug, formatTime(k.ExpiresAt), approval, k.OrgSlug, k.ID)
	fmt.Fprintln(a.stdout, key)
	return nil
}

func cmdEnrollList(a *app, args []string) error {
	fs := a.flags("enroll list", "[--org <org>]")
	org := fs.String("org", "", "only keys in this organization")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	keys, err := s.ListEnrollKeys(a.ctx, *org)
	if err != nil {
		return err
	}
	now := time.Now()
	rows := make([][]string, len(keys))
	for i, k := range keys {
		uses := strconv.Itoa(k.Uses)
		if k.MaxUses > 0 {
			uses += "/" + strconv.Itoa(k.MaxUses)
		}
		approval := "no"
		if k.Approval {
			approval = "yes"
		}
		rows[i] = []string{strconv.FormatInt(k.ID, 10), k.OrgSlug, k.EnvSlug, strings.Join(k.Tags, ","), k.Label,
			uses, approval, formatTime(k.ExpiresAt), k.Status(now)}
	}
	return table(a, "ID\tORG\tENV\tTAGS\tLABEL\tUSES\tAPPROVAL\tEXPIRES\tSTATUS", rows)
}

func cmdEnrollRevoke(a *app, args []string) error {
	fs := a.flags("enroll revoke", "--org <org> <key-id>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	id, err := strconv.ParseInt(pos[0], 10, 64)
	if err != nil {
		return fmt.Errorf("key ID must be a number")
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := a.defaultOrg(s, org); err != nil {
		return err
	}
	if err := s.RevokeEnrollKey(a.ctx, actor(), *org, id); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Revoked enrollment key %d. Hosts it enrolled keep their own tokens.\n", id)
	return nil
}

func cmdEnrollPending(a *app, args []string) error {
	fs := a.flags("enroll pending", "[--org <org>]")
	org := fs.String("org", "", "only hosts in this organization")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	hosts, err := s.AwaitingHosts(a.ctx, *org)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		fmt.Fprintln(a.stderr, "No hosts are waiting for approval.")
		return nil
	}
	rows := make([][]string, len(hosts))
	for i, h := range hosts {
		rows[i] = []string{h.OrgSlug, h.Name, h.EnvSlug, strings.Join(h.Tags, ","), strconv.FormatInt(h.KeyID, 10), h.KeyLabel,
			h.IP, formatTime(h.EnrolledAt)}
	}
	if err := table(a, "ORG\tHOST\tENV\tTAGS\tKEY\tLABEL\tFROM\tENROLLED", rows); err != nil {
		return err
	}
	fmt.Fprintln(a.stderr, "\nApprove with: heimdall enroll approve --org <org> <host>; reject with: heimdall host rm --org <org> --yes <host>")
	return nil
}

func cmdEnrollApprove(a *app, args []string) error {
	fs := a.flags("enroll approve", "[--org <org>] <hostname>...")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	pos, err := parseAtLeast(fs, args, 1)
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
	for _, name := range pos {
		if err := s.ApproveHost(a.ctx, actor(), *org, name); err != nil {
			return err
		}
		fmt.Fprintf(a.stderr, "Approved %s: its next report (within the hour) is stored.\n", name)
	}
	return nil
}
