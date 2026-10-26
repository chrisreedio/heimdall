// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/store"
)

func cmdInit(a *app, args []string) error {
	fs := a.flags("init", "[--database path] [--ui-base-url URL] [--ingest-public-url URL] [--behind-proxy] [--mcp-base-url URL]")
	dbFlag := fs.String("database", "heimdall.db", "database path, relative to the config file's directory")
	uiURL := fs.String("ui-base-url", "", "UI address you browse to, e.g. https://hub.tailnet.ts.net")
	ingestURL := fs.String("ingest-public-url", "", "address servers use for ingest, e.g. https://ingest.example.com")
	behind := fs.Bool("behind-proxy", false, "ingest sits behind a local TLS proxy (Caddy or tailscale serve)")
	mcpURL := fs.String("mcp-base-url", "", "enable MCP at this https address")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	if err := config.ValidateDatabasePath(*dbFlag); err != nil {
		return fmt.Errorf("--database: %w", err)
	}
	dbPath := *dbFlag
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(filepath.Dir(a.configPath), dbPath)
	}

	// Config first, exclusively: never clobber an existing install.
	tmpl := config.TemplateWith(config.Setup{Database: *dbFlag, UIBaseURL: *uiURL, IngestPublicURL: *ingestURL,
		BehindProxy: *behind, MCPBaseURL: *mcpURL})
	if err := writeExclusive(a.configPath, tmpl, 0o640); err != nil {
		return err
	}
	if err := initDB(a, dbPath); err != nil {
		os.Remove(a.configPath)
		return err
	}

	fmt.Fprintf(a.stderr, "Created %s and %s (mode 0600).\n\nNext:\n"+
		"  heimdall org create acme --name \"Acme Corp\"\n"+
		"  heimdall env create --org acme prod\n"+
		"  heimdall host add --org acme --env prod web-01\n", a.configPath, dbPath)
	return nil
}

func initDB(a *app, path string) error {
	if err := store.Create(path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("database %s already exists; refusing to overwrite", path)
		}
		return err
	}
	s, err := store.Open(a.ctx, path)
	if err == nil {
		_, err = s.Migrate(a.ctx)
		s.Close()
	}
	if err != nil {
		os.Remove(path)
		os.Remove(path + "-wal")
		os.Remove(path + "-shm")
	}
	return err
}

func writeExclusive(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s already exists; refusing to overwrite", path)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

func cmdMigrate(a *app, args []string) error {
	if _, err := parse(a.flags("migrate", ""), args, 0); err != nil {
		return err
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	migrateConfig(a)
	s, err := store.Open(a.ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer s.Close()
	applied, err := s.Migrate(a.ctx)
	for _, name := range applied {
		fmt.Fprintln(a.stderr, "applied", name)
	}
	if err != nil {
		return err
	}
	v, _, err := s.SchemaStatus(a.ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "schema at version %d\n", v)
	return tidyDatabase(a, s, cfg.Database)
}

func cmdOrgCreate(a *app, args []string) error {
	fs := a.flags("org create", "<slug> [--name \"Display Name\"]")
	name := fs.String("name", "", "display name (defaults to slug)")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	o, err := s.CreateOrg(a.ctx, actor(), pos[0], *name)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Created org %s (%s).\n", o.Slug, o.Name)
	return nil
}

func cmdOrgList(a *app, args []string) error {
	if _, err := parse(a.flags("org list", ""), args, 0); err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	orgs, err := s.ListOrgs(a.ctx)
	if err != nil {
		return err
	}
	rows := make([][]string, len(orgs))
	for i, o := range orgs {
		rows[i] = []string{o.Slug, o.Name, strconv.Itoa(o.Hosts), formatTime(o.CreatedAt)}
	}
	return table(a, "SLUG\tNAME\tHOSTS\tCREATED", rows)
}

func cmdEnvCreate(a *app, args []string) error {
	fs := a.flags("env create", "--org <org> <slug> [--name \"Display Name\"]")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	name := fs.String("name", "", "display name (defaults to slug)")
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
	e, err := s.CreateEnv(a.ctx, actor(), *org, pos[0], *name)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Created env %s in org %s.\n", e.Slug, *org)
	return nil
}

func cmdEnvList(a *app, args []string) error {
	fs := a.flags("env list", "--org <org>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	if _, err := parse(fs, args, 0); err != nil {
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
	envs, err := s.ListEnvs(a.ctx, *org)
	if err != nil {
		return err
	}
	rows := make([][]string, len(envs))
	for i, e := range envs {
		rows[i] = []string{e.Slug, e.Name, strconv.Itoa(e.Hosts), formatTime(e.CreatedAt)}
	}
	return table(a, "SLUG\tNAME\tHOSTS\tCREATED", rows)
}

func cmdHostAdd(a *app, args []string) error {
	fs := a.flags("host add", "--org <org> --env <env> [--tag t]... [hostname]")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	env := fs.String("env", "", "environment slug (optional if the org has only one)")
	var tags multiFlag
	fs.Var(&tags, "tag", "tag, repeatable or comma-separated (e.g. web,role:lb)")
	pos, err := parseAtLeast(fs, args, 0)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		fs.Usage()
		return errUsage
	}
	name := "" // no name: the host takes the hostname it reports first
	if len(pos) == 1 {
		name = pos[0]
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
	h, token, err := s.AddHost(a.ctx, actor(), *org, *env, name, tags)
	if err != nil {
		return err
	}
	// Only the token goes to stdout, so `heimdall host add ... > token` works.
	fmt.Fprintf(a.stderr, "Added host %s (org %s, env %s).\n", h.Name, h.OrgSlug, h.EnvSlug)
	if h.AutoName {
		fmt.Fprintln(a.stderr, "It takes the server's own hostname on its first report.")
	}
	fmt.Fprint(a.stderr, "Ingest token, shown once (install it on the host as /etc/heimdall/token, mode 0400):\n\n")
	fmt.Fprintln(a.stdout, token)
	return nil
}

func cmdHostList(a *app, args []string) error {
	fs := a.flags("host list", "[--org <org>]")
	org := fs.String("org", "", "only hosts in this organization")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	hosts, err := s.ListHosts(a.ctx, *org)
	if err != nil {
		return err
	}
	rows := make([][]string, len(hosts))
	for i, h := range hosts {
		rows[i] = []string{h.OrgSlug, h.EnvSlug, h.Name, strings.Join(h.Tags, ","), formatTime(h.LastSeenAt)}
	}
	return table(a, "ORG\tENV\tHOST\tTAGS\tLAST SEEN", rows)
}

func cmdHostRm(a *app, args []string) error {
	fs := a.flags("host rm", "--org <org> --yes <hostname>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	yes := fs.Bool("yes", false, "confirm: deletes the host, its tokens, snapshots and findings")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if !*yes {
		return fmt.Errorf("this permanently deletes %s with its tokens, snapshots and findings; re-run with --yes", pos[0])
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := a.defaultOrg(s, org); err != nil {
		return err
	}
	if err := s.RemoveHost(a.ctx, actor(), *org, pos[0]); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Removed host %s from org %s.\n", pos[0], *org)
	return nil
}

func cmdHostRename(a *app, args []string) error {
	fs := a.flags("host rename", "[--org <org>] <hostname> <new-name>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	pos, err := parse(fs, args, 2)
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
	if err := s.RenameHost(a.ctx, actor(), *org, pos[0], pos[1]); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Renamed %s to %s.\n", pos[0], pos[1])
	return nil
}
