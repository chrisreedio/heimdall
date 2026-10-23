// SPDX-License-Identifier: AGPL-3.0-or-later

// Command heimdall is the Heimdall hub: CLI, web UI and ingest API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	_ "time/tzdata" // maintenance windows need timezones even on minimal hosts
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	restrictUmask()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
	case errors.Is(err, errUsage):
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, "heimdall:", err)
		os.Exit(1)
	}
}

const usage = `Heimdall — server inventory and patch status across organizations.

Usage:
  heimdall [-c heimdall.toml] <command> [flags]

Commands:
  init                         Create config and database
  migrate                      Apply database migrations
  serve                        Run the web UI, ingest listener and scheduled feed sync
  org  create|list             Manage organizations
  env  create|list --org       Manage environments within an org
  host add|list|show|rm        Manage hosts
  host history|diff            Snapshots over time and what changed between them
  drift <tag>                  Packages that differ across hosts with a tag
  sbom <hostname>              Export a host's inventory as a CycloneDX SBOM
  backup --to f --age-recipient k  Consistent, age-encrypted database backup
  anomaly list|ack|suppress    Tripwire alerts: review, acknowledge, mute a rule
  window add|list|rm           Maintenance windows (changes inside don't alert)
  host token --rotate          Issue a new ingest token for a host
  user create|list|disable|enable|reset-totp|passwd
                               Manage web UI accounts (password + TOTP, or --entra)
  user grant|revoke            Give or remove a role (viewer, operator, admin) in an org
  user mcp-token create|list|revoke
                               Tokens for AI assistants on the read-only MCP endpoint
  import                       Store (or --check) a snapshot file
  collector trust|list         Manage known-good collector checksums
  feeds sync|status            Refresh OSV, KEV and end-of-life data now
  report                       Findings and lifecycle per host (text, JSON, CSV or HTML)
  notify preview|send          Show or send the counts-only digest now
  plan create|list|show|add|rm|done|undo|close
                               Patch plans: batch hosts, tick them off, auto-verify
  sso set-secret               Store the Entra client secret (prompted, never echoed)
  version                      Print version

The config path can also be set with HEIMDALL_CONFIG.
Run 'heimdall <command> -h' for command flags.
`

// errUsage signals that a usage message was already printed.
var errUsage = errors.New("usage")

type app struct {
	ctx        context.Context
	configPath string
	stdout     io.Writer // command output, safe to pipe
	stderr     io.Writer // messages for humans
}

type command func(a *app, args []string) error

var commands = map[string]command{
	"init":    cmdInit,
	"migrate": cmdMigrate,
	"org":     group("org", map[string]command{"create": cmdOrgCreate, "list": cmdOrgList}),
	"env":     group("env", map[string]command{"create": cmdEnvCreate, "list": cmdEnvList}),
	"host": group("host", map[string]command{
		"add": cmdHostAdd, "list": cmdHostList, "show": cmdHostShow, "rm": cmdHostRm, "token": cmdHostToken,
		"diff": cmdHostDiff, "history": cmdHostHistory,
	}),
	"collector": group("collector", map[string]command{"trust": cmdCollectorTrust, "list": cmdCollectorList}),
	"feeds":     group("feeds", map[string]command{"sync": cmdFeedsSync, "status": cmdFeedsStatus}),
	"report":    cmdReport,
	"drift":     cmdDrift,
	"sbom":      cmdSBOM,
	"backup":    cmdBackup,
	"anomaly":   group("anomaly", map[string]command{"list": cmdAnomalyList, "ack": cmdAnomalyAck, "suppress": cmdAnomalySuppress}),
	"window":    group("window", map[string]command{"add": cmdWindowAdd, "list": cmdWindowList, "rm": cmdWindowRm}),
	"notify":    group("notify", map[string]command{"preview": cmdNotifyPreview, "send": cmdNotifySend}),
	"plan": group("plan", map[string]command{
		"create": cmdPlanCreate, "list": cmdPlanList, "show": cmdPlanShow, "add": cmdPlanAdd,
		"rm": cmdPlanRm, "done": cmdPlanDone, "undo": cmdPlanUndo, "close": cmdPlanClose,
	}),
	"user": group("user", map[string]command{
		"create": cmdUserCreate, "list": cmdUserList, "disable": cmdUserDisable, "enable": cmdUserEnable,
		"reset-totp": cmdUserResetTOTP, "passwd": cmdUserPasswd, "grant": cmdUserGrant, "revoke": cmdUserRevoke,
		"mcp-token": group("user mcp-token", map[string]command{"create": cmdMCPTokenCreate, "list": cmdMCPTokenList, "revoke": cmdMCPTokenRevoke}),
	}),
	"sso":     group("sso", map[string]command{"set-secret": cmdSSOSetSecret}),
	"serve":   cmdServe,
	"import":  cmdImport,
	"version": func(a *app, _ []string) error { _, err := fmt.Fprintln(a.stdout, version); return err },
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("heimdall", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	configPath := fs.String("c", envOr("HEIMDALL_CONFIG", "heimdall.toml"), "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return errUsage
	}
	cmd, ok := commands[fs.Arg(0)]
	if !ok {
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", fs.Arg(0), usage)
		return errUsage
	}
	return cmd(&app{ctx: ctx, configPath: *configPath, stdout: stdout, stderr: stderr}, fs.Args()[1:])
}

// group dispatches "<name> <sub> ..." to a subcommand.
func group(name string, subs map[string]command) command {
	return func(a *app, args []string) error {
		if len(args) == 0 || subs[args[0]] == nil {
			fmt.Fprintf(a.stderr, "usage: heimdall %s <%s>\n", name, joinKeys(subs))
			return errUsage
		}
		return subs[args[0]](a, args[1:])
	}
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}
