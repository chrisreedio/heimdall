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
  migrate                      Apply database migrations (and config update)
  config update [--dry-run]    Add config sections for new features, off (backs up the file)
  serve                        Run the web UI, ingest listener and scheduled feed sync
  org  create|list             Manage organizations
  env  create|list --org       Manage environments within an org
  host add|list|show|rm|rename Manage hosts (add without a name to use the server's hostname)
  host history|diff            Snapshots over time and what changed between them
  drift <tag>                  Packages that differ across hosts with a tag
  sbom <hostname>              Export a host's inventory as a CycloneDX SBOM
  backup --to f --age-recipient k  Consistent, age-encrypted database backup
  anomaly list|ack|suppress    Tripwire alerts: review, acknowledge, mute a rule
  window add|list|rm           Maintenance windows (changes inside don't alert)
  host token --rotate          Issue a new ingest token for a host
  enroll create|list|revoke    Expiring keys that add many servers (each gets its own token)
  enroll pending|approve       Hosts enrolled with a key, waiting for an admin's approval
  user create|list|disable|enable|reset-totp|passwd
                               Manage web UI accounts (password + TOTP, or --entra)
  user grant|revoke            Give or remove a role (viewer, operator, admin) in an org
  user mcp-token create|list|revoke
                               Tokens for AI assistants on the read-only MCP endpoint
  import                       Store (or --check) a snapshot file
  collector trust|list         Manage known-good collector checksums
  feeds sync|status            Refresh OSV, KEV and end-of-life data now
  report                       Findings and lifecycle per host (text, JSON, CSV or HTML)
  notify preview|send          Show (with each destination's payload) or send the digest now
  notify test [destination]    Send a labelled test message (all destinations, or one)
  notify set-webhook <slack|discord|webhook> <name>
                               Store a Slack, Discord or webhook URL (never echoed)
  plan create|list|show|add|rm|done|undo|close
                               Patch plans: batch hosts, tick them off, auto-verify
  sso setup                    Set up Entra ID single sign-on (asks, writes, restarts)
  sso set-secret               Store or rotate the Entra client secret (never echoed)
  ai set-key|status|test       AI analysis with your Azure model: store the key (never echoed), show, test
  upgrade [--check]            Upgrade this hub to the latest release (sudo)
  restart                      Restart the hub (after config changes) and check it's up (sudo)
  ingest cert                  Install a certificate for public ingest, e.g. a Cloudflare Origin cert (sudo)
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
	"config":  group("config", map[string]command{"update": cmdConfigUpdate}),
	"org":     group("org", map[string]command{"create": cmdOrgCreate, "list": cmdOrgList}),
	"env":     group("env", map[string]command{"create": cmdEnvCreate, "list": cmdEnvList}),
	"host": group("host", map[string]command{
		"add": cmdHostAdd, "list": cmdHostList, "show": cmdHostShow, "rm": cmdHostRm, "token": cmdHostToken, "rename": cmdHostRename,
		"diff": cmdHostDiff, "history": cmdHostHistory,
	}),
	"enroll": group("enroll", map[string]command{"create": cmdEnrollCreate, "list": cmdEnrollList, "revoke": cmdEnrollRevoke,
		"pending": cmdEnrollPending, "approve": cmdEnrollApprove}),
	"collector": group("collector", map[string]command{"trust": cmdCollectorTrust, "list": cmdCollectorList}),
	"feeds":     group("feeds", map[string]command{"sync": cmdFeedsSync, "status": cmdFeedsStatus}),
	"report":    cmdReport,
	"drift":     cmdDrift,
	"sbom":      cmdSBOM,
	"backup":    cmdBackup,
	"anomaly":   group("anomaly", map[string]command{"list": cmdAnomalyList, "ack": cmdAnomalyAck, "suppress": cmdAnomalySuppress}),
	"window":    group("window", map[string]command{"add": cmdWindowAdd, "list": cmdWindowList, "rm": cmdWindowRm}),
	"notify": group("notify", map[string]command{"preview": cmdNotifyPreview, "send": cmdNotifySend,
		"test": cmdNotifyTest, "set-webhook": cmdNotifySetWebhook}),
	"plan": group("plan", map[string]command{
		"create": cmdPlanCreate, "list": cmdPlanList, "show": cmdPlanShow, "add": cmdPlanAdd,
		"rm": cmdPlanRm, "done": cmdPlanDone, "undo": cmdPlanUndo, "close": cmdPlanClose,
	}),
	"user": group("user", map[string]command{
		"create": cmdUserCreate, "list": cmdUserList, "disable": cmdUserDisable, "enable": cmdUserEnable,
		"reset-totp": cmdUserResetTOTP, "passwd": cmdUserPasswd, "grant": cmdUserGrant, "revoke": cmdUserRevoke,
		"mcp-token": group("user mcp-token", map[string]command{"create": cmdMCPTokenCreate, "list": cmdMCPTokenList, "revoke": cmdMCPTokenRevoke}),
	}),
	"sso":     group("sso", map[string]command{"setup": cmdSSOSetup, "set-secret": cmdSSOSetSecret}),
	"ai":      group("ai", map[string]command{"set-key": cmdAISetKey, "status": cmdAIStatus, "test": cmdAITest}),
	"upgrade": cmdUpgrade,
	"restart": cmdRestart,
	"ingest":  group("ingest", map[string]command{"cert": cmdIngestCert}),
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
	if err := asHubUser(*configPath, fs.Args()); err != nil {
		return err
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
