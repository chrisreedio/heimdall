# Deployment

> Choosing a machine? See [hosting.md](hosting.md) (VPS, local box, AWS, Azure).
>
> One Heimdall per organization. The hub is a single binary, a SQLite file and two loopback listeners.

## One-command install

**Hub** (fresh Debian/Ubuntu VM with Tailscale logged in):
```sh
curl -fsSLO https://github.com/chrisreedio/heimdall/releases/download/v0.4.0/install-hub.sh
sudo sh install-hub.sh --org acme --ingest-host ingest.acme.example.com --admin you@example.com --mcp
#   or --tailnet-only instead of --ingest-host if every server is on your tailnet
```
It downloads the verified release, creates the `heimdall-hub` user, config and database, starts the sandboxed service, publishes the UI (and MCP) with `tailscale serve`, and, with `--ingest-host`, installs Caddy to serve only the ingest path publicly. The ingest host's root (`GET /`) serves a blank splash page (just the logo, a strict CSP, no `Server` header); every other path is an empty 404. Re-running it is safe: it keeps the existing config and just migrates.

**New VM?** Paste [`deploy/cloud-init-hub.yaml`](../deploy/cloud-init-hub.yaml) as user data instead. It installs Tailscale and runs the same installer on first boot.

**Each server:** in the UI go to **Hosts → Add a host**. Heimdall registers the server and shows the token once, plus a ready-to-paste command for Linux, cloud-init or Windows:
```sh
curl -fsSLO https://github.com/chrisreedio/heimdall/releases/download/v0.4.0/install.sh && sudo sh install.sh --hub https://ingest.acme.example.com
#   paste the token when asked (never echoed or put on a command line)
```
The installers always come from the signed GitHub release, never from the hub, so a compromised hub can't push code to your servers. Set `ingest.public_url` (the installer does this for you) so the page shows the right address.

The sections below explain what the installers set up, if you'd rather do it by hand.

## Shape

```
servers ──HTTPS──▶ ingest (public, one path only) ─┐
                                                   ├─ heimdall serve ── /var/lib/heimdall/heimdall.db
you ──tailnet/VPN──▶ UI (private) ─────────────────┘
```

- **Ingest** is the only thing your servers reach. Heimdall terminates TLS itself (`ingest.tls_cert`/`tls_key`), or sits behind a local proxy (`behind_proxy = true`).
- **UI** always listens on loopback. Put HTTPS in front with one of the options below, and **never expose it publicly**.

## Option A: Tailscale (simplest)

```sh
sudo tailscale serve --bg 8080          # https://<hub>.<tailnet>.ts.net → 127.0.0.1:8080
```
Set `ui.base_url` to that `https://…ts.net` address. Only devices on your tailnet can reach the UI. For ingest, servers on the tailnet can use `tailscale serve --bg --tcp 8443`. Otherwise expose ingest with Caddy (option B).

## Option B: Caddy

[`deploy/Caddyfile.example`](../deploy/Caddyfile.example) proxies ingest publicly (only `/api/v1/ingest`) and serves the UI on a private interface, with automatic certificates. Set `ingest.behind_proxy = true` so rate limits and logs see real client IPs.

## Where to host it

See [hosting.md](hosting.md): a small VPS, a local box with Tailscale, AWS (Lightsail/EC2) or Azure (B-series VM), with step-by-step setup for each.

## Install

Follow the [quick start](../README.md#quick-start), then:

| Task | Command |
|---|---|
| First admin | `hd user create --admin you@example.com` |
| Entra SSO | Register an app (redirect `https://<ui>/auth/callback`), then run `sudo heimdall sso setup`: it asks for the tenant ID, client ID and secret (never echoed), writes `[auth.entra]`, the secret and the unit's `LoadCredential` line, and restarts the hub |
| Trust the collector release | `hd collector trust --version 0.3.0 <sha256 of collect.sh>` |
| Slack / Discord alerts and digest | `hd notify set-webhook slack ops` (or `discord alerts`), then `hd notify test`; see [Notifications](#notifications) |
| Email digest | Set `[notify]` email settings and add `LoadCredential=heimdall-smtp:…` |

(`hd` = `sudo heimdall`: on an installed hub it runs as `heimdall-hub` with `/etc/heimdall/heimdall.toml`)

## Backups

```sh
age-keygen -o heimdall-backup.key        # keep this offline; note the public key it prints
hd backup --to /var/backups/heimdall-$(date +%F).age --age-recipient age1…
# restore: age -d -i heimdall-backup.key backup.age > /var/lib/heimdall/heimdall.db
```
The plaintext copy exists only briefly, owner-only, and is removed on exit. Schedule this with a systemd timer or cron and ship the `.age` files off the box.

## Upgrades

Admins see a banner in the UI when a newer release exists. The hub checks GitHub once a day for the latest version number; turn this off with `[updates] check = false`. The hub never downloads or installs anything itself.

**Upgrade the hub** with one command:
```sh
sudo heimdall upgrade            # or: heimdall upgrade --check
```
It finds the latest release (or `--version vX.Y.Z`), checks that release's `install-hub.sh` against its `SHA256SUMS`, and runs it. Flags after `--` go to the installer. Without Heimdall's command, the same thing by hand:
```sh
curl -fsSLO https://github.com/chrisreedio/heimdall/releases/download/vX.Y.Z/install-hub.sh
sudo sh install-hub.sh
```
The installer verifies the release, then:
1. Stops the hub and keeps the previous binary (`/usr/local/bin/heimdall.previous`) and a pre-upgrade copy of the database (`heimdall.db.pre-upgrade`, owner-only).
2. Installs the new binary and unit, runs migrations, starts the hub, and checks that it answers.
3. **Rolls back automatically** (old binary and old database) if any step fails.
4. Trusts the release's collector checksum, so servers that update don't raise "collector changed" anomalies.

Your config, data, Tailscale and Caddy settings and the unit's `LoadCredential` lines are kept. If the new version doesn't come up, its log is printed before the rollback.

**Upgrade servers** after the hub, with one command on each:
```sh
sudo heimdall-collect upgrade
```
It asks the hub which release it runs (an authenticated request on the ingest URL), downloads that release's `install.sh` from GitHub, checks it against the release's `SHA256SUMS`, and reinstalls with the same hub, token and settings. Collectors never upgrade past the hub. `sudo heimdall-collect upgrade vX.Y.Z` picks a release yourself. A collector that's behind says so on each push (in its log), and the host page shows "update available". Collectors from before v0.4.12 don't have the command yet: re-run `install.sh` once with `--token-file /etc/heimdall/token`.

For many servers, a loop is enough:
```sh
for h in web-01 web-02 db-01; do ssh "$h" sudo heimdall-collect upgrade; done
```

## Threat news

Heimdall can cross-reference a curated "being exploited right now" incident feed with your hosts' findings, so the dashboard says "2 in the news affect your hosts" and the News page lists what's happening. It's off by default, because the hub makes no outbound calls you haven't turned on. Turn it on in `heimdall.toml` and restart:

```toml
[news]
enabled  = true
sources  = ["https://pwn.watch/incidents.json"]   # the default
interval = "1h"
```

The default source is [pwn.watch](https://pwn.watch), which publishes its incidents as JSON. Items credit their source ("via pwn.watch", linking to the incident), and the hub fetches at most hourly, respecting caching headers. Any https feed in the same shape can be added. Matching happens on the hub: nothing about your servers is sent. Run `heimdall feeds sync` to fetch now and `heimdall feeds status` to see how the last fetch went. A broken feed keeps the last good copy and never blocks the other feeds. See [threat-news.md](threat-news.md) for how matching works.

## Notifications

Heimdall sends two kinds of message, to every destination you turn on (several at once is fine, for example Slack and Discord):

- **Immediate alerts:** a host went silent (`[hosts] alert_after`, default 3h) and, later, is back; and new high-signal anomalies: change reporting disabled, privilege watch disabled, privileged access outside a maintenance window, and anything high severity (collector changed, package downgraded, packages vanished, a replayed report). New anomalies are checked every 30 seconds and sent as one message. `[notify] alert_anomalies = false` keeps only the silence alerts.
- **The digest** (`[notify] every`, e.g. `"24h"`): counts only.

**What's in a message.** Counts, `org/host` names and a fixed label per rule ("privilege watch disabled"), with a link to the hub (`[ui] base_url`, sign-in required). Never package names, versions, CVEs, user names, inventory or an anomaly's own summary. The digest has no host names at all.

**Discord bots can read alerts.** Anyone and any bot in the channel sees the messages, so they are designed to be safe to share: the content above, and nothing in them can ping anyone. Discord messages carry `allowed_mentions: {"parse": []}`, and host names are shown as code with every `@` neutralised, so a host called `@everyone` can't ping. Slack messages escape `&`, `<` and `>`, so `<!channel>` in a name is shown, not parsed.

### Slack

1. In Slack, create an app for your workspace (api.slack.com/apps, "From scratch"), open **Incoming Webhooks**, turn it on, and **Add New Webhook to Workspace** for the channel. Copy the URL, `https://hooks.slack.com/services/T…/B…/…`. ([Slack's guide](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks))
2. On the hub:
   ```sh
   sudo heimdall notify set-webhook slack ops   # paste the URL; it's never echoed
   sudo heimdall notify test slack:ops          # a clearly labelled test message
   sudo heimdall restart
   ```

Messages use [Block Kit](https://docs.slack.dev/block-kit) (a header, a section, a context line with the link) with a plain `text` fallback for notifications.

### Discord

1. In Discord, open the channel's **Edit Channel** (the cog), then **Integrations**, **Webhooks**, **New Webhook**. Name it (for example "Heimdall") and **Copy Webhook URL**, `https://discord.com/api/webhooks/<id>/<token>`. ([Discord's docs](https://docs.discord.com/developers/resources/webhook))
2. On the hub:
   ```sh
   sudo heimdall notify set-webhook discord alerts
   sudo heimdall notify test discord:alerts
   sudo heimdall restart
   ```

Messages are one embed, coloured by severity: red for silent hosts, high-severity anomalies and a digest with known-exploited or critical findings, orange for other anomalies and digests, green for "back" and a quiet digest, blurple for a test. URLs copied from `discordapp.com` or the PTB and Canary clients are accepted and stored as `discord.com`.

### Commands

| Command | What it does |
|---|---|
| `sudo heimdall notify set-webhook <slack\|discord\|webhook> <name>` | Asks for the URL with echo off (`--stdin` to pipe it), checks it (Slack: `https://hooks.slack.com/services/…`; Discord: `https://discord.com/api/webhooks/…`; `webhook`: any https URL, sent the raw JSON), stores it in `/etc/heimdall/notify-<kind>-<name>` (mode 0600), adds `LoadCredential=heimdall-notify-<kind>-<name>:…` to the unit and `"<kind>:<name>"` to `[notify] destinations`. Run it again to rotate the URL. |
| `heimdall notify test [destination]` | Sends a test message to every destination, or one (`slack:ops`, `discord`, `email`), and prints OK or the error for each. |
| `heimdall notify preview [--alert silent\|back\|anomaly\|test]` | Prints the digest (or an example alert), then each destination's exact payload, with the URL redacted. Sends nothing. |
| `heimdall notify send` | Sends the digest now. |

**Webhook URLs are credentials** (anyone with one can post to your channel), so they are never in `heimdall.toml`: the config only lists which destinations are on. The original `webhook = true` setting (URL in the `heimdall-webhook` credential, `webhook_format = "slack"` or `"json"`) keeps working; `set-webhook` is the preferred way now. Email works as before.

**Delivery.** Each destination may only reach its own host over HTTPS (`hooks.slack.com`, `discord.com`, or a generic webhook's host). Destinations are sent to in parallel, so a slow or broken one never delays the others, and ingest never waits on any of them. A failed send is retried with backoff (4 tries), honouring a 429's `Retry-After` (Slack allows about one message per second per webhook, see [rate limits](https://docs.slack.dev/apis/web-api/rate-limits); Discord's are [here](https://docs.discord.com/developers/topics/rate-limits)); a 4xx such as a deleted webhook isn't retried. Failures are logged by destination name, never with the URL. A silence alert that no destination took is retried on the next check; one that reached some destinations isn't resent.

## AI analysis

Heimdall can write a daily brief per org and explain a host's findings using **your own** Azure AI Foundry / Azure OpenAI model deployment. It's off by default. To turn it on, set `[ai]` (`enabled`, `endpoint`, `deployment`), then:

```sh
sudo heimdall ai set-key     # the key, never echoed; adds LoadCredential=heimdall-ai to the unit
sudo heimdall ai test        # one tiny request: HTTP status and latency
sudo heimdall restart
```

Compact facts about your hosts (names, OS, package names and versions, CVEs, counts) are sent to that endpoint. [ai.md](ai.md) lists exactly what, and how the output is checked. Nothing a model says is ever run.

## Hardening checklist

- [ ] UI reachable only over the tailnet/VPN
- [ ] Ingest has TLS; consider `ingest.allow_cidrs`
- [ ] Disk or volume encryption on the hub
- [ ] Encrypted backups shipped off-box
- [ ] `auth.local_login = false` once SSO works (break-glass via the CLI)
- [ ] Egress limited to the feed hosts (firewall or proxy): `api.osv.dev`, `www.cisa.gov`, `endoflife.date`, `api.first.org`, `api.github.com` (update check), `login.microsoftonline.com` with SSO, your `[news]` source hosts (e.g. `pwn.watch`) if threat news is on, your `[ai]` endpoint's host if AI analysis is on, and `hooks.slack.com` / `discord.com` (or your webhook's host) for the notify destinations you use
