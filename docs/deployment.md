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
It downloads the verified release, creates the `heimdall-hub` user, config and database, starts the sandboxed service, publishes the UI (and MCP) with `tailscale serve`, and, with `--ingest-host`, installs Caddy to serve only the ingest path publicly. Re-running it is safe: it keeps the existing config and just migrates.

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
| Digest | Set `[notify]` and add `LoadCredential=heimdall-smtp:…` or `heimdall-webhook:…` |

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

**Upgrade servers** by re-running `install.sh` from the new release on each one. The **Hosts → Add a host** page shows the current command, and you can skip the token prompt with `--token-file /etc/heimdall/token`.

## Hardening checklist

- [ ] UI reachable only over the tailnet/VPN
- [ ] Ingest has TLS; consider `ingest.allow_cidrs`
- [ ] Disk or volume encryption on the hub
- [ ] Encrypted backups shipped off-box
- [ ] `auth.local_login = false` once SSO works (break-glass via the CLI)
- [ ] Egress limited to the feed hosts (firewall or proxy): `api.osv.dev`, `www.cisa.gov`, `endoflife.date`, `api.first.org`, `api.github.com` (update check), and `login.microsoftonline.com` with SSO
