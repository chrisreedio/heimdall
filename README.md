<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/heimdall-dark.svg">
    <img src="docs/assets/heimdall-light.svg" alt="Heimdall" width="420">
  </picture>
</p>

# Heimdall

> *The watchman of the gods sees everything across all nine realms, and touches nothing.*

Heimdall is a small, self-hosted tool for keeping an inventory of an organization's servers. It records what is installed on each one (OS, packages, runtimes, containers), checks those versions against public vulnerability and end-of-life data, and shows you **what needs updating, where, and how urgently**.

The expected setup is **one install per organization**, so each org's inventory, tokens and users stay completely separate. A single install can still hold several orgs if that suits you, for example as a small MSP.

It's meant for people who look after a handful to a few hundred servers spread across clients, employers and personal projects, and who want one honest view of patch status without running an enterprise vulnerability-management platform.

**Status:** pre-1.0. Milestones M0–M11 are implemented. The remaining steps before 1.0 are an independent security review and a run on real servers.

**Guides:** [Getting started](docs/getting-started.md) · [Hosting](docs/hosting.md) · [Deployment](docs/deployment.md) · [MCP](docs/mcp.md) · [Collector](docs/collector.md) · [Snapshot format](docs/snapshot-format.md) · [Anomaly signals](docs/anomaly-signals.md)

---

## Security first

Heimdall's database lists every weak spot in every server you manage, which makes the tool itself an attractive target. It's designed so that **a fully compromised hub gives an attacker that list and nothing else**: no access to the servers and no way to push code to them.

### Core principles

1. **The hub is a sink, not a controller.** Servers push data to the hub. The hub never connects to a server, holds no SSH keys or server credentials, and has no feature that runs anything remotely, not even as an opt-in.
2. **The hub never serves code to servers.** The collector script is installed from the git repo and its checksum is verified. It is never downloaded from the hub, so a compromised hub can't turn itself into a malware distribution point.
3. **Ingest is a one-way, write-only channel.** A host's token can append snapshots for that host only. It can't read anything, and the collector ignores whatever the hub sends back apart from the HTTP status code.
4. **Everything sent by servers is untrusted input.** A compromised server can send anything it likes, so payloads get strict size limits, schema validation and normalization, and are escaped on output.
5. **The UI is private by default.** The web UI and the ingest API listen on separate ports. Only ingest is meant to be reachable from your servers. The UI should sit behind a VPN or tailnet.
6. **Least privilege everywhere.** The collector runs as an unprivileged user. The hub runs as a sandboxed, non-root systemd service with a read-only filesystem apart from its data directory.
7. **Small, auditable code.** The hub is one Go binary with only a few dependencies and no shell-outs, plugins or templating of user input into commands. The collector is a short POSIX shell script you can read in full in five minutes.

### Threat model at a glance

| If an attacker gets… | They can… | They cannot… |
|---|---|---|
| **The hub** (full RCE / DB theft) | Read the inventory and findings, and forge or delete records | Log into or run code on any server, or push code to collectors |
| **One server** (and its ingest token) | Send fake inventory for *that* host, or try to attack the ingest parser | Read any data, affect other hosts or orgs, or reach the UI |
| **A user account** (viewer/operator) | See the orgs that account is granted | See other orgs, or create users or tokens (without admin) |
| **An Entra ID account in an allowed tenant** (not pre-provisioned in Heimdall) | Complete the Microsoft sign-in | Get in. Users must be provisioned in Heimdall first, and new users start with no org access. |
| **The network path** | Nothing useful, because everything goes over TLS | Read or alter snapshots in transit |
| **A feed provider** (OSV/KEV/etc.) | Return bad advisory data, causing wrong findings | Learn your hostnames or IPs, since only package and version tuples are sent |

These risks are knowingly accepted to keep things simple:
- A compromised server can lie about itself. Heimdall reports what hosts say they run. It raises [anomaly signals](docs/anomaly-signals.md) that catch sloppy attacks and unplanned changes, but it is a patching aid, not an intrusion detection system.
- A full hub compromise exposes the inventory, i.e. a map of your weak spots. To limit this, keep the UI private, use disk encryption and encrypted backups, and run one install per organization (the default setup), so a breach exposes only that org.

---

## Goals

- **Minimal attack surface and minimal dependencies.** The hub is one static binary plus one SQLite file. The collector is a POSIX shell script. There's no Node build step, no Redis, no message queue and no long-running agent.
- **One install per organization.** Each org gets its own hub, database and keys, so nothing is shared between orgs. Orgs still exist in the data model, so one install *can* hold several, and `--org` is optional when there's only one.
- **Strictly read-only.** Heimdall observes and advises. It has no way to change a server.
- **Defensive focus.** It answers "am I exposed, and what do I patch first?" It never scans or probes anything.
- **Boring to operate.** It runs fine on a $5 VPS, and a backup is one file.

## Non-goals

- Agentless pull over SSH, or any other hub → server connection (see [why](#why-no-ssh-pull-mode))
- Remote command execution or automated patching
- Network or port scanning
- Being a full CMDB, ticketing system or monitoring platform
- Full intrusion detection (HIDS/EDR). Heimdall's anomaly signals are tripwires, not a replacement for tools like auditd, AIDE, osquery or Wazuh.

---

## Features

### Inventory
- **Organizations → Environments → Hosts**, plus free-form tags (`prod`, `web`, `client:acme`)
- OS name and version, kernel, architecture, uptime, last boot
- Installed system packages and their versions:
  - `dpkg` (Debian, Ubuntu)
  - `rpm` (RHEL, Rocky, Alma, Fedora, Amazon Linux)
  - `apk` (Alpine)
  - `pacman` (Arch), on a best-effort basis
- Pending updates, with security updates flagged separately where the package manager exposes it
- Whether a reboot is required
- Language runtimes: PHP, Node.js, Python, Ruby, Go, Java
- Common services: nginx, Apache, MySQL/MariaDB, PostgreSQL, Redis, OpenSSH, Docker
- Docker containers and images (name, image, tag, digest), if the collector user is allowed to query Docker
- **Laravel / PHP sites:** each site the web server serves (domains, document root, PHP-FPM version), its Laravel version and every Composer package from `composer.lock`. See [Sites & Laravel](#sites--laravel).
- Optional application lockfiles (`package-lock.json`, `requirements.txt`) from an allowlist of paths you configure *on the host*
- Snapshot history, so you can see what changed on a host between two check-ins

**Never collected:** environment variables, `.env` files, config file contents, secrets, keys, users and groups, process arguments, shell history or any file not explicitly allowlisted. Site discovery reads web server vhost files but only reports the fields listed under [Sites & Laravel](#sites--laravel).

**Never collected, even with the privilege watch:** users and commands. The opt-in [privilege watch](docs/collector.md#privilege-watch) (`install.sh --watch-privilege`) records only *when* sudo, su or a root SSH login happened and which of the three it was; usernames only with a second opt-in, `--watch-privilege-users`. Root can remove it, like anything else on the box, but removing it while the host still reports raises **privilege watch disabled**, and removing the collector raises **silence**.

### Sites & Laravel
Most PHP apps are a site on a shared box, so Heimdall inventories **sites**, not just packages.

- **Discovery:** enabled nginx and Apache vhosts (`sites-enabled/`, `conf.d/`), which covers Forge and Ploi layouts, plus any app roots you list in `/etc/heimdall/collect.conf`
- **Per site:** server names, document root, app root, web server, and the **PHP-FPM version serving it** (read from the `fastcgi_pass` / `SetHandler` socket, e.g. `php8.3-fpm.sock`)
- **Laravel:** framework version and the PHP requirement from `composer.json`/`composer.lock`, plus the last deploy time (the `composer.lock` modification time)
- **Composer packages:** every package in `composer.lock`, matched against OSV's Packagist advisories, so findings are reported **per site**
- **PHP on the host:** every installed PHP version (CLI and FPM), taken from the package list
- **End of life:** EOL warnings for both PHP and Laravel versions
- **Fleet questions:** e.g. "which sites still run Laravel 9?", "which sites are served by PHP 8.1?", or "where is `laravel/framework` < 11.31 deployed?"

**Never done:** reading `.env`, running `artisan`, `php` or `composer`, or executing any app code. Heimdall only reads `composer.json` and `composer.lock`. The collector user needs read access to just those two files, granted with an ACL or group membership. It never needs access to the whole app.

### Vulnerability & lifecycle checks
- Matches package versions against **[OSV.dev](https://osv.dev)**, which aggregates the Debian, Ubuntu, Alpine, Red Hat, Rocky, Alma, npm, Packagist, PyPI and other advisory feeds
- Flags CVEs listed in **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** (Known Exploited Vulnerabilities)
- Optional **[EPSS](https://www.first.org/epss/)** scores to help rank what to fix first
- End-of-life warnings for operating systems and runtimes via **[endoflife.date](https://endoflife.date)**
- Feeds are synced into a local cache. Outbound requests go only to a fixed allowlist of feed hosts and contain only `(ecosystem, package, version)` tuples.

### Fleet views
- **Dashboard:** hosts by risk, KEV hits, EOL systems, hosts with pending reboots, and stale hosts that haven't checked in for N days
- **Search:** queries such as "every host running `openssl` < `3.0.13`" or "which hosts still have PHP 8.1?"
- **Reports:** a summary you can print or export (per org on multi-org installs)
- **Drift:** compare hosts that should match, e.g. all `web` nodes in `prod`
- Export to CSV or JSON

### Anomaly signals (tripwires)
Heimdall looks for patterns in the snapshots it already collects that are hard to fake consistently. It needs no extra data and no extra privileges.
- Hosts that go silent
- Replayed snapshots or implausible timestamps
- Packages installed, removed or downgraded outside a patch plan or maintenance window
- A kernel change without a reboot, or a reboot outside a maintenance window
- The collector's version or checksum changing unexpectedly
- New services, runtimes or packages that a host's peers don't have
- [Reports that don't add up](docs/anomaly-signals.md#reports-that-dont-add-up) against the host's own history: uptime growing faster than time passes, an inventory reverting to an older one, a sudden big drop in packages, a collector downgrade, or a different OS

See [docs/anomaly-signals.md](docs/anomaly-signals.md) for what each signal means, its innocent explanations, and what to do when one fires.

### Update assistance (advisory only)
- A per-host list of pending updates, sorted by KEV status, severity and EPSS
- Commands for each host that **you** copy and run (`apt-get install --only-upgrade …`, `dnf upgrade --advisory …`)
- "Patch plans" that group hosts into batches you can work through and tick off
- Verification: the next check-in confirms the vulnerable version is gone

---

## Architecture

```
   Private network / tailnet only               Reachable by your servers
  ┌───────────────────────────────┐         ┌──────────────────────────────┐
  │  UI listener   127.0.0.1:8080 │         │  Ingest listener  :8443      │
  │  (admins, behind VPN + TLS)   │         │  POST /ingest only           │
  └───────────────┬───────────────┘         └──────────────┬───────────────┘
                  │        heimdall (one binary, sandboxed) │
                  └──────────────┬──────────────────────────┘
                                 │
                     SQLite (heimdall.db)  ◄── feed sync (outbound, allowlisted:
                                                OSV, KEV, EPSS, endoflife.date)
                                 ▲
        ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
          one-way HTTPS push     │      (hub never initiates connections)
                 ┌───────────────┼────────────────┐
          ┌──────┴──────┐ ┌──────┴──────┐  ┌──────┴──────┐
          │ collect.sh  │ │ collect.sh  │  │ host.json   │
          │ timer, user │ │ timer, user │  │ manual      │
          │ heimdall    │ │ heimdall    │  │ import      │
          │  (Org A)    │ │  (Org B)    │  │ (air-gap)   │
          └─────────────┘ └─────────────┘  └─────────────┘
```

### Collection modes

| Mode | How it works | Good for |
|---|---|---|
| **Push** | A systemd timer or cron runs `collect.sh` as the unprivileged `heimdall` user and POSTs the snapshot over TLS with that host's token | Most servers |
| **Import** | Run the script yourself and upload the JSON through the UI or with `heimdall import`, e.g. `ssh web-01 sh -s < collect.sh > web-01.json` from *your* machine | Air-gapped servers, locked-down client boxes, or "install nothing" |

Import mode covers the agentless use case while SSH access stays with **you**. The hub never gets it.

#### Why no SSH pull mode?
Pull mode would mean the hub holds SSH credentials to every server in every org, so one hub compromise would become a compromise of the whole fleet. Restricted `authorized_keys` commands reduce that risk but don't remove it. Push mode costs one small cron job per server, and in exchange Heimdall can be fully compromised without any server being touched.

### The collector
Supported platforms: **Ubuntu 22.04/24.04, Debian 12, Rocky 9, AlmaLinux 9 and Alpine 3.20**, all tested in CI. RHEL 9 uses the same tooling but isn't tested. See [docs/collector.md](docs/collector.md) for its full list of security properties, installation and troubleshooting.

- POSIX `sh`, a few hundred lines, with no network calls except the single POST
- Needs only coreutils, `awk`, the host's package manager, and `curl` for push mode. It reads the existing package metadata cache and never refreshes it, so leave `apt-daily`/`dnf-makecache` enabled.
- Runs as a dedicated unprivileged `heimdall` user, never as root. Checks that need privileges are skipped and reported as "unavailable".
- Installed from a tagged release, with its SHA-256 checksum and signature verified, **never from the hub**
- Pins the hub's TLS certificate or a private CA if you want (`HEIMDALL_CA_FILE`)
- Ignores the response body completely, so the hub can't send instructions back
- Token is read from a `0400` file owned by the `heimdall` user, never passed on the command line
- Reports hourly, 3 minutes after boot and about a minute after packages change (a systemd path unit, or apk/apt hooks without systemd), so the hub's tripwires see changes within minutes. A sudoers-limited one-liner reports after deploys. See [When it reports](docs/collector.md#when-it-reports).

---

## Hub hardening

### Network
- **Two listeners:** the UI binds to `127.0.0.1` or a tailnet/WireGuard interface by default. The ingest listener exposes `POST /api/v1/ingest` and nothing else, not even a health page or static files.
- Use TLS everywhere, terminated by Heimdall or a reverse proxy (Caddy/nginx).
- Optionally allowlist ingest source IPs or CIDRs (`ingest.allow_cidrs`).
- Outbound traffic: only the feed hosts, `login.microsoftonline.com` (if SSO is enabled) and the `[news]` source hosts (if threat news is on, in their own allowlist), ideally enforced with a host firewall (`IPAddressAllow=` in systemd).

### Ingest
- Request bodies are capped (default 5 MB), decompressed with a cap, and parsed with a strict JSON decoder that rejects unknown fields
- Every field is validated and normalized: lengths, character sets, version formats
- Rate-limited per token and per IP. Failed authentication attempts are logged.
- Tokens are 256-bit random values, stored as SHA-256 hashes, scoped to one host, and revocable. Rotate them with `heimdall host token --rotate`.
- Snapshots are append-only, so a host can't edit or delete its own history. A report with an unchanged inventory is stored as a small heartbeat instead of a new snapshot.

### Web UI
- **Microsoft Entra ID (Azure AD) SSO** via OpenID Connect. See [Single sign-on](#single-sign-on-microsoft-entra-id).
- **Local accounts** with **argon2id** password hashes and **mandatory TOTP**. These are meant for break-glass admin access and can be disabled entirely once SSO is working.
- Session cookies use `Secure`, `HttpOnly`, `SameSite=Strict`, idle and absolute timeouts, and the `__Host-` prefix
- CSRF tokens on every state-changing request
- Server-rendered `html/template` escapes output automatically. There is **no inline JS**, and the strict CSP is `default-src 'self'; frame-ancestors 'none'; form-action 'self'`.
- Standard security headers: HSTS, `X-Content-Type-Options`, `Referrer-Policy: same-origin` (nothing leaks to other sites)
- Login throttling and lockout
- Roles (`viewer`, `operator`, `admin`). On an install that holds several orgs, roles are scoped per org, enforced in the data-access layer and not just in handlers.
- An **audit log** records logins, failed logins, token creation and rotation, and user and org changes

### Single sign-on (Microsoft Entra ID)
Heimdall acts as a confidential OIDC client using the **authorization code flow with PKCE**. Only one provider is supported, so the flow is implemented with the standard library (`crypto/rsa`, `encoding/json`) rather than a general OIDC library.

- **App registration:** use a single-tenant registration in the organization's own tenant, which is the usual case. A multi-tenant registration restricted by `allowed_tenants` is only needed if outside accounts, such as a contractor's, must sign in. The redirect URI is `https://<ui base_url>/auth/callback`. It only has to be reachable from your browser, so a tailnet hostname works.
- **ID token validation:** the signature is checked against Entra's JWKS (keys cached, refetched for unknown `kid`, RS256 only). The token must also pass all of these checks:
  - `iss` matches the tenant
  - `aud` equals the client ID
  - `exp`/`nbf`/`iat` are valid, with small clock skew allowed
  - `nonce` matches the session
  - `tid` is in `allowed_tenants`
- **Identity:** users are keyed by the immutable **`tid` + `oid`** pair, never by email or UPN, which can change or be reused.
- **No silent self-signup:** an Entra user has to be provisioned in Heimdall first, either by `oid` or by an email that is bound to the `oid` on first login, and only within an allowed tenant. Unknown users are rejected, and the rejection is logged.
- **Roles:** granted in Heimdall, or optionally mapped from Entra **app roles** in the token (`Heimdall.Admin`, `Heimdall.Operator`, `Heimdall.Viewer`). Per-org role names such as `Heimdall.Org.acme.Viewer` only matter on multi-org installs. Group claims aren't used, because of the group overage limit.
- **MFA and device policy:** enforced on the Entra side through Conditional Access. Heimdall doesn't ask for TOTP again for SSO users.
- **Credentials:** a client secret or certificate is loaded from systemd credentials, never from the config file. A certificate is preferred. `sudo heimdall sso setup` walks through it: it shows the redirect URI to register, asks for the IDs and the secret (echo off), writes the config, the secret (`/etc/heimdall/entra-secret`, owner-only) and the unit's `LoadCredential` line, and restarts the hub. `heimdall sso set-secret` rotates the secret.
- **Sessions:** a Heimdall session is created after login and is limited by the same idle and absolute timeouts. No refresh tokens are kept, and Heimdall calls no Graph APIs and requests only the `openid profile email` scopes.

### Process & host
- Runs as the dedicated non-root `heimdall-hub` user with systemd sandboxing, so admin CLI commands can run as the same user against the same database. [`deploy/heimdall.service`](deploy/heimdall.service) is provided, and `systemd-analyze security` rates it 1.4 (OK). Key settings:
  ```ini
  NoNewPrivileges=yes
  ProtectSystem=strict
  ProtectHome=yes
  PrivateTmp=yes
  PrivateDevices=yes
  ReadWritePaths=/var/lib/heimdall
  CapabilityBoundingSet=
  RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
  SystemCallFilter=@system-service
  MemoryDenyWriteExecute=yes
  ```
- No `os/exec`, plugins, or dynamic code loading anywhere in the hub
- Database file is `0600`. Use full-disk or volume encryption on the host.
- `heimdall backup` writes a consistent snapshot, encrypted with [age](https://age-encryption.org) to a recipient you choose

### Supply chain
- **Few direct Go dependencies** (see below), vendored and reviewed when bumped
- `govulncheck`, `go vet` and `staticcheck` run in CI
- Reproducible builds (`-trimpath`, pinned toolchain), with release checksums signed via minisign or cosign
- The collector is plain text, so you can diff it between releases before upgrading

---

## Tech stack

| Piece | Choice | Why |
|---|---|---|
| Hub | Go standard library (`net/http`, `html/template`, `crypto/*`, `embed`) | Single static binary, memory-safe, easy to sandbox |
| Database | SQLite via [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite) | Pure Go, no CGO, one file |
| Password hashing | `golang.org/x/crypto/argon2` | Maintained by the Go team |
| Config | [`github.com/BurntSushi/toml`](https://github.com/BurntSushi/toml) | Small and stable. The standard library has no TOML parser. |
| SSO | Standard library OIDC client (Entra ID only) | One provider doesn't justify a JOSE/OIDC dependency tree |
| Backups | [`filippo.io/age`](https://github.com/FiloSottile/age) | Well-reviewed modern file encryption; backups are encrypted to your age public key |
| UI | Server-rendered HTML, one CSS file, a little vanilla JS from `'self'` | No bundler, no `node_modules`, strict CSP possible |
| Collector | POSIX `sh` | Runs anywhere and can be audited at a glance |

Direct dependencies: **five** (SQLite, x/crypto, TOML, filippo.io/age for encrypted backups and rsc.io/qr for the TOTP enrollment QR code). TOTP, OIDC, CSRF, rate limiting and sessions are implemented with the standard library.

---

## Quick start

**The fast way:** run `install-hub.sh` on a fresh VM, then use **Hosts → Add a host** in the UI to get a one-line install command for each server. See [docs/deployment.md](docs/deployment.md#one-command-install). The manual steps below do the same thing by hand.

> The hub and collector below work today (M1). The web UI and user accounts arrive in M3.

All files come from a [release](../../releases): the `heimdall-linux-*` binaries, `collect.sh`, the `deploy/` units and `SHA256SUMS`. Verify every download first:

```sh
sha256sum -c --ignore-missing SHA256SUMS
```

### Hub (one per organization)
```sh
sudo useradd --system --home-dir /var/lib/heimdall --shell /usr/sbin/nologin heimdall-hub
sudo install -m 0755 heimdall-linux-amd64 /usr/local/bin/heimdall
sudo install -d -m 0700 -o heimdall-hub -g heimdall-hub /etc/heimdall /var/lib/heimdall
cd /var/lib/heimdall && sudo -u heimdall-hub heimdall -c /etc/heimdall/heimdall.toml \
    init --database /var/lib/heimdall/heimdall.db
# Edit /etc/heimdall/heimdall.toml: set ingest.listen + tls_cert/tls_key, or keep it
# on loopback behind Caddy with behind_proxy = true.
sudo install -m 0644 heimdall.service /etc/systemd/system/
sudo systemctl enable --now heimdall

# On an installed hub, `sudo heimdall …` runs as heimdall-hub with /etc/heimdall/heimdall.toml.
alias hd='sudo heimdall'
hd org  create acme --name "Acme Corp"
hd env  create prod
hd host add web-01            # prints a one-time ingest token
hd collector trust --version 0.1.0 "$(sha256sum collect.sh | cut -d' ' -f1)"
```

### Each server
```sh
sudo install -m 0755 collect.sh /usr/local/bin/heimdall-collect
sudo useradd --system --no-create-home --shell /usr/sbin/nologin heimdall   # Alpine: adduser -S -D heimdall
sudo install -d -m 0700 -o heimdall /etc/heimdall
sudo install -m 0400 -o heimdall /dev/stdin /etc/heimdall/token     # paste the token, then Ctrl-D
sudo install -m 0644 collect.env.example /etc/heimdall/collect.env  # set HEIMDALL_URL
sudo install -m 0644 heimdall-collect.service heimdall-collect.timer /etc/systemd/system/
sudo systemctl enable --now heimdall-collect.timer
sudo systemctl start heimdall-collect.service     # first push now, instead of waiting
```

Then check from the hub: `hd host show web-01`.

Both units are sandboxed. `systemd-analyze security` rates the hub **1.4** and the collector **1.6**, where lower means less exposed. The timer runs hourly, at a fixed random offset of up to 15 minutes per host; unchanged reports are stored as small heartbeats. See [docs/collector.md](docs/collector.md) for details and troubleshooting.

---

## Configuration

`heimdall.toml`:

```toml
database = "/var/lib/heimdall/heimdall.db"

[ui]
listen   = "127.0.0.1:8080"        # loopback only; HTTPS via `tailscale serve` or Caddy
base_url = "https://heimdall.internal"
session_idle    = "30m"
session_max     = "12h"

[auth]
local_login = true                 # break-glass; set false once SSO works

[auth.entra]
enabled         = true
tenant          = "<your-tenant-id>"  # single-tenant (usual); "organizations" for multi-tenant
client_id       = "00000000-0000-0000-0000-000000000000"
allowed_tenants = ["<your-tenant-id>"]
app_role_mapping = true
# client secret/cert: systemd credential "heimdall-entra" (never in this file)

[ingest]
listen        = ":8443"
tls_cert      = "/etc/heimdall/tls/cert.pem"
tls_key       = "/etc/heimdall/tls/key.pem"
max_body      = "5MB"
rate_per_host = "30/h"
# allow_cidrs = ["203.0.113.0/24"]  # optional

[feeds]
sync_interval = "6h"
osv = true
kev = true
epss = true
endoflife = true

[hosts]
stale_after = "72h"
alert_after = "3h"   # quiet this long: silence anomaly + immediate notice ("0" = off)

[news]                             # threat news, off by default
enabled  = false
sources  = ["https://pwn.watch/incidents.json"]
interval = "1h"
```

Settings can be overridden with environment variables (`HEIMDALL_UI_LISTEN`, …). Secrets are never read from the config file. They're stored in the database or provided via systemd credentials.

---

## CLI

```
heimdall init                          Create config and database
heimdall serve                         Run UI + ingest listeners and feed scheduler
heimdall migrate                       Apply database migrations

heimdall org   create|list|delete
heimdall env   create|list    --org
heimdall host  add|list|rm    --org --env
heimdall host  token --rotate <host>
heimdall user  create|list|grant|revoke|reset-totp
heimdall user  create --entra --tenant <tid> (--oid <oid> | --email <addr>)

heimdall import <file.json> --host     Ingest a manually collected snapshot
heimdall feeds  sync|status            Refresh vulnerability/EOL data now (serve also syncs on a schedule)
heimdall report [--org acme] [--format text|json|csv|html] [--limit N]
heimdall plan   create|list|show|add|rm|done|undo|close
heimdall notify preview|send
heimdall user   grant|revoke --role viewer|operator|admin <email>
heimdall backup --to <file> --age-recipient <pubkey>
heimdall audit  [--since 7d]           Show audit log
```

---

## Data model (sketch)

```
organizations ─┬─ environments ─── hosts ─┬─ ingest_tokens (hashed)
               │                          ├─ snapshots ─┬─ packages
               └─ memberships ── users*   │             ├─ runtimes
                                          └─ tags       └─ containers
snapshots ── sites ── app_packages        (per-site composer.lock)
heartbeats = unchanged reports (time, uptime) of a host's latest snapshot
advisories ── affected_ranges            (cached from feeds)
findings   = snapshot packages × advisories (materialized on ingest/sync)
anomalies  = rule hits per host (open / acknowledged / suppressed)
maintenance_windows (per org/env/host)
audit_log

* users: local (password hash + TOTP secret) or entra (tid + oid), never both
```

---

## Milestones

The **MVP is M0 to M3**: real servers reporting in, with their vulnerable packages shown in a private, logged-in UI. Everything after that builds on a working tool.

The security baseline isn't saved for later. Each milestone ships with the hardening for the parts it adds: split listeners, strict ingest, sandboxed units and CSP all land when their component does. The schema keeps orgs, append-only snapshots and per-org memberships from day one, so later milestones don't need painful migrations.

### M0 · Foundations
- [x] Repo layout, `go.mod` with vendored dependencies, `-trimpath` build
- [x] CI running `go vet`, `staticcheck`, `govulncheck` and `go test`
- [x] TOML config, SQLite with embedded migrations, DB file `0600`
- [x] CLI scaffold: `init`, `migrate`, `org create|list`, `env create|list`, `host add|list|rm`
- [x] Full schema, even where later milestones fill it in

**Done when:** `heimdall init && heimdall org create acme && heimdall host add …` works and prints a token.

### M1 · Collect & ingest
- [x] `collect.sh` for `dpkg`, `rpm` and `apk`, collecting OS, kernel, pending updates (with security updates flagged) and reboot-required, run as an unprivileged user. Verified on Ubuntu 22.04/24.04, Debian 12, Rocky 9, AlmaLinux 9 and Alpine 3.20 (`make test-collector`).
- [x] Ingest listener with only `POST /api/v1/ingest`: hashed per-host tokens, body/decompression caps, strict schema, rate limit, append-only snapshots
- [x] `heimdall import` (and `import --check`) for manually collected JSON, plus `host token --rotate` and `host show`
- [x] systemd units: sandboxed hub, collector service and timer, verified under real systemd
- [x] Release `collect.sh` together with `SHA256SUMS` (`make dist`, plus a tag-triggered release workflow)
- [x] Collector reports its own version and SHA-256, and the hub records them on each snapshot (`collector trust|list`)
- [x] Ingest-time tripwires: reject replayed payloads (same hash for the same host), and flag clock skew between `collected_at` and `received_at`

**Done when:** three or more real servers (Debian/Ubuntu, a RHEL family distro and Alpine) check in daily and their package lists are in the DB.

### M2 · Findings
- [x] Version comparison for dpkg, rpm and apk: ports of each tool's algorithm, checked against `dpkg --compare-versions`, rpm and `apk version -t` on 1,044 real and edge-case pairs (`make test-versions`), plus fuzzing
- [x] OSV matching via the batch query API, with query results and advisories cached locally. Findings are computed right after each push and on every scheduled sync. Advisories are matched by **source** package, and rpm queries carry the epoch.
- [x] CISA KEV flag, joined through each advisory's CVE IDs (distro records keep them in `upstream`/`related`)
- [x] EOL flags for OS and runtimes from endoflife.date (v1 API), fetched only for products the fleet runs
- [x] Runtimes (PHP, Node.js, Python) derived on the hub from installed packages, with no collector change or execution. Several PHP versions side by side are all reported.
- [x] Outbound allowlist enforced **in-process** (`internal/netx`: HTTPS only, fixed host list, redirects checked, size caps). systemd can't allowlist by hostname, so for a hard guarantee add an egress firewall or proxy.
- [x] `heimdall feeds sync|status` and `heimdall report` (text or JSON), sorted for patching: known-exploited first, then fixable, then by severity

**Done when:** `heimdall report --org acme --format json` lists the correct CVEs for a host with known-vulnerable packages, checked against `apt`/`dnf` security advisories. ✅ On a Rocky 9.3 host, Heimdall found 136 of the 137 security advisories `dnf updateinfo` lists, with no false positives. The one missing advisory (RLSA-2025:7444) isn't in OSV, but its CVE is caught through RLSA-2025:3531, so CVE coverage is complete.

### M3 · Private UI → **MVP** 🎯
- [x] UI listener on loopback only, with HTTPS from `tailscale serve` or Caddy. `html/template`, strict CSP, no inline JS, and security headers.
- [x] Local login: argon2id, mandatory TOTP that can't be replayed, hashed sessions with idle and absolute expiry, CSRF and Origin checks, and login throttling per IP and per account
- [x] Audit log covering logins (success, and failures with an internal reason), logout and account changes
- [x] Dashboard: KEV hits, critical findings, EOL hosts, reboot required, stale hosts, and hosts waiting for their first report
- [x] Host page: findings, lifecycle, pending updates with copy-paste upgrade commands (security-only and all), packages, anomalies
- [x] Fleet search: `openssl < 3.0.13`, `php = 8.1`, `CVE-2024-6387`, `host:web`
- [x] Org filter (hidden when the install has only one org)

**Done when:** you log in over the tailnet and can answer "what do I patch first, and where?" across the fleet. ✅ Verified live: login with password + TOTP, every page, a replayed code rejected, a POST without CSRF or Origin rejected, and logout ending the session.

### M4 · Sites & Laravel
Right after the MVP, since most apps are Laravel. Adds `sites[]` to the snapshot as `heimdall.snapshot/v2`. The hub keeps accepting v1, so collectors can be upgraded gradually.
- [x] Collector: site discovery from enabled nginx and Apache vhosts (Debian and RHEL paths, Forge and Ploi layouts), plus explicit roots in `/etc/heimdall/collect.conf` and an opt-out
- [x] Collector, per site: server names, document root, app root, web server, PHP-FPM version from the socket path, Laravel version, `require.php`, `composer.lock` mtime
- [x] Collector: Composer packages from `composer.lock`, read-only. It never reads `.env` or runs PHP, artisan or composer.
- [x] Hub: PHP versions per host derived from packages (`php8.3-fpm`, `php83`, `php-cli`), with no execution needed
- [x] Hub: OSV Packagist matching, findings per site, and EOL flags for PHP and Laravel from endoflife.date
- [x] Hub: flag sites whose PHP-FPM version doesn't satisfy the app's `require.php`, or is EOL
- [x] UI: sites list, a site page (domains, PHP, Laravel, findings) and search such as `laravel/framework < 11.31` or `php-fpm = 8.1`
- [x] Upgrade hints: copy-paste `composer update vendor/package --with-dependencies`, advisory only as always
- [x] Docs: how to grant the collector read access to just `composer.json`/`composer.lock` (ACL example for Forge's `/home/forge/*`)

**Done when:** on a Forge-style server with two or more Laravel sites, Heimdall lists each site with its domains, PHP-FPM version and Laravel version, and flags a known-vulnerable Composer package in one of them. ✅ Covered by container fixtures (Forge layout, Apache, Alpine, an unreadable app) and by a Packagist matching test: a site on `laravel/framework` 11.31.0 is flagged for CVE-2025-27515 with fix 11.44.1, and the finding resolves after the upgrade.

### M5 · Entra ID SSO & multi-user
- [x] OIDC authorization code + PKCE flow against Entra, with JWKS cache and full claim validation
- [x] `allowed_tenants`, `tid`+`oid` identity, pre-provisioned users only
- [x] Roles (`viewer` / `operator` / `admin`) enforced in the store layer, scoped per org on multi-org installs
- [x] Optional mapping from Entra app roles
- [x] User management UI and CLI, and an option to disable local login (break-glass stays available from the CLI)
- [x] Audit log covering user, role and SSO events

**Done when:** a colleague signs in with their Entra account, gets the right role, and a user who isn't provisioned is turned away. ✅ Covered end to end against a fake Entra ID that issues real RS256 tokens: sign-in, app-role mapping, rejected forged and foreign tokens, unprovisioned users turned away, and org scoping on every page and search.

### M6 · Prioritize & patch
- [x] EPSS scores, with risk ranking by KEV, then severity, then EPSS
- [x] Patch plans: batch hosts and tick them off, and verify on the next check-in
- [x] Reports in HTML, CSV and JSON
- [x] Notifications: email or webhook digest containing counts only

### M7 · History & drift
- [x] Snapshot diffs: what changed on a host between check-ins
- [x] Drift view across hosts with the same tags
- [x] Retention policy for old snapshots (`hosts.keep_snapshots_for`, at least `keep_snapshots_min` per host, latest always kept)

### M8 · Anomaly signals (tripwires)
Builds on M6 patch plans and M7 history. See [docs/anomaly-signals.md](docs/anomaly-signals.md) for details.
- [x] Rule engine that runs on each ingest and records hits in `anomalies` (tables already exist from M0)
- [x] `heimdall collector trust <sha256>` to mark collector releases as known-good
- [x] Maintenance windows per org, env or host (one-off and recurring)
- [x] Rules:
  - silence (escalates the existing stale-host flag)
  - package installed, removed or downgraded outside a plan or window
  - kernel changed without a reboot
  - reboot outside a window
  - unknown collector version or checksum
  - new service, runtime or package not seen on tag peers
  - reports that don't add up: uptime inconsistent with the boot time, inventory reverted, package drop, collector downgraded, OS changed
- [x] Learning period for new hosts, so a first-ever snapshot doesn't alert on everything
- [x] Triage: acknowledge with a note, or suppress a rule per host until a date. Every action is recorded in the audit log.
- [x] Dashboard tile and notification digest entries (counts only)

**Done when:** installing a package by hand on a test host outside a window raises an alert on its next check-in, while the same install inside a patch plan doesn't. ✅ Covered by `internal/anomaly` tests (plus windows crossing midnight, learning period, suppression and collector trust).

### M9 · Coverage
- [x] Docker containers and images (opt-in: socket access is root-equivalent)
- [x] Allowlisted non-PHP lockfiles (`package-lock.json`, `requirements.txt`)
- [ ] Laravel apps running in Docker containers: covered when the app directory is bind-mounted from the host (list it in `HEIMDALL_SITES`). Apps baked into images aren't inspected, since that would need `docker exec`, which is root-equivalent.
- [x] `pacman`
- [x] Windows collector (`collect.ps1` + `install-windows.ps1`: scheduled task as LocalService, PowerShell 5.1+). The document builder is tested in CI; the system readers need a first run on real Windows. See [docs/collector.md](docs/collector.md#windows).
- [x] SBOM export (CycloneDX)

### M10 · Release hardening
- [x] Reproducible builds with a pinned toolchain (`make reproducible`, checked in the release workflow)
- [x] Signed releases: `SHA256SUMS` signed keylessly with Sigstore cosign, plus GitHub build-provenance attestations for every artifact
- [x] `heimdall backup` encrypted with age
- [x] Example Caddy and tailnet deployment guide ([docs/deployment.md](docs/deployment.md))
- [x] Optional TLS pinning in the collector (`HEIMDALL_CA_FILE`)
- [ ] WebAuthn/passkeys for local accounts: **deferred**. It needs CBOR/COSE parsing and attestation handling, and there's no small, well-reviewed dependency for that. Password + TOTP (or Entra SSO with phishing-resistant MFA through Conditional Access) remains.
- [ ] External security review before calling it 1.0: **owner action**. See [SECURITY.md](SECURITY.md).


### M11 · MCP for AI assistants
- [x] Read-only MCP endpoint (Streamable HTTP, JSON-RPC 2.0) on its own loopback listener, exposed over the tailnet with `tailscale serve`
- [x] Per-user tokens (`hmd_mcp_…`, hashed, revocable). Scope and roles follow the user, and every call is audit-logged.
- [x] Tools: `search`, `patch_priorities`, `host`, `sites`, `anomalies`, `changes`, `drift`, all through the same scoped code paths as the UI
- [x] Prompt-injection hygiene (untrusted-data labelling, read-only), Origin check against DNS rebinding, bounded output
- [ ] Later: opt-in write tools for operators (acknowledge an anomaly, tick a patch plan item)

**Done when:** `claude mcp add` against the hub answers "what should I patch first?" with only the orgs the token's user can see. ✅ Verified with curl against a live hub, and scope isolation covered by tests.

### Up next
- [x] **Splash page on the public ingest host.** `GET /` returns a minimal dark page with the centered logo and no text, instead of a bare 404. Caddy serves it as static HTML with the logo inline, so the hub isn't involved. Headers give nothing away: no `Server` or `Via`, `Cache-Control: no-store`, a strict CSP (`default-src 'none'`, the style pinned by hash), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`. Every other path stays an empty 404, and nothing names Heimdall or a version. Existing hubs pick it up when they re-run `install-hub.sh --ingest-host`.
- [x] **Environments that fit:** create one on the fly from Add a host ("New environment…"), move a host between environments from its page, and filter Hosts by environment. Name them after what the servers are (`shared-hosting`, `internal`), not just prod and staging.
- [x] **Site labels:** each site is Production, Staging or Development, suggested from its name (`staging.`, `dev.`, `test.`…) and overridable by org admins. Sites can be filtered by label, and the host page shows the labels.
- [x] **Event-driven reports:** a report about a minute after packages change (one per `apt upgrade`, however many packages), 3 minutes after boot so "reboot required" clears quickly, and after deploys with a one-line, sudoers-limited snippet. See [When it reports](docs/collector.md#when-it-reports).
- [ ] **Threat news (draft, Phase 1 built):** cross-reference a curated "what's being exploited now" feed such as pwn.watch with the inventory, so the UI can say "this is in the news and it affects 3 of your hosts". Phase 1 (feed, confirmed CVE matches, News page, dashboard strip, Patch first boost) is in; turn it on with `[news] enabled = true`. See [docs/threat-news.md](docs/threat-news.md).

---

## Development

```sh
make build                    # static binary at bin/heimdall (CGO_ENABLED=0, -trimpath)
make test
make check                    # gofmt, vet, staticcheck, govulncheck, tests (what CI runs)
make vendor                   # after changing dependencies; review the vendor/ diff
./heimdall serve --dev        # (M3) reloads templates from disk; refuses non-loopback listeners
```

Requires Go 1.27+. Dependencies are vendored, and staticcheck and govulncheck run at pinned versions via `go run`, so they never enter `go.mod`.

Layout:

```
cmd/heimdall/        entrypoint & CLI
internal/store/      SQLite schema, migrations, org-scoped queries
internal/ingest/     strict decoding, validation, normalization
internal/auth/       passwords, TOTP, sessions, CSRF, rate limiting
internal/auth/entra/ OIDC code+PKCE flow, JWKS cache, ID token validation
internal/feeds/      OSV, KEV, EPSS, endoflife.date clients
internal/match/      version comparison (dpkg, rpm, apk, semver)
internal/web/        handlers, templates, static assets
collector/collect.sh
deploy/              systemd units, example Caddyfile
```

---

## Security

Please report vulnerabilities in Heimdall itself privately. See `SECURITY.md`.

## License

Heimdall is free software under the **GNU Affero General Public License v3.0 or later** ([LICENSE](LICENSE)).

In short: you can use, modify and self-host it freely. If you modify it and let others use it over a network (for example, offering it as a hosted service), you must offer them the source of your modified version under the same license. Running it unmodified, or modifying it for your own internal use, carries no extra obligations.
