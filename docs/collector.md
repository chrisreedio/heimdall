# The collector

> `collector/collect.sh` is a short POSIX shell script that runs on each server and reports its OS and packages to Heimdall.
> Output format: [snapshot-format.md](snapshot-format.md).

## Supported platforms

| Distro | Versions tested | Package manager | Security updates flagged | Reboot required |
|---|---|---|---|---|
| Ubuntu | 22.04, 24.04 | dpkg / apt | ✅ (from the `-security` pocket) | ✅ `/var/run/reboot-required`, or a kernel comparison |
| Debian | 12 | dpkg / apt | ✅ (from `Debian-Security`) | ✅ newest `linux-image-*` vs running kernel |
| Rocky, AlmaLinux | 9 (RHEL 9 is the same tooling, untested) | rpm / dnf | ✅ (from `dnf updateinfo`) | ✅ `needs-restarting`, or a kernel comparison |
| Alpine | 3.20 | apk | ❌ apk can't tell, so reported as unknown | ✅ kernel package vs running kernel |

Every row runs in CI as an unprivileged user (`make test-collector`), and each snapshot is checked with the hub's strict decoder. The script runs under `dash`, `bash` and busybox `ash`.

**Not covered:** in containers, "reboot required" is reported as unknown, because there's no kernel package to compare with. That's expected.

---

### More platforms and sources (snapshot v3, collector 0.3.0)

| Source | How to enable | Findings |
|---|---|---|
| **Arch Linux** (pacman) | Automatic | Inventory and pending updates only. OSV has no Arch ecosystem. |
| **Docker containers** | `HEIMDALL_DOCKER=1` in `collect.env`, and give the `heimdall` user access to the Docker socket | Inventory (name, image, tag, state) |
| **Windows** | `install-windows.ps1`, see [Windows](#windows) | Inventory, pending KB updates, reboot status and Windows Server end of life. No CVE findings, since OSV has no Windows ecosystem. |
| **npm / pip lockfiles** | `HEIMDALL_LOCKFILES="/srv/app/package-lock.json /srv/api/requirements.txt"` | Matched against OSV's npm and PyPI data, keyed by the lockfile path |

⚠️ **Docker socket access is root-equivalent.** Anyone who can talk to `/var/run/docker.sock` can start a privileged container. Only enable `HEIMDALL_DOCKER` on hosts where you accept that, or point the collector at a read-only socket proxy.

**Lockfiles:**
- Paths must be absolute. Anything containing `..` or `.` segments is ignored.
- `package-lock.json` must be lockfile version 2 or 3. Version 1 isn't parsed.
- `requirements*.txt` must pin `name==version`. Ranges, `-e` lines and URLs are skipped.

### Windows

`collect.ps1` is the Windows collector. It runs on Windows PowerShell 5.1 (built into every supported Windows) and PowerShell 7.

| Reports | Source |
|---|---|
| Installed programs | `Uninstall` registry keys (64- and 32-bit views, system components skipped) |
| OS, build, uptime | `Win32_OperatingSystem` |
| Pending updates (KBs, security flagged) | Windows Update Agent. Reported as unavailable if the account can't query it. |
| Reboot pending | Servicing and Windows Update registry flags |
| End of life | Windows Server 2012–2025 LTSC, by build number. Desktop editions aren't mapped yet. |

OSV has no Windows ecosystem, so Windows hosts get inventory, update and lifecycle status, but no CVE findings.

**Install** (once, from an elevated PowerShell, after verifying the files against `SHA256SUMS`):

```powershell
.\install-windows.ps1 -HubUrl https://ingest.example.com
#   paste the token from `heimdall host add` when prompted
Start-ScheduledTask -TaskName 'Heimdall collector'    # first push now
```

The installer sets up a daily scheduled task with a random delay of up to an hour, running as **`NT AUTHORITY\LocalService`**, a built-in low-privilege account. The token goes in `C:\ProgramData\Heimdall\token`, with permissions limited to LocalService (read), SYSTEM and Administrators. It never appears on a command line.

**Try it without installing:** `powershell -File collect.ps1 -Print` shows exactly what would be sent.

**Tests:** the document builder is checked in CI. It runs under `pwsh` against fixture inventories (including dropped duplicates, markup in names and every source failing), and the output is validated by the hub's decoder. The registry and Update Agent readers can only be exercised on real Windows, so try `-Print` on your first host before rolling out.

## Security properties

The collector runs on every server you manage, so it's built to be **boring, read-only and hard to abuse**.

| Property | How | Why it matters |
|---|---|---|
| **Never runs as root** | It refuses unless `HEIMDALL_ALLOW_ROOT=1` is set explicitly | A bug or tampered script can't do root-level damage |
| **Read-only** | It only runs read-only queries (`dpkg-query`, `rpm -q`, `apt-get -s`, `dnf -C`) and reads apk's database file directly | It can't change, install or update anything |
| **Never refreshes package metadata** | It uses the cache that `apt-daily` / `dnf-makecache` already keep up to date | No network access to mirrors, and no need for privileges |
| **Can't be hijacked through `PATH`** | It sets a fixed `PATH=/usr/sbin:/usr/bin:/sbin:/bin` and `LC_ALL=C` | A planted `rpm` or `awk` earlier in the path is never used |
| **Treats `os-release` as data** | It parses the file with `sed` and never `source`s it | A tampered file can't run code |
| **Token never appears in process arguments** | The token goes to curl on stdin via `--config`, using the shell's built-in `printf` | Other users on the box can't read it from `ps` or `/proc/*/cmdline` |
| **Refuses an exposed token file** | It exits if the token file is readable by group or others | Forces `chmod 400` |
| **Validates the token** | It accepts only `[A-Za-z0-9_-]` before using the token | A malformed file can't inject curl config |
| **HTTPS only** | Plain `http://` is allowed only to `127.0.0.1`, `localhost` or `[::1]` (a local proxy or tests). TLS 1.2+. | Snapshots and tokens can't travel in the clear |
| **Optional CA pinning** | `HEIMDALL_CA_FILE` trusts only your CA | A rogue public certificate can't intercept traffic |
| **Ignores the response** | It reads only the HTTP status code and discards the body | A compromised hub can't send instructions back |
| **One request, then done** | No daemon, no listening port, no other network calls | Nothing persistent to attack |
| **Private temp files** | `umask 077` and a `mktemp -d` directory that's removed on exit | Other users can't read the snapshot while it's being sent |
| **Collects only what's listed** | OS, kernel, uptime, reboot flag, packages, pending updates, and [sites](#sites--laravel) (paths, hostnames, PHP-FPM version, Composer packages). See [What it never touches](#what-it-never-touches). | Nothing sensitive leaves the box |
| **Never runs app code** | Sites are found by *reading* vhost files and `composer.json`/`composer.lock` with `awk`. It never runs `php`, `composer` or `artisan`, and never reads `.env`. | A compromised or broken app can't affect the collector, and secrets stay put |
| **Reports its own checksum** | It sends the SHA-256 of itself with every snapshot | Tampering shows up as "collector changed" (M8) |
| **Installed from a release, not the hub** | You download it from a tagged release and verify `SHA256SUMS` | A compromised hub can't push code to your servers |

### What it never touches
- `.env` files, config file contents, environment variables
- Users, groups, SSH keys, shell history
- Process lists or process arguments
- Any file other than `/etc/os-release`, `/proc/uptime`, the package database, `/var/run/reboot-required`, enabled nginx/Apache vhost files, each discovered app's `composer.json` and `composer.lock`, its own script file and the token file
- Application source code, `vendor/`, logs or storage

### What it trusts
- **The package manager's own output.** If an attacker has root, they can make the collector report anything. See [anomaly-signals.md](anomaly-signals.md) for what Heimdall does about that.
- **The system tools in `/usr/bin` and `/bin`.** Those can only be replaced by root.

---

## Installing

**Quickest:** **Hosts → Add a host** in the UI gives you a one-line command running `install.sh` from the release. It verifies checksums (and the Sigstore signature when `cosign` is installed), creates the user and token, schedules daily pushes (systemd, or cron on Alpine and other non-systemd systems) and sends the first report. On the hub's own box it uses `/etc/heimdall-collect`, so the hub's config is never touched.

To install by hand:

```sh
# 1. Download collect.sh, the deploy files and SHA256SUMS from a tagged release, then verify
#    them. Never fetch the collector from the hub.
sha256sum -c --ignore-missing SHA256SUMS

# 2. Install it and create the unprivileged user
sudo install -m 0755 collect.sh /usr/local/bin/heimdall-collect
sudo useradd --system --no-create-home --shell /usr/sbin/nologin heimdall   # Alpine: adduser -S -D heimdall

# 3. Install the token from `heimdall host add` (readable only by heimdall)
sudo install -d -m 0700 -o heimdall /etc/heimdall
sudo install -m 0400 -o heimdall /dev/stdin /etc/heimdall/token   # paste the token, then Ctrl-D

# 4. Point it at the hub and schedule it
sudo install -m 0644 collect.env.example /etc/heimdall/collect.env   # set HEIMDALL_URL
sudo install -m 0644 heimdall-collect.service heimdall-collect.timer /etc/systemd/system/
sudo systemctl enable --now heimdall-collect.timer

# 5. Push once now and check the result
sudo systemctl start heimdall-collect.service
journalctl -u heimdall-collect -n 5
```

The service runs as `heimdall` under systemd sandboxing (`systemd-analyze security` rates it 1.6), with the filesystem read-only, no capabilities and a restricted set of system calls. The timer fires daily at a random time between 04:00 and 05:00.

**Collecting on the hub's own box?** The hub owns `/etc/heimdall`, so give the collector its own directory, e.g. `/etc/heimdall-collect`. Set `HEIMDALL_TOKEN_FILE` in its env file and `EnvironmentFile=` in the unit.

**Alpine:** run `apk add curl` for push mode. busybox `wget` isn't supported, because it would expose the token in process arguments.

## Usage

| Command | What it does |
|---|---|
| `heimdall-collect --print` | Write a snapshot to stdout, to review or to save for `heimdall import` |
| `heimdall-collect --push` | Send a snapshot to the hub |
| `heimdall-collect --version` | Print the collector version |

**Push mode settings** (environment variables, usually from a systemd `EnvironmentFile`):

| Variable | Default | Meaning |
|---|---|---|
| `HEIMDALL_URL` | none (required) | Hub ingest URL, e.g. `https://heimdall.example.com:8443` |
| `HEIMDALL_TOKEN_FILE` | `/etc/heimdall/token` | The host's ingest token |
| `HEIMDALL_CA_FILE` | none | CA bundle to pin the hub's certificate |
| `HEIMDALL_SITES` | none | Extra app roots to inventory, space-separated (e.g. queue workers with no vhost) |
| `HEIMDALL_DISCOVER_SITES` | `1` | Set to `0` to skip reading nginx/Apache vhost files |

**Without installing anything** (import mode), from your own machine:

```sh
ssh web-01 sh -s -- --print < collector/collect.sh > web-01.json
```

When piped like this the script can't hash itself, so the snapshot declares `collector_sha256` unavailable. That's expected.

## Upgrading

```sh
sudo heimdall-collect upgrade          # to the release the hub runs
sudo heimdall-collect upgrade v0.4.12  # or a release you choose
```
It runs as root (it replaces `/usr/local/bin/heimdall-collect`), reads the hub URL, token path and site settings from `collect.env` without executing it, asks the hub for its release with the server's token, downloads that release's `install.sh` from GitHub and checks it against `SHA256SUMS` before running it. Nothing runs automatically: like the hub, the collector never updates itself.

## Sites & Laravel

Snapshot format v2 includes the web apps on each server, so Heimdall can show which sites run which Laravel and PHP-FPM versions, and match their Composer packages against advisories.

**How sites are found**
1. **nginx:** every `server { … }` block in `/etc/nginx/sites-enabled/*`, `/etc/nginx/conf.d/*.conf` and `/etc/nginx/http.d/*.conf` (Alpine). The collector reads `server_name`, `root` (a server-level `root` wins over one in a `location`) and `fastcgi_pass`.
2. **Apache:** every `<VirtualHost>` in `/etc/apache2/sites-enabled/*` and `/etc/httpd/conf.d/*.conf`. It reads `ServerName`, `ServerAlias`, `DocumentRoot` and a `SetHandler "proxy:unix:…php…-fpm.sock|fcgi://…"` handler.
3. **`HEIMDALL_SITES`:** any extra roots you list, e.g. a queue worker or scheduler with no vhost.

**From vhost to app:** if the document root ends in `/public` and its parent has `composer.json` (the Laravel layout), the parent is the app root. Several vhosts pointing at the same app are merged into one site with all their hostnames. The PHP-FPM version comes from the socket name: `php8.3-fpm.sock` → 8.3, and Alpine's `php-fpm83` / `php83-fpm` → 8.3.

**Permissions:** the collector runs as `heimdall` and only needs to *enter* each app folder and *read* its two composer files. It doesn't need access to the rest of the app. On a Forge box, for example:

```sh
sudo setfacl -m u:heimdall:x /home/forge /home/forge/example.com
sudo setfacl -m u:heimdall:r /home/forge/example.com/composer.json /home/forge/example.com/composer.lock
```

A site the collector can't read is still reported, with its hostnames and PHP version, but `readable: false` and no Composer data. That makes missing permissions visible instead of silent.

**Known limitations**
- `include` lines aren't followed, so `server_name`/`root`/`fastcgi_pass` must be in the vhost file itself. That's true for Forge, Ploi and most hand-written configs.
- Regex server names (`~^…`), roots containing variables (`$…`) and TCP PHP pools (`127.0.0.1:9000`) are skipped or reported without a PHP version.
- `composer.lock` must be in Composer's normal pretty-printed layout. A minified lock file yields no packages.
- Caddy, LiteSpeed and apps inside Docker containers aren't discovered yet. List their roots in `HEIMDALL_SITES`, or wait for M9.

## Exit codes & messages

| Exit | Meaning |
|---|---|
| `0` | Success |
| `1` | Error, with a one-line reason on stderr (see below) |
| `2` | Wrong usage |

| Message | Fix |
|---|---|
| `refusing to run as root` | Run as the `heimdall` user: `sudo -u heimdall heimdall-collect …` |
| `… is readable by other users` | `chmod 400 /etc/heimdall/token` |
| `HEIMDALL_URL must use https://` | Use an `https://` URL, or a local `http://127.0.0.1` proxy |
| `hub rejected the token (HTTP 401/403)` | The token was rotated or the host removed. Get a new one with `heimdall host add`. |
| `hub rejected the snapshot as invalid (HTTP 422)` | Run `--print` and check the output with `heimdall import --check` |
| `rate limited by the hub (HTTP 429)` | It's running too often. The default limit is 10 per hour per host. |
| `curl is required for --push` | Install curl |

## Testing changes to the collector

```sh
make shellcheck         # lint (Docker)
make test-collector     # run on every supported distro, then validate (incl. a fake-vhost
                        # site fixture on Ubuntu 22.04 and Alpine: test/sites-fixture.sh)
```

To add a distro, add a line to `collector/test/run-containers.sh`.
