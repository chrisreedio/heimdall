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
- Any file other than `/etc/os-release`, `/proc/uptime`, the package database, `/var/run/reboot-required`, enabled nginx/Apache vhost files, each discovered app's `composer.json` and `composer.lock`, its own script file and the token file (plus, for the opt-in [privilege watch](#privilege-watch), its events file and whether `/etc/pam.d/sudo`, `su` and `sshd` contain its line)
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

## Privilege watch

An opt-in tripwire for "someone used root". It records **that** privileged access happened, never what was typed.

```sh
sudo sh install.sh --hub https://ingest.example.com --watch-privilege        # time and kind only
sudo sh install.sh --hub https://ingest.example.com --watch-privilege-users  # also who
sudo sh install.sh --hub https://ingest.example.com --no-watch-privilege     # remove it
```
Re-running `install.sh`, and `sudo heimdall-collect upgrade` (which runs it), keeps the current choice. It's stored as `HEIMDALL_PRIVILEGE_WATCH=on|users|off` in `collect.env`.

**What it installs** (as root; the logic is in `privilege-watch.sh`, fetched and checksum-verified with the other release files):
- `/usr/local/lib/heimdall/privilege-hook`, a short root-owned POSIX sh script.
- One line at the end of each of `/etc/pam.d/sudo`, `/etc/pam.d/su` and `/etc/pam.d/sshd` that exists:
  `session optional pam_exec.so quiet seteuid /usr/local/lib/heimdall/privilege-hook  # heimdall`
  (`seteuid` because sudo opens its session with the caller's real uid; without it the hook couldn't write a root-owned file.) Only lines ending in `# heimdall` are ever added or removed. Each file is rewritten through a temp file with the same owner and mode, then renamed, and `--no-watch-privilege` puts it back byte for byte. A PAM file that is a symlink is left alone, with a warning.
- `/var/lib/heimdall-privilege/events` (directory 0755, file 0644, root-owned): one `<unix-time> <kind>[ <user>]` line per event, the last 500 kept.

**What it records:** `sudo`, `su`, and `root-ssh` (an SSH login as root). SSH logins as other users are ignored. With `--watch-privilege-users`, the invoking user (`PAM_RUSER`, else `PAM_USER`) is added if it matches `[a-z_][a-z0-9_.-]{0,31}`, and `?` otherwise. Never commands, arguments, terminals or source addresses.

**It never blocks or slows a login.** The PAM line is `optional`, the hook always exits 0, makes no network requests, does nothing unless the session is opening, and gives up quietly if the events directory is missing or the disk is full. A broken hook (not executable, deleted, or its directory gone) still lets sudo, su and SSH work. After recording, it starts `heimdall-collect-soon.timer` if installed (a short debounce), otherwise `heimdall-collect.service`, in the background with errors ignored, so the hub hears about it within a minute or so. Without systemd (cron installs), events wait for the next daily push.

**How it's reported:** the collector itself stays unprivileged and read-only. On each push it reads the events file and sends the last 7 days, deduplicated and capped at 200 (about 8 KB), in a request header, `X-Heimdall-Privilege: v1 <ts>:<kind>[:<user>],...`. It also sends `X-Heimdall-Privilege-Watch: on|off|partial`: `on` means the hook is executable, the events file exists and every existing PAM file of the three has its line; `off` means none of it is there; `partial` is anything in between. They're headers, not snapshot fields, so collectors and hubs of different versions still work together. The collector keeps no state, so it resends recent events every time and the hub dedupes them on (host, time, kind, user). Malformed or oversized headers are dropped without failing the push. The hub keeps events for 180 days.

**What you see:** the host page shows a "Privileged access" line ("3 sudo, 1 root SSH in the last 24 hours") once a host has turned it on, and two anomalies, **privileged access** and **privilege watch disabled**, described in [anomaly-signals.md](anomaly-signals.md#privilege-watch).

**Be honest about its limits.** Root can remove the hook, edit the events file or stop the collector, like anything else on the box. What it buys you is that doing so isn't silent: removing the watch while the host still reports raises **privilege watch disabled**, and stopping the collector raises **silence**. Turning it off on purpose with `--no-watch-privilege` raises **privilege watch disabled** too, which you acknowledge. Two events of the same kind by the same user in the same second count once, and a flood of more than 500 events between pushes pushes older ones out of the file (the flood itself still shows).

**SELinux:** tested on Rocky 9 in a container, where SELinux isn't enforcing. On an enforcing host the stock policy may stop the hook from writing `/var/lib/heimdall-privilege` from the sshd or sudo domains. Logins still work (the line is `optional`), but events may not be recorded; check `ausearch -m avc -ts recent` after a test `sudo true`.

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
