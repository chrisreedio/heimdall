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

The installer sets up two scheduled tasks running as **`NT AUTHORITY\LocalService`**, a built-in low-privilege account, with the least privilege (see [When it reports](#when-windows-reports)). The token goes in `C:\ProgramData\Heimdall\token`, with permissions limited to LocalService (read), SYSTEM and Administrators. It never appears on a command line.

**Upgrading:** download the new release's `install-windows.ps1`, `collect.ps1` and `SHA256SUMS` and run the installer again, the same way. It replaces `collect.ps1` and both tasks (an install from before v0.4.14 has its daily task replaced by the hourly one) and keeps the hub URL; press Enter at the token prompt to keep the current token. There's no `heimdall-collect upgrade` on Windows yet. When the hub runs a newer release, `collect.ps1 -Push` says so on stderr.

**Try it without installing:** `powershell -File collect.ps1 -Print` shows exactly what would be sent.

#### When Windows reports

| Task | Triggers | Runs |
|---|---|---|
| `Heimdall collector` | Hourly, with a random delay of up to 15 minutes; 3 minutes after boot | `collect.ps1 -Push` |
| `Heimdall collector (changes)` | An event: Windows Installer (`MsiInstaller`) 11707, 11724, 1033 or 1034 in the Application log (a product installed or removed), or Windows Update (`Microsoft-Windows-WindowsUpdateClient`) 19 in the System log (an update installed) | `collect.ps1 -Push -AfterChanges` |

Both run as LocalService with the least privilege, also on battery, never two copies of one at once (a start while one runs is dropped), and are registered from Task Scheduler XML generated by `collect.ps1` itself (`Get-HeimdallTaskXml`). Their security descriptor gives LocalService read access, so the collector can report their state.

**Debounce.** The event trigger fires once per event, and a big install logs several. The first one starts the task; later ones are dropped while it runs. With `-AfterChanges` the collector first reads the Application and System logs for those same events, and waits until none has been logged for 60 seconds (at most 10 minutes), then reports. If more were logged while that report was being sent, it waits and reports again (at most 3 reports per run). So a burst of installs, or a Patch Tuesday, is one report about a minute after the last event. If the logs can't be read, it waits a minute and reports once. The logs grant read access to service accounts, and the Task Scheduler (not the collector) watches for the events, so nothing needs extra rights; the Security log is never read.

**Not covered:** programs installed by EXE installers that don't use Windows Installer (many `winget` packages, Inno Setup and NSIS installers, browsers updating themselves) log no reliable event; the hourly report picks them up. Store and MSIX apps aren't inventoried, so their installs don't trigger a report (Store updates delivered through Windows Update do log event 19, and send an unchanged report).

**Trigger state.** Each push sends `X-Heimdall-Triggers: task=<enabled>,<state>; changes=<enabled>,<state>` for the two tasks, read through the Task Scheduler's COM API, e.g. `task=enabled,running; changes=enabled,ready`. `<enabled>` is `enabled`, `disabled`, `missing` (deleted) or `unknown` (the Task Scheduler couldn't be asked); `<state>` is the Task Scheduler's `ready`, `running`, `queued` or `disabled`, `no-triggers` when every trigger was removed or disabled, or `none` for a missing task. Disabling or deleting either task while the host keeps reporting raises **Change reporting disabled** on the hub, as on Linux; see [anomaly-signals.md](anomaly-signals.md#change-reporting-disabled).

**Tests:** the document builder is checked in CI. It runs under `pwsh` against fixture inventories (including dropped duplicates, markup in names and every source failing), and the output is validated by the hub's decoder. The same run checks the generated task XML, the event queries, the trigger states and the debounce (with a fake clock). The registry, Update Agent, Task Scheduler and event log readers can only be exercised on real Windows, so try `-Print` on your first host before rolling out.

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

**Quickest:** **Hosts → Add a host** in the UI gives you a one-line command running `install.sh` from the release. It verifies checksums (and the Sigstore signature when `cosign` is installed), creates the user and token, schedules pushes (hourly, after boot and after package changes; see [When it reports](#when-it-reports)) and sends the first report. On the hub's own box it uses `/etc/heimdall-collect`, so the hub's config is never touched.

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
sudo install -m 0644 heimdall-collect.service heimdall-collect.timer heimdall-collect-boot.timer heimdall-collect-soon.timer \
  heimdall-collect-changes.service heimdall-collect-changes.path /etc/systemd/system/
#    (optional) delete the PathChanged= lines in heimdall-collect-changes.path for package
#    managers this box doesn't have; install.sh does that for you
sudo systemctl enable --now heimdall-collect.timer heimdall-collect-changes.path
sudo systemctl enable heimdall-collect-boot.timer   # next boot on; started now it would fire at once

# 5. Push once now and check the result
sudo systemctl start heimdall-collect.service
journalctl -u heimdall-collect -n 5
```

The service runs as `heimdall` under systemd sandboxing (`systemd-analyze security` rates it 1.6), with the filesystem read-only, no capabilities and a restricted set of system calls. The timer fires hourly, at a fixed random offset of up to 15 minutes per host. A separate `heimdall-collect-boot.timer` reports 3 minutes after boot, with no random delay.

**Collecting on the hub's own box?** The hub owns `/etc/heimdall`, so give the collector its own directory, e.g. `/etc/heimdall-collect`. Set `HEIMDALL_TOKEN_FILE` in its env file and `EnvironmentFile=` in the unit.

**Alpine:** run `apk add curl` for push mode. busybox `wget` isn't supported, because it would expose the token in process arguments.

## When it reports

| When | systemd | Without systemd | Windows |
|---|---|---|---|
| Hourly | `heimdall-collect.timer`: a fixed random offset of up to 15 minutes past each hour | cron (`/etc/periodic/hourly` or `/etc/cron.hourly`), after a random delay of up to 15 minutes | The `Heimdall collector` task, with a random delay of up to 15 minutes |
| After boot | `heimdall-collect-boot.timer`, 3 minutes after boot (`OnBootSec=3min`, no random delay), so the hub sees the reboot and clears "reboot required" | Not yet | 3 minutes after boot, the same task |
| After package changes | About a minute after the last change: `heimdall-collect-changes.path` | About a minute after the last change: an apk commit hook or an apt `DPkg::Post-Invoke` hook | About a minute after the last Windows Installer install or removal, or Windows Update install: the `Heimdall collector (changes)` task, see [Windows](#when-windows-reports) |
| After a deploy | One line in your deploy script, see [below](#report-after-deploys) | The same, with `soon.sh` | `Start-ScheduledTask -TaskName 'Heimdall collector'` (as Administrator) |

The hub runs its tripwire rules on every report, so these event reports let it see changes within minutes instead of the next morning.

### After package changes

**systemd.** Three small units, none of which change the collector's own sandbox:

1. `heimdall-collect-changes.path` watches the package database: `/var/lib/dpkg/status` (dpkg), `/var/lib/rpm/rpmdb.sqlite` (rpm 4.16+, as on RHEL/Rocky/Alma 9) or `/var/lib/rpm/Packages` (older rpm), `/lib/apk/db/installed` (apk) and `/var/lib/pacman/local` (pacman). `install.sh` keeps only the paths that exist on the box.
2. Each change starts `heimdall-collect-changes.service`, which only runs `systemctl restart --no-block heimdall-collect-soon.timer`. It runs as root (to talk to systemd) with no network, no capabilities and a read-only filesystem; `systemd-analyze security` rates it 1.1.
3. `heimdall-collect-soon.timer` (`OnActiveSec=60s`) then starts the usual `heimdall-collect.service`.

Restarting the timer restarts its countdown, so the report goes out 60 seconds after the *last* change. A whole `apt upgrade` sends one report, about a minute after it ends. A change made while a report is running restarts the countdown too, so it gets a report of its own a minute later.

For rpm the path unit watches `rpmdb.sqlite` itself, not `/var/lib/rpm`: read-only queries by root (`dnf makecache`, `rpm -q`) rewrite the sqlite `-shm` and `-wal` files beside it, but `rpmdb.sqlite` changes only when packages do.

**Without systemd** (Alpine with OpenRC, Debian without systemd, containers), `install.sh` adds a hook for the package manager it finds:

| Package manager | Hook |
|---|---|
| apk | `/etc/apk/commit_hooks.d/heimdall-collect` (on `post-commit`) |
| apt | `/etc/apt/apt.conf.d/80heimdall-collect` (`DPkg::Post-Invoke`) |

Both run `/usr/local/lib/heimdall-collect/soon.sh` as root. It returns at once and always succeeds, so it can't slow down or break the package manager. A background process waits until there have been no changes for 60 seconds (a lock directory in `/run` holds the time of the last change), then pushes as the `heimdall` user, just like the hourly cron job. Its output goes to syslog (`logger -t heimdall-collect`). There's no hook for rpm or pacman without systemd; those boxes report hourly.

Event reports count toward the hub's rate limit of 30 reports per hour per host (`[ingest] rate_per_host`; hubs set up before v0.4.13 have `"10/h"` in their config, which still fits hourly reports plus a few events). The 60-second wait keeps a busy upgrade to one of them.

### Report after deploys

Add this as the last line of your deploy script (for example, Laravel Forge's deploy script), so the hub sees new Composer packages right away:

```sh
sudo -n systemctl start --no-block heimdall-collect.service || true
```

It returns at once: `--no-block` doesn't wait for the report, and `|| true` means a problem with reporting never fails the deploy.

A deploy user like `forge` can't start system services by itself (`Access denied`), and a sudo password prompt would hang the deploy. So allow exactly this one command, and nothing else, with a sudoers drop-in:

```sh
echo 'forge ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block heimdall-collect.service' |
  sudo tee /etc/sudoers.d/heimdall-collect
sudo chmod 0440 /etc/sudoers.d/heimdall-collect && sudo visudo -cf /etc/sudoers.d/heimdall-collect
```

sudo matches the arguments exactly, so the user can't stop the timer, start any other unit or even drop `--no-block`. The report still runs as `heimdall` in its sandbox. `/bin/systemctl` matches too, where `/bin` links to `/usr/bin`.

**Without systemd**, use the same debounced script as the package hooks, which also returns at once:

```sh
sudo -n /usr/local/lib/heimdall-collect/soon.sh || true
# sudoers: forge ALL=(root) NOPASSWD: /usr/local/lib/heimdall-collect/soon.sh
```

**By hand**, as a user who can already use sudo (this one waits for the push):

```sh
sudo -u heimdall sh -c 'set -a; . /etc/heimdall/collect.env; exec /usr/local/bin/heimdall-collect --push'
```

On the hub's own box the collector's settings are in `/etc/heimdall-collect/collect.env`.

## Usage

| Command | What it does |
|---|---|
| `heimdall-collect --print` | Write a snapshot to stdout, to review or to save for `heimdall import` |
| `heimdall-collect --push` | Send a snapshot to the hub |
| `heimdall-collect --site-repos` | Print the site repositories a push would send (see [Site repositories](#site-repositories)) |
| `heimdall-collect --version` | Print the collector version |

**Push mode settings** (environment variables, usually from a systemd `EnvironmentFile`):

| Variable | Default | Meaning |
|---|---|---|
| `HEIMDALL_URL` | none (required) | Hub ingest URL, e.g. `https://heimdall.example.com:8443` |
| `HEIMDALL_TOKEN_FILE` | `/etc/heimdall/token` | The host's ingest token |
| `HEIMDALL_CA_FILE` | none | CA bundle to pin the hub's certificate |
| `HEIMDALL_SITES` | none | Extra app roots to inventory, space-separated (e.g. queue workers with no vhost) |
| `HEIMDALL_DISCOVER_SITES` | `1` | Set to `0` to skip reading nginx/Apache vhost files |
| `HEIMDALL_DETECT_REPOS` | `1` | Set to `0` to stop reading sites' `.git/config` (see [Site repositories](#site-repositories)) |

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
sudo sh install.sh --hub https://ingest.example.com --watch-privilege-users  # also who, and from which IP
sudo sh install.sh --hub https://ingest.example.com --no-watch-privilege     # remove it
```
Re-running `install.sh`, and `sudo heimdall-collect upgrade` (which runs it), keeps the current choice. It's stored as `HEIMDALL_PRIVILEGE_WATCH=on|users|off` in `collect.env`.

**What it installs** (as root; the logic is in `privilege-watch.sh`, fetched and checksum-verified with the other release files):
- `/usr/local/lib/heimdall/privilege-hook`, a short root-owned POSIX sh script.
- One line at the end of each of `/etc/pam.d/sudo`, `/etc/pam.d/su` and `/etc/pam.d/sshd` that exists:
  `session optional pam_exec.so quiet seteuid /usr/local/lib/heimdall/privilege-hook  # heimdall`
  (`seteuid` because sudo opens its session with the caller's real uid; without it the hook couldn't write a root-owned file.) Only lines ending in `# heimdall` are ever added or removed. Each file is rewritten through a temp file with the same owner and mode, then renamed, and `--no-watch-privilege` puts it back byte for byte. A PAM file that is a symlink is left alone, with a warning.
- `/var/lib/heimdall-privilege/events` (directory 0755, file 0644, root-owned): one `<unix-time> <kind>[ <user> <source>]` line per event, the last 500 kept.

**What it records:** `sudo`, `su`, and `root-ssh` (an SSH login as root). SSH logins as other users are ignored. With `--watch-privilege-users`, two more things are added:
- **The invoking user** (`PAM_RUSER`, else `PAM_USER`) if it matches `[a-z_][a-z0-9_.-]{0,31}`, and `?` otherwise.
- **Where the session came from.** For a root SSH login that's sshd's remote address (`PAM_RHOST`; a host name if sshd has `UseDNS yes`). For sudo and su, PAM gives no address (sudo sets `PAM_RHOST` to the server's own name), so the hook looks up the terminal (`PAM_TTY`) in utmp with `who` and takes that login session's remote host. So `sudo` in an SSH session from 203.0.113.7 records 203.0.113.7. It records `-` when there's no remote session: a local console, cron, or a terminal utmp doesn't list, such as one inside tmux or screen. It records `?` when the value isn't an IP address or host name.

Never commands, arguments or terminals. The source is only as trustworthy as the server: anyone with root there can edit utmp or the events file.

**It never blocks or slows a login.** The PAM line is `optional`, the hook always exits 0, makes no network requests, does nothing unless the session is opening, and gives up quietly if the events directory is missing or the disk is full. A broken hook (not executable, deleted, or its directory gone) still lets sudo, su and SSH work. After recording, it restarts `heimdall-collect-soon.timer` (the same 60-second debounce as package changes, so a burst of logins is one push), or runs `soon.sh` without systemd, in the background with errors ignored. The hub hears about it within a minute or so.

**How it's reported:** the collector itself stays unprivileged and read-only. On each push it reads the events file and sends the last 7 days, deduplicated and capped at 200 (about 8 KB), in a request header, `X-Heimdall-Privilege: v1 <ts>:<kind>[:<user>[:<source>]],...` (the source is last, since an IPv6 address has colons; `-` is left out). It also sends `X-Heimdall-Privilege-Watch: on|off|partial`: `on` means the hook is executable, the events file exists and every existing PAM file of the three has its line; `off` means none of it is there; `partial` is anything in between. They're headers, not snapshot fields, so collectors and hubs of different versions still work together. The collector keeps no state, so it resends recent events every time and the hub dedupes them on (host, time, kind, user). Malformed or oversized headers are dropped without failing the push. The hub keeps events for 180 days.

**What you see:** the host page shows a "Privileged access" line ("3 sudo, 1 root SSH in the last 24 hours") once a host has turned it on, with the last few events and who and where from ("sudo by chris from 203.0.113.7") when the server records them, and two anomalies, **privileged access** and **privilege watch disabled**, described in [anomaly-signals.md](anomaly-signals.md#privilege-watch).

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

### Site repositories

For the hub's [Hand off to an agent](deployment.md#hand-off-to-an-agent), the collector reports each site's git remote: the `url` of `[remote "origin"]` in a git config file. It reads the file directly. **git is never run**, so nothing touches the network and no privileges are needed: a file the `heimdall` user can't read is skipped. It looks in, first match wins:

1. `<app root>/.git/config`: a plain checkout (Forge's standard deployments, Ploi, a hand-made `git pull` setup), or a release that kept its `.git`.
2. For a release layout, where the app root is `<base>/current` or `<base>/releases/<n>`: `<base>/.git/config`, then the repository caches `<base>/repo/config` (Capistrano-style mirrors) and `<base>/.dep/repo/config` (Deployer).

**Laravel Forge zero-downtime deployments** serve `/home/forge/<site>/current/public`, where `current` is a symlink to `releases/<n>`; `$CREATE_RELEASE()` clones the site into each new release, and `.env` and `storage` are shared from `/home/forge/<site>`. The app root is then `/home/forge/<site>/current`, and its `.git/config` is read through the symlink. Forge's documentation doesn't say whether a release keeps its `.git`. If yours doesn't (check with `ls /home/forge/<site>/current/.git`), set the repository on the site page instead.

**Credentials are stripped on the server,** before anything is sent. A remote like `https://forge:ghp_…@github.com/acme/app.git` is sent as `https://github.com/acme/app`. Only `https://`, `ssh://` and `user@host:path` forms are accepted, a query or fragment is dropped, an SSH user name is kept only if it's `git` (or `gitea`, `forgejo`, `gogs`, `gitlab`) with no password, and the result is at most 200 characters. The hub normalizes it again with the same rules.

**Permissions:** like the composer files, the collector needs to enter `.git` and read `config`, nothing else in it:

```sh
sudo setfacl -m u:heimdall:x /home/forge/example.com/.git
sudo setfacl -m u:heimdall:r /home/forge/example.com/.git/config
# zero-downtime: new releases are new folders, so give a default ACL on releases/
sudo setfacl -d -m u:heimdall:rX /home/forge/example.com/releases
```

**How it's sent:** in a request header, `X-Heimdall-Site-Repos: v1 <root> <url>,<root> <url>` (just `v1` when none are known), at most about 4 KB. It's a header, not a snapshot field, for the same reason as the privilege watch's: the hub rejects snapshots with unknown fields, so a new field would make an older hub refuse a newer collector's push, while every hub ignores a header it doesn't know. A push without the header (an older collector) leaves the hub's stored repositories alone. `heimdall-collect --site-repos` prints the value; `HEIMDALL_DETECT_REPOS=0` sends `v1` (none).

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
| `rate limited by the hub (HTTP 429)` | It's running too often. The default limit is 30 per hour per host (`[ingest] rate_per_host`). |
| `curl is required for --push` | Install curl |

## Testing changes to the collector

```sh
make shellcheck         # lint (Docker)
make test-collector     # run on every supported distro, then validate (incl. a fake-vhost
                        # site fixture on Ubuntu 22.04 and Alpine: test/sites-fixture.sh)
```

To add a distro, add a line to `collector/test/run-containers.sh`.
