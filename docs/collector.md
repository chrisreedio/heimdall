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
| **npm / pip lockfiles** | `HEIMDALL_LOCKFILES="/srv/app/package-lock.json /srv/api/requirements.txt"` | Matched against OSV's npm and PyPI data, keyed by the lockfile path. A site's own `package-lock.json` is read without this (see [npm packages](#npm-packages-snapshot-v4)). |

⚠️ **Docker socket access is root-equivalent.** Anyone who can talk to `/var/run/docker.sock` can start a privileged container. Only enable `HEIMDALL_DOCKER` on hosts where you accept that, or point the collector at a read-only socket proxy.

**Lockfiles:**
- Paths must be absolute. Anything containing `..` or `.` segments is ignored.
- `package-lock.json` can be lockfile version 1, 2 or 3, read the same way as a site's (see [npm packages](#npm-packages-snapshot-v4)).
- A listed `package-lock.json` in a site's app root belongs to that site: the hub shows it in the site's card, not as a separate lockfile.
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

**Install** (once, from an elevated PowerShell). Download `install-windows.ps1`, `collect.ps1`, `SHA256SUMS` and `SHA256SUMS.sigstore.json` from the release into one folder. The installer checks the [signature](deployment.md#release-signatures) and `collect.ps1`'s checksum before installing anything:

```powershell
.\install-windows.ps1 -HubUrl https://ingest.example.com
#   paste the token from `heimdall host add` when prompted
Start-ScheduledTask -TaskName 'Heimdall collector'    # first push now
```

With an [enrollment key](#many-servers-enrollment-keys) instead of a token, add `-Enroll` and paste the key when asked: the hub adds the server and gives it its own token. A server that already has a working token keeps it.

```powershell
.\install-windows.ps1 -HubUrl https://ingest.example.com -Enroll
```

The installer sets up two scheduled tasks running as **`NT AUTHORITY\LocalService`**, a built-in low-privilege account, with the least privilege (see [When it reports](#when-windows-reports)). The token goes in `C:\ProgramData\Heimdall\token`, with permissions limited to LocalService (read), SYSTEM and Administrators. It never appears on a command line.

**Upgrading:** download the new release's `install-windows.ps1`, `collect.ps1`, `SHA256SUMS` and `SHA256SUMS.sigstore.json` and run the installer again, the same way. It replaces `collect.ps1` and both tasks (an install from before v0.4.14 has its daily task replaced by the hourly one) and keeps the hub URL; press Enter at the token prompt to keep the current token. There's no `heimdall-collect upgrade` on Windows yet. When the hub runs a newer release, `collect.ps1 -Push` says so on stderr.

**Changing the hub address:** `& 'C:\Program Files\Heimdall\collect.ps1' -SetHub https://new-ingest.example.com`, as Administrator. See [Moving to a new hub address](#moving-to-a-new-hub-address).

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
| **Never runs app code** | Sites are found by *reading* vhost files, `composer.json`/`composer.lock` and `package-lock.json` with `awk`. It never runs `php`, `composer`, `npm`, `node` or `artisan`, and never reads `.env`. | A compromised or broken app can't affect the collector, and secrets stay put |
| **Reports its own checksum** | It sends the SHA-256 of itself with every snapshot | Tampering shows up as "collector changed" (M8) |
| **Installed from a release, not the hub** | You download it from a tagged release and verify `SHA256SUMS` | A compromised hub can't push code to your servers |

### What it never touches
- `.env` files, config file contents, environment variables
- Users, groups, SSH keys, shell history
- Process lists or process arguments
- Any file other than `/etc/os-release`, `/proc/uptime`, `/etc/machine-id` (only a hash of it is sent, see [Many servers](#many-servers-enrollment-keys)), the package database, `/var/run/reboot-required`, enabled nginx/Apache vhost files, each discovered app's `composer.json`, `composer.lock` and `package-lock.json`, its own script file and the token file (plus, for the opt-in [privilege watch](#privilege-watch), its events file and whether `/etc/pam.d/sudo`, `su` and `sshd` contain its line)
- Application source code, `vendor/`, logs or storage

### What it trusts
- **The package manager's own output.** If an attacker has root, they can make the collector report anything. See [anomaly-signals.md](anomaly-signals.md) for what Heimdall does about that.
- **The system tools in `/usr/bin` and `/bin`.** Those can only be replaced by root.

---

## Installing

**Quickest:** **Hosts → Add a host** in the UI gives you a one-line command running `install.sh` from the release. It verifies the release's [signature](deployment.md#release-signatures) and checksums, creates the user and token, schedules pushes (hourly, after boot and after package changes; see [When it reports](#when-it-reports)) and sends the first report. On the hub's own box it uses `/etc/heimdall-collect`, so the hub's config is never touched.

### Many servers: enrollment keys

To add a batch of servers, create one **enrollment key** instead of a host per server: **Hosts → Add servers** in the UI, or `heimdall enroll create`. A key is scoped to one org and environment (and gives each server its tags), expires (after 1 hour to 30 days, 24 hours by default), and can be limited to a number of servers. Each server it enrolls becomes a host named after its hostname, with **its own ingest token**; the key itself can never send reports.

```sh
# On the hub (or use Hosts → Add servers): only the key goes to stdout
sudo heimdall enroll create --org acme --env prod --tag web --expires 24h --uses 20 --label "web rollout"

# On each server: paste the key when asked (it isn't echoed or put on a command line)
curl -fsSLO https://github.com/realmwatch/heimdall/releases/download/vX.Y.Z/install.sh &&
  sudo sh install.sh --hub https://ingest.example.com --enroll

# Or many at once, from your own machine (needs passwordless sudo, or root login):
read -rs KEY   # paste the key (it isn't shown), then Enter
for h in web-01 web-02 web-03; do
  printf '%s\n' "$KEY" | ssh "$h" 'cd "$(mktemp -d)" && curl -fsSLO https://github.com/realmwatch/heimdall/releases/download/vX.Y.Z/install.sh && sudo sh install.sh --hub https://ingest.example.com --enroll-stdin'
done
unset KEY
```

The Add servers page also gives cloud-init user data for new VMs (it contains the key, so keep that key short-lived and limited) and the Windows command.

- **Approval, on by default.** A server enrolled with a key that requires approval is *waiting for approval*: the hub answers its reports (`202 Accepted`, so the collector stays quiet) but doesn't store them, and nothing about it alerts. Approve or reject it under **Waiting for approval** on the Add servers page, or with `heimdall enroll pending` and `heimdall enroll approve --org acme web-01`; reject removes the host (`heimdall host rm`). Its next hourly report after approval counts. Turn approval off (`--no-approval`, or untick **Require approval**) only for a key you keep to yourself.
- **Each server once.** The installer and collector send `X-Heimdall-Machine`, the hex SHA-256 of `heimdall-machine:` and `/etc/machine-id` (Windows: the `MachineGuid` registry value). The ID itself never leaves the server. A server already in the org is refused (`already enrolled as web-01`), and re-running `install.sh --enroll` on a server whose token still works keeps that token: it's an upgrade, not a second host. So an ssh loop over the whole fleet is safe.
- **Same address as reports.** Enrolling is a `POST` to `/api/v1/ingest` with `Authorization: Bearer hmd_enroll_…`, so a reverse proxy that forwards only that path needs no change. The answer is the new token (`text/plain`, `201 Created`) with `X-Heimdall-Host: <name>`, and `X-Heimdall-Pending: 1` when it waits for approval.
- **Guarded.** Keys are stored only as hashes, audit-logged when created, used and revoked, and rate-limited (wrong keys count toward the per-address failure limit; each key enrolls at most 60 servers a minute). Revoke one early with `heimdall enroll revoke` or the page's **Revoke**; the hosts it added keep their tokens.

The hub must run a release with enrollment keys before servers can enroll; an older hub answers `401`, and the installer says it can't enroll yet.

### By hand


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
  heimdall-collect-soon.service heimdall-collect-changes.service heimdall-collect-changes.path /etc/systemd/system/
#    (optional) delete the PathChanged= lines in heimdall-collect-changes.path for package
#    managers this box doesn't have, and add your sites' deploy markers (see "Reporting
#    after deploys"); install.sh does both for you
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
| After a deploy | About a minute after a site deploys (its `current` symlink swaps, or `composer.lock` changes), or after `heimdall-collect deployed` in the deploy script, no sudo needed: see [Reporting after deploys](#reporting-after-deploys) | Hourly only, unless the deploy script runs `soon.sh` with sudo | `Start-ScheduledTask -TaskName 'Heimdall collector'` (as Administrator) |

The hub runs its tripwire rules on every report, so these event reports let it see changes within minutes instead of the next morning.

### After package changes

**systemd.** Three small units, none of which change the collector's own sandbox:

1. `heimdall-collect-changes.path` watches the package database: `/var/lib/dpkg/status` (dpkg), `/var/lib/rpm/rpmdb.sqlite` (rpm 4.16+, as on RHEL/Rocky/Alma 9) or `/var/lib/rpm/Packages` (older rpm), `/lib/apk/db/installed` (apk) and `/var/lib/pacman/local` (pacman). `install.sh` keeps only the paths that exist on the box.
2. Each change starts `heimdall-collect-changes.service`, which only runs `systemctl restart --no-block heimdall-collect-soon.timer`. It runs as root (to talk to systemd) with no network, no capabilities and a read-only filesystem; `systemd-analyze security` rates it 1.1.
3. `heimdall-collect-soon.timer` (`OnActiveSec=60s`) then starts `heimdall-collect-soon.service`, which starts the usual `heimdall-collect.service`, at most 12 times per rolling hour (see [the cap](#the-cap-on-event-reports)). It's sandboxed like `heimdall-collect-changes.service`, and only writes its count in `/var/lib/heimdall-collect/events`. The hourly and boot timers start `heimdall-collect.service` directly, so the cap never touches them.

Restarting the timer restarts its countdown, so the report goes out 60 seconds after the *last* change. A whole `apt upgrade` sends one report, about a minute after it ends. A change made while a report is running restarts the countdown too, so it gets a report of its own a minute later.

For rpm the path unit watches `rpmdb.sqlite` itself, not `/var/lib/rpm`: read-only queries by root (`dnf makecache`, `rpm -q`) rewrite the sqlite `-shm` and `-wal` files beside it, but `rpmdb.sqlite` changes only when packages do.

**Without systemd** (Alpine with OpenRC, Debian without systemd, containers), `install.sh` adds a hook for the package manager it finds:

| Package manager | Hook |
|---|---|
| apk | `/etc/apk/commit_hooks.d/heimdall-collect` (on `post-commit`) |
| apt | `/etc/apt/apt.conf.d/80heimdall-collect` (`DPkg::Post-Invoke`) |

Both run `/usr/local/lib/heimdall-collect/soon.sh` as root. It returns at once and always succeeds, so it can't slow down or break the package manager. A background process waits until there have been no changes for 60 seconds (a lock directory in `/run` holds the time of the last change), then pushes as the `heimdall` user, just like the hourly cron job. Its output goes to syslog (`logger -t heimdall-collect`). There's no hook for rpm or pacman without systemd; those boxes report hourly.

Event reports count toward the hub's rate limit of 30 reports per hour per host (`[ingest] rate_per_host`; hubs set up before v0.4.13 have `"10/h"` in their config, which still fits hourly reports plus a few events). The 60-second wait keeps a busy upgrade to one of them.

#### The cap on event reports

With systemd, at most **12 event reports** go out per rolling hour: those after package changes, site deploys, `heimdall-collect deployed` and the privilege watch. The hourly report is never capped. Anyone on the server can set off a deploy report, so without a cap a local user could keep the host over the hub's limit of 30 reports an hour, and the hub would reject its hourly reports too. With the cap, a host sends at most about 12 + 1 + (a boot) reports an hour, whatever happens on it.

Past the cap, `heimdall-collect-soon.service` logs one line and skips that report:

```
heimdall-collect: skipping this event report: 12 already in the last hour (the limit is 12); the next hourly report includes the change
```

Nothing is lost: every report is a full snapshot, so the next one (hourly, or an event report once the hour has room) includes the change. The count is the Unix times of the last hour's event reports, one a line, in `/var/lib/heimdall-collect/events` (root's, `0600`). The cap needs systemd 243 or later (`ExecCondition=`); older systemd ignores the line and doesn't cap. Without systemd, event reports come only from root's package hooks, so there's no cap.

## Reporting after deploys

A deploy changes a site's Composer packages, and so its findings. With systemd, the collector sends a report **about a minute after a deploy** instead of on the next hourly run, two ways, through the same path unit and 60-second wait as [package changes](#after-package-changes):

1. **Automatically**, for the sites it found when it was installed: no change to your deploy scripts.
2. **On request**, with `heimdall-collect deployed` at the end of a deploy script, for any site. It needs no sudo.

Either one is enough. Using both is fine: a deploy that sets off both still sends one report, a minute after the last change.

### What's watched automatically

When `install.sh` runs (and so on `sudo heimdall-collect upgrade`, which runs it), it asks the collector for each site's deploy markers (`heimdall-collect --deploy-watches` prints them) and adds them to `heimdall-collect-changes.path` as `PathChanged=` lines:

| Site layout | How it's recognized | Watched | Fires when |
|---|---|---|---|
| **Zero-downtime** (Forge, Ploi, Envoyer, Deployer): `/home/forge/example.com/current → releases/N` | The app root (or its parent) is a symlink to a folder next to it | The folder holding the symlink: `/home/forge/example.com` | The deploy swaps `current` to the new release |
| **In place** (`git pull` then `composer install` in the site folder) | Anything else | `<root>/composer.lock` and `<root>/vendor/composer/installed.php`, if they exist | `composer.lock` changes (new packages), or Composer records a new deployed commit in `installed.php` |

Why these paths, checked with real systemd (252 and 255) and Composer 2.10:

- **A watch on `current` itself, or on `current/composer.lock`, never fires on a deploy.** systemd's `PathChanged=` follows a symlink to its target: it watches `releases/N`, and swapping the symlink (`ln -sfn`, or renaming a new symlink over it, as Forge and Ploi do) changes neither. systemd does re-resolve the symlink afterwards, so such a watch would only see later writes inside the new release. A watch on the folder holding `current` sees the swap itself.
- **That folder also changes when** `.env` is saved (Forge and Ploi keep it there) or a new top-level entry appears. What happens inside `releases/` and `storage/` (logs, cache, new release folders) doesn't count: watches aren't recursive. So an `.env` edit sends a report too, which is harmless.
- **`composer install` doesn't rewrite `vendor/autoload.php`** when nothing changed (Composer writes it only if its content differs), so it isn't watched. `vendor/composer/installed.php` holds the root package's commit, so Composer rewrites it whenever a new commit is installed. A `git pull` that changes `composer.lock` fires that watch as well.

**Limits:**
- **The first 50 sites**, in the order the collector finds them (nginx, then Apache, then `HEIMDALL_SITES`), at most 100 paths. Every watched path costs systemd an inotify watch on each folder along it. With more sites, `install.sh` prints `watching deploys of the first 50 of N sites`; use `heimdall-collect deployed` for the rest.
- **The list is made at install and upgrade time.** A site added later, or one switched between in-place and zero-downtime deploys, is picked up the next time `install.sh` or `sudo heimdall-collect upgrade` runs. A plain `sudo heimdall-collect upgrade` with no newer release to install still refreshes the list and restarts the path unit, and changes nothing else. It says `watching 3 sites for deploys (was 2)` when the list changed, and nothing about it otherwise. Until then, `heimdall-collect deployed` covers a new site.
- Only paths that exist when it runs are watched. `cat /etc/systemd/system/heimdall-collect-changes.path` shows the list; the site lines are at the end.
- Sites are found as described in [Sites & Laravel](#sites--laravel). A site that isn't found (no vhost, not in `HEIMDALL_SITES`) isn't watched.

### `heimdall-collect deployed`

Add it as the last line of the deploy script, after the new release is live:

**Laravel Forge:** the site's **Deployments** tab, **Deploy Script**. Add it at the end, after `$ACTIVATE_RELEASE()` on a zero-downtime site:

```sh
heimdall-collect deployed || true
```

**Ploi:** the site's **Deploy script**. Add it at the end:

```sh
heimdall-collect deployed || true
```

**What it does:** it touches `/var/lib/heimdall-collect/deployed` and exits. It doesn't push anything and doesn't wait: the path unit sees the change and the report goes out about a minute later, as `heimdall` in its usual sandbox. It prints nothing when it works.

**It needs no sudo.** Forge and Ploi run the deploy script as the site user (`forge`, `ploi`, or an isolated site user), and that's enough: the file is writable by everyone.

**It never fails a deploy.** `deployed` always exits `0`. When it can't help, it says why on stderr (Forge and Ploi show it in the deploy log) and still exits `0`:

| Message | Meaning |
|---|---|
| `/var/lib/heimdall-collect/deployed is missing; re-run the installer …` | The collector is older than this feature, or was installed by hand. Run `sudo heimdall-collect upgrade` |
| `without systemd nothing watches deploys …` | See [Without systemd](#without-systemd) |
| `couldn't touch /var/lib/heimdall-collect/deployed …` | The file's mode was changed; re-running the installer resets it to `0666` |

The `|| true` covers a server where the collector isn't installed (`heimdall-collect: command not found`) or is too old to know `deployed` (it prints its usage and exits `2`). Without it, Forge or Ploi would mark the deploy failed there.

### Security

- **What anyone can do with the trigger file:** make the collector send one report, about a minute later. `/var/lib/heimdall-collect` is root's (`0755`), so nobody else can replace the file, link it elsewhere or add files next to it. The file itself is `0666` and its content is never read by anything: not by the collector, not by systemd, not by the hub. The report is the normal one, built from the server's own state as `heimdall`, so writing the file can't change what's reported, send data to the hub or run anything.
- **What it can't do:** start a report sooner than 60 seconds after the last change (every change restarts the countdown), or stop the hourly report.
- **The worst case is capped.** Touching it about once a minute would mean about 60 reports an hour, more than the hub's limit of 30 per hour per host (`[ingest] rate_per_host`). But event reports are [capped at 12 per rolling hour](#the-cap-on-event-reports), and the hourly report bypasses the cap, so the host stays well under the hub's limit and its hourly reports always get through. The same holds for anyone who can write a watched site file.
- **What the cap costs:** while someone keeps the cap used up, a genuine event (a deploy, a package change, a `sudo` the privilege watch records) waits for the next hourly report instead of going out a minute later. It's still recorded and sent; only the minute-later report is skipped. Each skip leaves a `skipping this event report` line in `journalctl -u heimdall-collect-soon`, so a steady stream of them is visible.
- **The disk:** anyone who can run commands on the server can already fill its disk through `/tmp`. The `0666` file adds no new way to do that.
- **The automatic watches** need nothing from site users: systemd (root) watches the paths, and the collector still reads only `composer.json`, `composer.lock`, `.git/config` and `.git/HEAD`, as `heimdall`.
- **Compared with the sudoers rule** this page used to suggest (`forge ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block heimdall-collect.service`), nothing is added to sudoers, and a deploy user who never had sudo needs none.

### Checking that it worked

After a deploy, on the server:

```sh
journalctl -u heimdall-collect-soon.timer -u heimdall-collect-soon -u heimdall-collect -n 20 --no-pager   # the countdown, the cap, the report
systemctl list-timers heimdall-collect-soon.timer                                # a countdown in progress
```

Then on the hub, the host's page shows **Last report** a minute or so after the deploy, and the site's packages and findings match the new release.

To see what's watched: `heimdall-collect --deploy-watches` (as `heimdall`, or as root with `HEIMDALL_ALLOW_ROOT=1`) and the end of `/etc/systemd/system/heimdall-collect-changes.path`.

### Without systemd

With cron (Alpine with OpenRC, Debian without systemd, containers), nothing watches deploys: `install.sh` makes no trigger file, and `heimdall-collect deployed` prints `without systemd nothing watches deploys; the next hourly report will include this deploy.` and exits `0`. The deploy shows up in the next hourly report, as before.

To report sooner there, run the package hooks' debounced script as root, which also returns at once:

```sh
sudo -n /usr/local/lib/heimdall-collect/soon.sh || true
# sudoers: forge ALL=(root) NOPASSWD: /usr/local/lib/heimdall-collect/soon.sh
```

### Other ways

**Report right away**, with no 60-second wait, from a deploy user allowed this one command in sudoers:

```sh
sudo -n systemctl start --no-block heimdall-collect.service || true
# sudoers (sudo visudo -f /etc/sudoers.d/heimdall-collect):
#   forge ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block heimdall-collect.service
```

sudo matches the arguments exactly, so the user can't start any other unit.

**By hand**, as a user who can already use sudo (this one waits for the push):

```sh
sudo -u heimdall sh -c 'set -a; . /etc/heimdall/collect.env; exec /usr/local/bin/heimdall-collect --push'
```

On the hub's own box the collector's settings are in `/etc/heimdall-collect/collect.env`.

**Not recorded:** the snapshot doesn't say a deploy was announced, or for which site. A new snapshot field would make older hubs refuse the push (they reject unknown fields), and the trigger file is writable by everyone, so whatever it said about a site couldn't be trusted. The site's `deployed_at` (the `composer.lock` time) still shows when its packages last changed.

## Usage

| Command | What it does |
|---|---|
| `heimdall-collect --print` | Write a snapshot to stdout, to review or to save for `heimdall import` |
| `heimdall-collect --push` | Send a snapshot to the hub |
| `heimdall-collect --site-repos` | Print the site repositories a push would send (see [Site repositories](#site-repositories)) |
| `heimdall-collect --site-branches` | Print the sites' checked-out branches a push would send (see [Site branches](#site-branches)) |
| `heimdall-collect --deploy-watches` | Print the site paths watched for deploys (see [What's watched automatically](#whats-watched-automatically)) |
| `heimdall-collect deployed` | Ask for a report in about a minute, from a deploy script, as any user; always exits `0` (see [`heimdall-collect deployed`](#heimdall-collect-deployed)) |
| `heimdall-collect --version` | Print the collector version |
| `sudo heimdall-collect set-hub https://…` | Report to another hub address from now on, once a test report there works (see [Moving to a new hub address](#moving-to-a-new-hub-address)) |

**Send a report now:** `sudo systemctl start heimdall-collect.service` (with systemd), or `sudo -u heimdall heimdall-collect --push`. Run by hand without `HEIMDALL_URL` set, `--push` loads the installed `/etc/heimdall/collect.env` (or `/etc/heimdall-collect/collect.env`) the way the systemd unit does, if it's readable, owned by root and writable by nobody else. It still refuses to run as root. On a terminal, when it finds no settings, it says how to send one.

**Push mode settings** (environment variables, usually from a systemd `EnvironmentFile`):

| Variable | Default | Meaning |
|---|---|---|
| `HEIMDALL_URL` | none (required) | Hub ingest URL, e.g. `https://heimdall.example.com:8443` |
| `HEIMDALL_TOKEN_FILE` | `/etc/heimdall/token` | The host's ingest token |
| `HEIMDALL_CA_FILE` | none | CA bundle to pin the hub's certificate |
| `HEIMDALL_SITES` | none | Extra app roots to inventory, space-separated (e.g. queue workers with no vhost) |
| `HEIMDALL_DISCOVER_SITES` | `1` | Set to `0` to skip reading nginx/Apache vhost files |
| `HEIMDALL_DETECT_REPOS` | `1` | Set to `0` to stop reading sites' `.git/config` and `.git/HEAD` (see [Site repositories](#site-repositories) and [Site branches](#site-branches)) |

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

## Moving to a new hub address

To rename the hub's ingest hostname (say `ingest.example.com` to `new-ingest.example.com`):

1. **Add the new name in front of the hub first:** DNS, the proxy or tunnel route, its certificate, and any firewall or allowlist rule. Keep the old name working.
2. **On each server**, point the collector at the new name:

   ```sh
   sudo heimdall-collect set-hub https://new-ingest.example.com
   ```

   It sends a real report to the new address first, as the `heimdall` user with the server's own token and settings, the way the timer does. Only if the hub answers is `HEIMDALL_URL` changed in `collect.env` (written to a new file in the same directory and renamed over it, keeping its owner and mode; nothing else in the file changes). The timer, path units and cron job read `collect.env` on every run, and `upgrade` reads the hub from it, so there's nothing to restart.

   ```
   heimdall-collect: sending a test report to https://new-ingest.example.com
   heimdall-collect: hub changed: https://ingest.example.com -> https://new-ingest.example.com (in /etc/heimdall/collect.env)
   ```

   If the new address doesn't answer 2xx, nothing changes, and it says what the hub there answered:

   ```
   heimdall-collect: sending a test report to https://new-ingest.example.com
   heimdall-collect: hub rejected the token (HTTP 401); check /etc/heimdall/token
   heimdall-collect: the hub at https://new-ingest.example.com doesn't know this server's token; is it the same hub?
   heimdall-collect: not changed; still reporting to https://ingest.example.com
   ```

   A `401` means a hub answered but doesn't know this server's token: the name probably points at another hub. A `403` is usually something in front of the hub (a firewall, WAF or proxy rule), or the hub's `[ingest] allow_cidrs`. `could not reach` is DNS, routing or TLS. The same address as now is a no-op (`already reporting to …; nothing to change`). It runs as root and takes an `https://` URL only: a host, an optional port and path.

   On Windows, as Administrator: `& 'C:\Program Files\Heimdall\collect.ps1' -SetHub https://new-ingest.example.com`. It does the same test first and then replaces `C:\ProgramData\Heimdall\hub-url`, which both scheduled tasks read. The test report runs as the Administrator, not LocalService; the next scheduled report is the usual one. Re-running `install-windows.ps1` later writes its `-HubUrl` again, so give it the new address.
3. **Keep the old name** until every server reports on the new one: until `set-hub` has run on all of them (an ssh loop works, as for [enrollment](#many-servers-enrollment-keys)), and the old name's proxy or tunnel log has gone quiet.
4. **Then set the hub's `[ingest] public_url`** in `heimdall.toml` to the new name and `sudo heimdall restart`, so the install commands on Add servers show it. After that, retire the old name.

## Privilege watch

An opt-in tripwire for "someone used root". It records **that** privileged access happened, never what was typed.

```sh
sudo sh install.sh --hub https://ingest.example.com --watch-privilege        # time and kind only
sudo sh install.sh --hub https://ingest.example.com --watch-privilege-users  # also who, and from which IP
sudo sh install.sh --hub https://ingest.example.com --no-watch-privilege     # remove it
```
On a server that already has the collector (0.4.23 or later), `upgrade` takes the same options, with no hub URL to repeat:

```sh
sudo heimdall-collect upgrade --watch-privilege-users
```
Re-running `install.sh`, and a plain `sudo heimdall-collect upgrade` (which runs it), keeps the current choice. It's stored as `HEIMDALL_PRIVILEGE_WATCH=on|users|off` in `collect.env`.

**Finding the servers that aren't watched:** the collector reports what its hook records. The host list's **Privilege** column and its *Privilege watch* filter (`/hosts?only=privilege`) show every Linux server that doesn't record who and from where: watch off, partly removed, time and kind only, no source IP (a hook from before 0.4.23), or a collector too old to say. The dashboard's Fleet card counts them, and the host page says what's missing and the command that fixes it.

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

### npm packages (snapshot v4)

Laravel apps usually build their frontend with npm, so the collector also reads `<app root>/package-lock.json` when there is one, and the hub matches its packages against OSV's npm advisories. Findings belong to the site, next to its Composer ones. Grant read access the same way:

```sh
sudo setfacl -m u:heimdall:r /home/forge/example.com/package-lock.json
```

- **Lockfile versions 1, 2 and 3** (npm 6 and later). Versions 2 and 3 list packages under `"packages"`, keyed by their `node_modules/` path; an aliased package (`"string-width-cjs": "npm:string-width@^4"`) is reported under its real name. Version 1 nests them under `"dependencies"`. Version 2 has both, and `"packages"` wins.
- **Dev dependencies** keep npm's flag: a package is `dev` when every copy of that name and version is marked `"dev": true` (needed only to build or test the app). `"devOptional"` packages count as runtime, since a production install can include them. Version 1 marks dev packages the same way.
- **Same caps as the rest:** only a readable regular file of at most 32 MiB is read, names and versions must match npm's rules (a git URL, a tarball or an `npm:` alias version is skipped), the same name at several versions (nested `node_modules`) is kept, and at most 5,000 packages are sent per site. An unreadable or malformed file sends none; the site itself is still reported.
- **Like `composer.lock`,** the file must be in npm's normal pretty-printed layout (two-space indents). A minified lockfile yields no packages.
- **Not read yet: `yarn.lock` and `pnpm-lock.yaml`.** Both could be parsed the same way (yarn's v1 format and Berry's YAML list `name@range:` headers with a `version` line; pnpm's lists `name@version:` keys), but yarn.lock has no dev flag at all, so it would also take `package.json`'s `devDependencies` and walking the dependency graph to tell dev from runtime packages. List the site's `package-lock.json` if you have one, or wait for a later version.

**Why dev dependencies don't need attention:** a Vite or webpack plugin runs when you build the frontend, on a developer's machine or in CI, and never handles a request in production. A vulnerability in it is real, but it's a build-time risk, not exposure of the running site. The hub lists dev findings with a **dev** badge (last in each list), but leaves them out of what needs attention, the fix commands and the severity, known-exploited and fixable counts; they're counted apart as "on dev dependencies". Composer's `packages-dev` aren't told apart: `composer.lock` is read as one list, as before.

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

### Site branches

So a hand-off can target the branch each site deploys from (see [Every site on the repository](deployment.md#every-site-on-the-repository-and-where-the-pull-request-goes)), the collector reports each site's checked-out branch. It reads **only `.git/HEAD`**, the first line of it, and nothing else in `.git` (the remote comes from `.git/config`, above). git is never run. `ref: refs/heads/<branch>` gives the branch; a bare commit hash is a detached checkout, reported as that commit with no branch. Anything else (another kind of ref, junk, an empty or oversized file) is left out. A branch name is sent only if it's at most 200 characters of letters, digits, `.`, `_`, `-` and `/` and follows git's rules (no `..`, `//`, leading `-` or `.`, or trailing `/`, `.` or `.lock`); the hub checks it again.

It looks, in order, first match wins:

1. `<app root>/.git`, through the root's symlinks (so for `<base>/current` it's the release's `.git`).
2. For a release layout (`<base>/current` or `<base>/releases/<n>`): `<base>/.git`, beside `releases/`.
3. Either of those can be a `.git` *file* holding `gitdir: <path>` (a worktree or a submodule): the `HEAD` it points to is read, if that's inside the site's tree.

It never leaves the site's own tree: the app root, or `<base>` for a release layout, with every symlink resolved. A `current` that points outside `<base>`, a `.git` symlink or `gitdir:` pointer that leads outside, and a `HEAD` that is itself a symlink are all ignored. The repository caches (`<base>/repo`, `<base>/.dep/repo`) aren't read for this: their `HEAD` is the remote's default branch, not what's deployed.

**Zero-downtime deploys:**

| Layout | Branch reported |
|---|---|
| `current` → `releases/<n>`, and the release kept its `.git` | The release's branch, or its commit if it was checked out detached |
| `current` → `releases/<n>` with no `.git`, and a `<base>/.git` beside `releases/` | `<base>/.git/HEAD`'s branch |
| `current` → `releases/<n>`, no `.git` anywhere | Nothing: the branch is unknown |

**Unknown is normal,** not an error: a push never fails over it, and the site page says "Branch: unknown (no git checkout found, common with zero-downtime deploys)". An operator can set the branch there (**Branch**, "set"), and the manual value wins over what the collector finds. The same permissions as `.git/config` apply: the `heimdall` user needs to enter `.git` and read `HEAD`:

```sh
sudo setfacl -m u:heimdall:r /home/forge/example.com/.git/HEAD
```

**How it's sent:** in a request header, `X-Heimdall-Site-Branches: v1 <root> branch:<name>,<root> commit:<sha>` (just `v1` when none are known), at most about 4 KB, for the same reason as the repositories' header: a snapshot field would make an older hub refuse the push. A push without it (an older collector) leaves the hub's stored branches alone, and an older hub ignores it. `heimdall-collect --site-branches` prints the value; `HEIMDALL_DETECT_REPOS=0` turns it off too.

**Known limitations**
- `include` lines aren't followed, so `server_name`/`root`/`fastcgi_pass` must be in the vhost file itself. That's true for Forge, Ploi and most hand-written configs.
- Regex server names (`~^…`), roots containing variables (`$…`) and TCP PHP pools (`127.0.0.1:9000`) are skipped or reported without a PHP version.
- `composer.lock` and `package-lock.json` must be in their tools' normal pretty-printed layout. A minified lock file yields no packages.
- `package-lock.json` is read only from the app root, so a frontend in a subfolder (or a Node app whose document root isn't `public`) isn't found. List that lockfile in `HEIMDALL_LOCKFILES`.
- Caddy, LiteSpeed and apps inside Docker containers aren't discovered yet. List their roots in `HEIMDALL_SITES`, or wait for M9.

## Exit codes & messages

| Exit | Meaning |
|---|---|
| `0` | Success |
| `1` | Error, with a one-line reason on stderr (see below) |
| `2` | Wrong usage |

`heimdall-collect deployed` is the exception: it always exits `0`, so it can't fail a deploy (see [`heimdall-collect deployed`](#heimdall-collect-deployed)).

| Message | Fix |
|---|---|
| `refusing to run as root` | Run as the `heimdall` user: `sudo -u heimdall heimdall-collect …` |
| `… is readable by other users` | `chmod 400 /etc/heimdall/token` |
| `HEIMDALL_URL must use https://` | Use an `https://` URL, or a local `http://127.0.0.1` proxy |
| `hub rejected the token (HTTP 401/403)` | The token was rotated or the host removed. Get a new one with `heimdall host add`. |
| `the hub rejected the enrollment key (mistyped or revoked)` (install.sh) | Check the key, or create a new one: the old one may have been revoked |
| `enrollment key expired` / `enrollment key used up` (install.sh) | Create a new key (Hosts → Add servers), with a longer expiry or a higher server limit |
| `this server is already enrolled as web-01` (install.sh) | The hub has this server (by machine ID). Keep its existing token (`/etc/heimdall/token`), or remove that host on the hub first |
| `this hub can't enroll servers yet` (install.sh) | Upgrade the hub to the release the installer came from, or use a token from Add a host |
| `waiting for an admin to approve it on the hub` (install.sh) | Not an error: approve the server under Hosts → Add servers, or `heimdall enroll approve`. Until then the hub discards its reports. |
| `hub rejected the snapshot as invalid (HTTP 422)` | Run `--print` and check the output with `heimdall import --check` |
| `could not reach https://… (curl exit N)` | No answer from the hub. curl's own error is on the line before; check the URL, DNS, firewall and that the hub is up |
| `hub returned HTTP N: …` | The hub answered with an error; the rest of the line is the first line of its reply. Check the hub's log (`journalctl -u heimdall`) at that time |
| `rate limited by the hub (HTTP 429)` | It's running too often. The default limit is 30 per hour per host (`[ingest] rate_per_host`). |
| `curl is required for --push` | Install curl |
| `not changed; still reporting to https://…` (set-hub) | The test report to the new address failed; the lines before say what it answered. See [Moving to a new hub address](#moving-to-a-new-hub-address) |

## Testing changes to the collector

```sh
make shellcheck         # lint (Docker)
make test-collector     # run on every supported distro, then validate (incl. a fake-vhost
                        # site fixture on Ubuntu 22.04 and Alpine: test/sites-fixture.sh)
```

To add a distro, add a line to `collector/test/run-containers.sh`.
