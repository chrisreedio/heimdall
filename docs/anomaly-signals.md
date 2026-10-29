# Anomaly signals

> **Status:** implemented. Triage with `heimdall anomaly list|ack|suppress` or the **Anomalies** page; define windows with `heimdall window add`.

Heimdall can notice when a host's reports look *wrong*: changes nobody planned, or patterns that are hard for an attacker to fake consistently. It does this using only the snapshots it already collects. It gets no new privileges, collects no new data, and doesn't contact your servers.

## The one thing to remember

**These are tripwires, not intrusion detection.**

Once an attacker has root on a server, they control what the collector reports. If they know Heimdall is there, they can keep sending believable, clean-looking snapshots. So:

- ✅ **An alert** is worth investigating.
- ❌ **No alerts** does *not* mean a host is clean.

Heimdall is good at catching **sloppy or automated attacks**, and just as often **your own unplanned changes**. For real intrusion detection, pair it with dedicated tools (see [Going further](#going-further)).

---

## The signals

| Signal | What it might mean | Common innocent reasons | Milestone |
|---|---|---|---|
| **Host went silent** | The collector was disabled or the timer removed | Host is down, network change, decommissioned without `host rm` | M3 (stale flag), M8 (alert) |
| **Replayed snapshot** | An old "clean" report is being resent to hide changes | None that matter: a quick network retry is ignored, and only an old payload resent later is flagged | M1 |
| **Clock skew** | Reports are being forged or replayed | The host's clock is wrong (no NTP). `import` is exempt, because manual snapshots are expected to be old. | M1 |
| **Unplanned package change** | Someone installed tools (`nmap`, `socat`, compilers) or removed security software | You or a colleague made a quick manual fix | M8 |
| **Package downgrade** | A rollback to reintroduce a vulnerable version | A deliberate rollback after a bad update | M8 |
| **Kernel changed without a reboot** | The report is forged, since a running kernel can't change in place | Live patching (Canonical Livepatch, kpatch) | M8 |
| **Unexpected reboot** | A reboot to load something malicious, or after a crash caused by an exploit | Provider maintenance, power loss, OOM crash | M8 |
| **Collector changed** | The script was tampered with to hide things | You upgraded the collector but didn't tell Heimdall about the new release | M8 |
| **Odd one out** | A miner, webshell runtime or backdoor service appeared | A legitimate deployment that only one host received | M8 |
| **Change reporting disabled** (`trigger_disabled`) | The change watch or the collector's timer was switched off, so changes stop being reported promptly | You disabled it while debugging, or uninstalled the collector | M8 |
| **Privileged access** (opt-in) | Someone used sudo, su or logged in as root over SSH outside a maintenance window | You or a colleague fixing something by hand; scripts that use sudo | Privilege watch |
| **Privilege watch disabled** (opt-in) | The PAM hook was removed or broken to hide privileged access | You turned it off with `--no-watch-privilege`, or a PAM file was replaced by a package upgrade | Privilege watch |
| **Uptime doesn't add up** (`uptime_inconsistent`) | A fake report: uptime grew faster than time passed, so the claimed boot time moved earlier | None known: the check allows 10 minutes and both the host's and the hub's clock. A container moved to another node reports that node's uptime | [Consistency](#reports-that-dont-add-up) |
| **Inventory reverted** (`inventory_reverted`, low) | An old report resent with fresh timestamps | A deliberate rollback, or a package installed and then removed again | [Consistency](#reports-that-dont-add-up) |
| **Package drop** (`package_drop`) | The inventory was gutted to hide things | A big cleanup outside a maintenance window | [Consistency](#reports-that-dont-add-up) |
| **Collector downgraded** (`collector_downgrade`) | An old or modified collector is sending the reports | You reinstalled from an older copy of `install.sh` | [Consistency](#reports-that-dont-add-up) |
| **OS changed** (`os_changed`) | The reports aren't coming from this host | A reinstall or an in-place distro migration (CentOS to Rocky) outside a window | [Consistency](#reports-that-dont-add-up) |
| **Failed, then logged in** (`login_then_succeeded`, high) | An address nobody knows guessed or stole a password: it failed SSH logins and then got in, the same day | A new colleague or a deploy service whose address isn't labelled yet: label it | [Bans](bans.md#alerts) |
| **Name no longer proxied** (`dns_unproxied`, medium) | A DNS record that leads to one of your hosts was switched to DNS-only, so the origin's address is public | A deliberate change for debugging, or a service that can't go through Cloudflare | [Bans](bans.md#alerts) |
| **CNAME takeover risk** (`cname_takeover`, high) | A name that leads to your host or site points (by CNAME) at a target that doesn't exist: whoever registers it can serve your name | A service you stopped using whose DNS record was left behind: delete the record | [Bans](bans.md#alerts) |

"Odd one out" means a new service, runtime or package that a host's **tag peers** don't have. For example, one `web` host in `prod` suddenly has a package the other `web` hosts don't.

**Silence is the strongest signal.** To avoid every other tripwire, an attacker has to keep the collector running *and* make it lie convincingly every day. Disabling the collector is easier, and Heimdall notices that.

### Silence as an alarm

Collectors report on a schedule (hourly is recommended) and whenever packages change. Heimdall treats a missing report as an alarm:

- **Fast alert** (`[hosts] alert_after`, default `"3h"`, `"0"` turns it off): when a host that has reported before goes quiet for longer than this, Heimdall raises a **Host went silent** anomaly and **notifies straight away** through the `[notify]` destinations (Slack, Discord, webhook or email; see [deployment.md](deployment.md#notifications)), not only in the next digest. High-signal anomalies (watches disabled, privileged access outside a window, high severity) are sent right away too. The check runs every 5 minutes.
- **Once per silence.** You get one alert when a host goes quiet, and one "reporting again" notice when it comes back. The anomaly stays open, with "reported again" added to it, until someone acknowledges it: a collector that went quiet and came back is what tampering looks like too.
- **Maintenance windows** apply. A host inside a window doesn't alert. If it's still quiet when the window ends, it does. Suppressing the `silence` rule for a host mutes the alert too.
- **Hosts on a daily timer (Linux collectors before v0.4.13, Windows before v0.4.14) aren't fast-alerted.** If a host's last two reports were further apart than `alert_after`, its collector isn't reporting often enough for the fast alert to mean anything. The `stale_after` check still covers it. This can't be gamed: making the gap that long means being silent for longer than `alert_after`, which raises the alert.
- The alert names the hosts (`org/host`) and nothing else about them: no OS, packages or findings.

The slower `stale_after` check (default 72h) still marks hosts as stale in the UI. It shares the same anomaly, so a silence is only raised once.

### Change reporting disabled

On every push the collector reports the state of its own triggers in an `X-Heimdall-Triggers` request header, never in the snapshot. For example:

```
X-Heimdall-Triggers: timer=enabled,active; changes=enabled,active
```

With systemd these are `systemctl is-enabled` and `is-active` for `heimdall-collect.timer` and `heimdall-collect-changes.path`. Without systemd it reports `cron=present|absent; hook=present|absent` for the cron job and the apk/apt hook. The Windows collector reports its two scheduled tasks as `task=<enabled>,<state>; changes=<enabled>,<state>`, e.g. `task=enabled,running; changes=enabled,ready`: whether the task is enabled (or `missing`), and its Task Scheduler state (`ready`, `running`, `queued`, `disabled`, or `no-triggers` when every trigger was removed or disabled). When a trigger that was on (enabled and active, or present) is now off, while the host keeps reporting, Heimdall raises **Change reporting disabled**. Each host is compared only with its own previous report. Older collectors that send no header never alert, and neither do hosts that never had the path unit. A state the collector couldn't read, such as when D-Bus is down, is reported as `unknown` and never alerts. The host page's Collector fact shows **change watch on** or **change watch off**.

An attacker with root can fake this header, just like the snapshot. It catches the easy move, `systemctl disable --now` or `Disable-ScheduledTask`, and the next one, stopping the collector entirely, sets off the silence alarm.

### Unchanged reports

Frequent reports are cheap. When a report's inventory matches the host's latest snapshot, Heimdall doesn't store a new snapshot. It records the report as a small *heartbeat* with its time and uptime. The inventory covers packages, pending updates, sites, containers, lockfiles, kernel, OS, reboot-required, skipped checks and the collector's version and checksum. Only `collected_at` and `uptime_seconds` change on every run, so only those are ignored. Reboots are still detected from each heartbeat's uptime. Changes (`host history`/`diff`) only list snapshots, so they only show real changes.

### Reports that don't add up

An attacker with root can make the collector send fake reports, but a fake has to agree with everything the hub has already seen from that host. These rules compare each report with the host's **own** previous report (heartbeats included where it matters) and need no collector changes. Like the other change rules, they start after the [learning period](#keeping-the-noise-down), so a host's first reports, and a hub that has just been upgraded, never alert. [Suppressions](#keeping-the-noise-down) apply to all of them.

| Rule | Severity | Fires when | Windows and plans |
|---|---|---|---|
| `uptime_inconsistent` | medium | Uptime grew more than 10 minutes beyond the time that passed since the previous report (snapshot or heartbeat), by both the host's clock (`collected_at`) and the hub's (received time). Put another way, the boot time (`collected_at` − uptime) moved earlier. | Don't apply: no maintenance makes uptime outrun the clock |
| `inventory_reverted` | low | A new snapshot's inventory is identical to an older snapshot's (not the previous one's), and packages changed on the way back. | Apply: a rollback in a window is expected |
| `package_drop` | high | The package count fell by more than 30% **and** at least 20 packages from one snapshot to the next. | Apply |
| `collector_downgrade` | medium | The collector's x.y.z version went backwards, and no collector release is trusted. | Apply |
| `os_changed` | medium | The os-release ID changed, such as `ubuntu` to `debian`. | Apply: a reinstall in a window is expected |

What they deliberately leave alone:

- **Reboots.** A smaller uptime is a reboot, which **Unexpected reboot** already covers, even when the reports are only minutes apart (a kernel upgrade reported, then a reboot), so it's never mistaken for **Kernel changed without a reboot**. Uptime that grows *less* than the time passed is a paused VM or a sleeping laptop (WSL), so it never alerts. Missing or zero uptimes (some containers) and `import`s are skipped.
- **Small removals.** An `apt autoremove` of a few packages is an ordinary **Unplanned package change**. A package drop replaces that anomaly for its report, so a gutted inventory is one alert listing the removals, not two. If you suppress `package_drop`, the report falls back to **Unplanned package change**. An empty package list means the package check was unavailable, and isn't counted as a drop.
- **Flapping that isn't packages.** A container that stops and starts again also returns a host to an earlier inventory, so **Inventory reverted** needs a package change. Snapshots stored before inventory hashes existed never match.
- **Collector rollbacks to a trusted release.** If any release is trusted (`heimdall collector trust`), an untrusted checksum is already **Collector changed** (high) from the first report, so the downgrade rule only adds a signal on hubs with no trusted releases. Dev builds (`0.4.13-dev.4`) compare as their release.
- **Time going backwards.** A report's `collected_at` can't land before the previous one's without tripping **Clock skew**: pushes must be within 15 minutes of the hub's clock, so a backwards step could be at most 30 minutes, between reports less than 30 minutes apart, which is what an NTP correction looks like. Imports are expected to be old. There's no separate rule.

### Privilege watch

Opt-in per server with `install.sh --watch-privilege` (see [collector.md](collector.md#privilege-watch)). It records *that* sudo, su or a root SSH login happened, and when, never what was typed. Usernames, and the IP address the session came from, are recorded only with `--watch-privilege-users`; the anomaly then names them ("by chris from 203.0.113.7").

- **Privileged access** (`privileged_access`, medium): events outside a maintenance window. One anomaly per host per day (UTC) with a count by kind, such as "4 privileged accesses outside a maintenance window on Oct 23, 2026 (UTC): 3 sudo, 1 root SSH", and with `--watch-privilege-users` who and from where ("... by alice from 203.0.113.7, bob"; a session with no remote address, such as a local console, names only the user). It names the first four and counts the rest ("+2 more"); the host page lists each event. Later events that day add to the open anomaly; after you acknowledge it, new events raise a fresh one. Events inside a window that covers the host (org, env or host scope) never count. Neither do sessions from a deploy service's synced address range, such as Laravel Forge SSHing in as root to deploy; a session that only uses a deploy service's account name (`forge` from an address outside its ranges) still counts. To count deploy-service sessions too, turn on the org's **count deploy-service sessions as privileged access** policy on the IP addresses page, or run `heimdall ip policy --org acme --count-services on` (off by default). See [IP awareness](ip-awareness.md#deploy-service-sessions-and-privileged-access). Collectors resend recent events on every push, and the hub dedupes them, so a resend never alerts twice.
- **Privilege watch disabled** (`privilege_watch_disabled`, high): the host reported the watch `on` before and now reports `off` or `partial` (a PAM line, the hook or its events file is missing) while still checking in. It's compared with the host's own previous report, so hosts that never turned it on never alert. A push without the header (an older collector) changes nothing.

- **Privileged access from an unknown address** (`privilege_unknown_source`, high) and **SSH from outside the tailnet** (`privilege_off_tailnet`, high, only with an org's tailnet-only policy): where sessions came from. An unknown-address anomaly closes itself once the address is known, for example when you label it as yours; the tailnet one doesn't. See [IP awareness](ip-awareness.md#alerts).
- **Stopped reporting, still on the tailnet** (`silent_online`, high): a host's collector has been quiet for `hosts.alert_after` (or `stale_after`) while Tailscale still saw its device online, or online well after its last report. The server is running, so the collector was likely stopped or blocked. A server that's powered off or unplugged drops off the tailnet too and raises only `silence`. Needs the [Tailscale integration](tailscale.md) and a sync less than an hour old; maintenance windows and suppressions apply.

All of them use the usual [suppression](#keeping-the-noise-down): `heimdall anomaly suppress --rule privileged_access ...`.

---

## Keeping the noise down

Alerts you learn to ignore are worse than no alerts. Heimdall has four tools for this:

1. **Maintenance windows.** Set them per org, env or host, as one-offs ("Sat 02:00–04:00") or recurring ones. Changes and reboots inside a window don't alert.
2. **Patch plans** (M6). Upgrades that match a plan you're working through are expected.
3. **Learning period.** A new host's first few reports set its baseline, so you don't get 400 "new package" alerts on day one.
4. **Suppression.** Mute one rule for one host until a date, e.g. "this box runs Livepatch". Suppressions expire, so they can't be forgotten forever.

Every acknowledgment and suppression is written to the audit log with who did it and their note.

**Several at once:** on the Anomalies page, tick the anomalies (shift-click ticks a run, the header box ticks every one you can triage), then **Acknowledge selected** with one note, or **Mute selected** for a number of days, which mutes each selected signal on its host and acknowledges the anomalies. It works without JavaScript too. Up to 500 per request; you need the operator role in every selected anomaly's org, or nothing is changed. Each anomaly is audited on its own, as if acknowledged one by one, and ones someone else closed in the meantime are skipped and counted.

Heimdall closes one kind of anomaly itself: **Privileged access from an unknown address**, once the address becomes known ([IP awareness](ip-awareness.md#when-the-address-becomes-known)). It's acknowledged as `heimdall` with a note saying who the address is, and audited as `anomaly.resolve`. The Anomalies page lists everything closed in the last 30 days, these marked **auto-resolved**.

---

## When an alert fires

1. **Check whether it was you.** Look at your shell history, your team chat and recent deploys. Most alerts end here.
2. **If not, don't trust the host.** A compromised machine's own tools (`ps`, `ls`, logs) can lie too. Investigate from outside: the provider console and logs, network flow logs, and logs you've shipped off the host.
3. **Compare with peers.** The host page shows what differs from hosts with the same tags.
4. **Record what you found.** Acknowledge the alert with a note, so the next person, or you in six months, knows what happened.

---

## What Heimdall will never do here

- Collect anything new for detection (no process lists, file hashes, logs or users). The one exception is opt-in on each server: the [privilege watch](#privilege-watch) records the time and kind of privileged access, and usernames only with a second opt-in.
- Connect to a server to investigate
- Take automatic action such as isolating a host or killing processes

These would all break the core rule that **a compromised hub can't touch your servers.**

---

## Going further

If you need real intrusion detection, these tools pair well with Heimdall:

| Tool | What it adds |
|---|---|
| **auditd** | Kernel-level audit trail of logins, commands and file access |
| **AIDE** | File integrity checking: alerts when system binaries or configs change |
| **osquery** / **Wazuh** | Full host visibility and detection rules (agent-based, much larger footprint) |
| **Off-host logging** | Shipping logs to a separate box means an attacker can't quietly erase them |
