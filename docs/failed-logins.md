# Failed logins and repeat offenders (opt-in)

Every server on the internet gets SSH password guesses. One server's log only tells you about that server. Heimdall adds up the failures across the whole fleet and shows which addresses keep coming back: the ones trying many of your hosts, the ones trying hardest, and, most importantly, any that **failed and then got in**.

This is **read-only**. The login watch never bans anyone, changes a firewall, or touches sshd. It only counts. (Bans at Cloudflare's edge are a separate, opt-in feature: see [bans.md](bans.md).)

## What's recorded, and what never is

For each source address, per server and UTC day:

- how many logins failed,
- how many **distinct usernames** were tried (a number, not the names),
- when it was first and last seen that day,
- whether a login from that address **then succeeded** (after its first failure that day).

Each day also gets a total, which includes addresses past the caps below.

**Never sent to the hub:** usernames, log lines, or anything else from the log. To count distinct usernames, the server keeps a short hash of each one in a root-only file next to the counts, for today and yesterday only; the names themselves are never written anywhere new.

It's **off by default** and turned on per server.

## Turn it on

When installing:

```sh
sudo sh install.sh --hub https://ingest.example.com --watch-logins
```

On a server that already reports:

```sh
sudo heimdall-collect upgrade --watch-logins      # on
sudo heimdall-collect upgrade --no-watch-logins   # off, and its counts deleted
```

Re-running the installer or `upgrade` keeps the current choice (`HEIMDALL_LOGIN_WATCH` in `collect.env`).

## How it works on the server

The collector runs as the unprivileged `heimdall` user and refuses to run as root, so it can't read auth logs. Two ways around that:

1. Add `heimdall` to `adm` or `systemd-journal`. That lets the collector read **every** log on the box, all the time: mail logs, application logs, anything a service writes. Too much.
2. A tiny root-run step that reads only sshd's lines and writes only counts. **This is what Heimdall does.**

`install.sh --watch-logins` installs `/usr/local/lib/heimdall/login-watch` (from the same release, checked against `SHA256SUMS`) and runs it before every push:

- **With systemd:** a oneshot unit, `heimdall-login-watch.service`, that the collector's own service pulls in (a drop-in with `Wants=` and `After=`), so it runs right before each push and a failure never stops the push. It's sandboxed: read-only filesystem except `/var/lib/heimdall-logins`, no network, no new privileges, and only the capabilities to read logs (`CAP_DAC_READ_SEARCH`) and hand the counts file to the `heimdall` group (`CAP_CHOWN`).
- **Without systemd:** the hourly `cron.sh` runs it as root before switching to the `heimdall` user.

It reads, in this order of preference:

1. the **journal** (`journalctl -t sshd -t sshd-session -t sshd-auth`), from the cursor it saved last time;
2. otherwise `/var/log/auth.log` (Debian, Ubuntu), `/var/log/secure` (RHEL, Rocky, Alma) or `/var/log/messages` (Alpine's busybox syslog), from the byte offset it saved last time. If the file was rotated meanwhile, it finishes the rest of `<file>.1` first. A half-written last line waits for the next run.

So each failure is counted once. It writes to `/var/lib/heimdall-logins/`:

| File | Owner, mode | Holds |
|---|---|---|
| `counts` | root:heimdall, 0640 | per address and day: failures, distinct usernames, first and last seen, then succeeded; per day: totals |
| `users` | root, 0600 | a short hash per (day, address, username), to count distinct usernames |
| `cursor` | root, 0600 | where it stopped: the journal cursor or the file, inode and offset |

The collector reads `counts` and sends it with each push in an `X-Heimdall-Logins` header. You can see exactly what it would send:

```sh
sudo -u heimdall heimdall-collect --logins
```

### What counts as a failure

sshd logs one attempt in several lines (sshd's own, PAM's, the disconnect). Heimdall groups lines by connection (sshd's process ID and the address) and counts a connection's attempts as the number of `Failed <method> for ...` lines or PAM's failure count (`authentication failure`, `PAM N more authentication failures`), whichever is more. A connection that only probed a username (`Invalid user ...`), hit `maximum authentication attempts exceeded`, or was disconnected or closed while authenticating (`... [preauth]`) counts as at least one.

Not counted: scanners that never tried to authenticate (`Received disconnect`, `Connection closed by <ip>` with no user, `Unable to negotiate`, banner errors) and `Failed none` (a client asking which methods exist).

Usernames are chosen by the client and can contain spaces or text like `x from 192.0.2.1 port 22`. Every line is read from the right, where sshd puts the real address, so a crafted username can't move the failure to someone else's address.

A success is `Accepted <method> for <user> from <ip>`; it sets **then succeeded** only if it came after that address's first failure on the same UTC day.

### Limits

- Days are UTC. Today's and yesterday's counts are kept on the server and resent on every push (the hub keeps the larger value, so resends never double count).
- At most 5,000 addresses per server per day are tracked individually; beyond that, failures only add to the day's total.
- Each push sends the addresses with the most failures, today's first, at most 200 and about 5 KB, so it fits beside the other headers on any hub. The rest still count in each day's total.
- A connection whose lines straddle two runs can be counted one extra time.
- With `UseDNS yes`, PAM names the client by host name; Heimdall joins that to sshd's line by process ID, or counts it in the day's total only.
- Syslog files in the traditional format have no year or zone; the server's current UTC offset is used.

**Windows** isn't covered yet. Failed logons are event 4625 in the Security log, which needs administrator rights, and the Windows collector deliberately runs as LocalService. Doing it properly needs a separate SYSTEM task in the same spirit as `login-watch`; until then a Windows host's page simply doesn't show the card.

## On the hub

Counts are stored per host, address and day, and kept **30 days**. Ingest checks every value (counts, times within the day and not in the future, addresses parsed and canonicalized, days only around today) and caps a push at 3 days and 200 addresses. A malformed header is ignored; it never fails the push.

### Known addresses are never offenders

Every address goes through [IP awareness](ip-awareness.md). If anything about the **address itself** is known, it's shown under **Known addresses** but never counted as an offender:

- a label: `staff`, `automation`, `infra`, `tailnet`, `private` (manual, or synced from a deploy service, Tailscale or Cloudflare),
- the built-in ranges: the tailnet, private networks, loopback, link-local,
- one of your hosts (the address its reports come from),
- a Heimdall sign-in from it around that time,
- Cloudflare's edge ranges (built in, even with `[cloudflare]` off).

A deploy service's account name doesn't vouch for an address (no usernames are reported anyway). A label belongs to an org, so an office range labeled in one org is still unknown to another.

If [Cloudflare Radar](cloudflare.md) is on, the network name and country of an offender ("AS64500 Example ISP (US)") are shown when Radar already has them cached. Ranking never queues addresses for Radar lookups, so a flood of attackers can't use up its daily budget.

### Repeat offenders

**Offenders** in the navigation (`/offenders`) ranks the unknown addresses over the last 24 hours or 7 days by:

1. how many hosts they failed on,
2. then total failures,
3. then the most recent.

Each row has the hosts hit, failures, the most distinct usernames tried on one host, first and last seen, and a red **then succeeded** pill when a login from it got in after failing (hover for the hosts). Each address links to its [IP page](ip-awareness.md#labeling-addresses), which lists where it failed in the last 30 days.

Each Linux host page has a **Failed logins** line: the last 24 hours' failures and the top five sources, with **also on N other hosts** for repeat offenders and the same **then succeeded** pill. A host without the watch shows the command to turn it on.

From the CLI (every org, or one):

```sh
heimdall offenders [--org acme] [--since 24h|7d|30d] [--json]
```

### Who sees what

Everything is scoped by org: a user sees failures only on hosts in orgs they can view. An address's host count, failures and "then succeeded" only include those hosts, so one org never learns another's.

## Bans

The login watch itself never bans anyone. [Bans](bans.md) (off by default) read this ranked list, which already excludes everything IP awareness vouches for, score each address, and propose (or, in shadow mode, only record) bans at Cloudflare's edge, approved on `/bans`. An address that failed and then logged in from nowhere known also raises the `login_then_succeeded` anomaly, whatever the ban mode.

## Troubleshooting

- **"Not counting: No sshd log found":** the server has no sshd entries in the journal and none of the log files. On a minimal image, sshd may log nowhere persistent; install rsyslog, or make the journal persistent.
- **"login watch can't count":** the collector couldn't read `/var/lib/heimdall-logins/counts`. Re-run `sudo heimdall-collect upgrade --watch-logins`.
- **Counts look stale:** run `sudo /usr/local/lib/heimdall/login-watch run` and check its output; with systemd, `journalctl -u heimdall-login-watch`.
