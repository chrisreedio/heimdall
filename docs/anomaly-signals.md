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

"Odd one out" means a new service, runtime or package that a host's **tag peers** don't have. For example, one `web` host in `prod` suddenly has a package the other `web` hosts don't.

**Silence is the strongest signal.** To avoid every other tripwire, an attacker has to keep the collector running *and* make it lie convincingly every day. Disabling the collector is easier, and Heimdall notices that.

---

## Keeping the noise down

Alerts you learn to ignore are worse than no alerts. Heimdall has four tools for this:

1. **Maintenance windows.** Set them per org, env or host, as one-offs ("Sat 02:00–04:00") or recurring ones. Changes and reboots inside a window don't alert.
2. **Patch plans** (M6). Upgrades that match a plan you're working through are expected.
3. **Learning period.** A new host's first few snapshots set its baseline, so you don't get 400 "new package" alerts on day one.
4. **Suppression.** Mute one rule for one host until a date, e.g. "this box runs Livepatch". Suppressions expire, so they can't be forgotten forever.

Every acknowledgment and suppression is written to the audit log with who did it and their note.

---

## When an alert fires

1. **Check whether it was you.** Look at your shell history, your team chat and recent deploys. Most alerts end here.
2. **If not, don't trust the host.** A compromised machine's own tools (`ps`, `ls`, logs) can lie too. Investigate from outside: the provider console and logs, network flow logs, and logs you've shipped off the host.
3. **Compare with peers.** The host page shows what differs from hosts with the same tags.
4. **Record what you found.** Acknowledge the alert with a note, so the next person, or you in six months, knows what happened.

---

## What Heimdall will never do here

- Collect anything new for detection (no process lists, file hashes, logs or users)
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
