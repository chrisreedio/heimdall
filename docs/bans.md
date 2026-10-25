# Bans at Cloudflare's edge (off by default)

Heimdall can turn [repeat offenders](failed-logins.md) into bans at Cloudflare's edge. Think of it as an air defence network:

- **Sensors:** the collectors (failed SSH logins) and Cloudflare (zones, DNS, security events).
- **Command and control:** the hub. It scores every offender, decides what deserves a ban, and keeps track of every ban until it ends.
- **Identify-friend-or-foe:** [IP awareness](ip-awareness.md). Heimdall never fires on your staff, automation, infrastructure, the tailnet, private networks or Cloudflare's own edge.
- **Enforcement:** Cloudflare. An account-level IP list holds the bans, and one custom rule in each zone you opt in challenges or blocks every address on it.

Bans are **off** until you choose a mode. Start in **shadow** mode: it records what it *would* ban, so you can tune the scoring on your own traffic before anything is written.

## Modes

Set `[bans] mode` in `heimdall.toml` (`heimdall config update` adds the section, off), then `sudo heimdall restart`.

| Mode | What it does |
|---|---|
| `off` | Nothing is scored. The default. |
| `shadow` | Scores every offender and records what would have been proposed or banned, with its score breakdown. **No Cloudflare writes and no notifications**, except an optional daily digest (`shadow_digest = true`). Shown on `/bans` as **Would have banned**. |
| `propose` | Creates a proposal, sends a card to your [notify destinations](deployment.md#notifications) (Discord, Slack, webhook), and writes to Cloudflare **only after an operator approves it** on `/bans`. |
| `auto` | Bans without approval, within the caps. A ban that would break a cap becomes a proposal instead. |

`propose` and `auto` need `[cloudflare]` on, because the zones come from its sync.

In `shadow` or `off`, Heimdall never adds anything to Cloudflare. If an earlier `propose` or `auto` mode left bans behind and the write token is still installed, it keeps removing them as they expire. To stop that too, use **pause**.

### Pause all

On `/bans`, any operator or admin can press **Pause all Cloudflare writes**. You can also run `heimdall bans pause [--note why]`. The switch is stored in the database, and every write checks it first, so pausing takes effect immediately, even in the middle of a sync.

While paused, approvals, unbans and expiries wait. Resume with the button or `heimdall bans resume`.

## Who is a candidate

Only addresses on the [offender list](failed-logins.md#repeat-offenders) can be candidates, so nothing IP awareness vouches for ever gets this far. Because a ban applies to the whole hub, the list is checked across every org: an address that any org knows (a label, a sign-in, one of its hosts) is never a candidate, even where another org doesn't know it.

Before a ban is proposed, and again right before it's written, its **target** goes through a second check. If it overlaps anything known, it's dropped and shown as **friendly**, with the reason. Known means any of:

- a label in any org, manual or synced (deploy services, Tailscale);
- the tailnet, private ranges, loopback, link-local, multicast;
- Cloudflare's edge ranges;
- one of your hosts' report addresses;
- an address someone signed in to Heimdall from in the last 30 days;
- an address IP awareness vouched for among the failures.

If an approved ban turns friendly before it's written (someone labels the range), it's cancelled with `vouched: …` as the reason.

## Scoring

The owner of this feature put it plainly: "AI-driven attackers rotate addresses, so I don't know the right number." No single count can catch that, so Heimdall gives each candidate a score built from several signals.

Every part of the score is shown on `/bans`, in `heimdall bans list --candidates` and in each ban's record, so you can see exactly why something scored what it did.

| Part | Points (defaults, `[bans.weights]`) |
|---|---|
| hosts | `hosts` (2.0) per host it failed on, up to 10 |
| failures | `failures` (1.0) × log₂(1 + failures): 100 failures ≈ 6.7 |
| usernames | `usernames` (0.5) per distinct username, up to 20 |
| then succeeded | `succeeded` (10.0) if a login from it got in after failing |
| days | `days` (1.5) per extra UTC day it came back, up to 7 (slow and steady) |
| same network | `asn` (0.5) per other offender in the same ASN, up to 10 (only from Radar's cache, never looked up) |

A candidate is proposed (or recorded, in shadow mode) at `propose_at` (12.0) and above. It also needs `min_failures` (5) failures, unless it then succeeded.

The defaults are conservative. One host with 50 failures and 5 usernames scores about 10 and isn't proposed. The same address across three hosts, or one that got in, is.

### Networks

Attackers that rotate through a block of addresses keep each address under the threshold. To catch that, Heimdall groups offenders by **/24 (IPv4) or /48 (IPv6)**. A network with `network_addresses` (4) or more offenders that each stayed under the threshold scores `network` (0.6) × the sum of their scores. At `propose_at` it becomes a **network ban** on the prefix, unless anything in the prefix is friendly.

### Challenge or block

A ban **challenges** by default (Cloudflare's `managed_challenge`: a person gets through, a script doesn't). It **blocks** instead when:

- the address failed on `block_hosts` (3) or more hosts, or
- it failed and then logged in (`block_succeeded = true`).

A network is challenged (others may share it) unless one of its addresses got in.

### How long

| Offense | Length |
|---|---|
| First ban | `duration` (7 days) |
| Each repeat within a year | doubles: 14, 28, 56 days … |
| Cap | `max_duration` (90 days) |

A ban you lift by hand (**unban**) doesn't count as an offense. Cloudflare lists have no TTL, so Heimdall tracks every ban's expiry and removes the item itself.

IPv6 addresses are banned as their **/64**, since one machine usually holds a whole /64 and can rotate within it.

### Calibrating in shadow mode

1. Set `mode = "shadow"` and restart.
2. After a few days, open `/bans`. **Would have banned** lists what crossed the threshold, each with its breakdown; **Candidates** lists everyone, scored right now, including those that came close.
3. If attackers you'd want banned are missing, lower `propose_at` or raise a weight. If something looks too eager, raise it. `heimdall bans list --candidates --json` gives you the raw numbers.
4. When the list looks right, switch to `propose`.

## Approving

In `propose` mode, each proposal sends a card to your notify destinations. The card has:

- the address, its /24 or /48, and its network name and country (when Radar has it cached);
- the hosts it hit, its failures and distinct usernames, and when it was first and last seen;
- **THEN SUCCEEDED**, if a login from it got in after failing;
- what IP awareness says;
- the proposed action and duration;
- an **Approve / review** link to `ui.base_url/bans`.

There's no Discord bot, no buttons, and no public endpoint that can approve anything. The link opens the hub's UI (tailnet-only, behind sign-in), where approving or rejecting is one click: a POST with the CSRF token. Operators and admins can approve.

A run that proposes many bans at once sends cards for the first five. The last card says how many more are waiting.

Proposals nobody decides on lapse after `proposal_ttl` (72 hours). A rejected target isn't proposed again for 7 days.

From the CLI:

```sh
heimdall bans list [--status proposed|pending|active|shadow|ended] [--json]
heimdall bans approve [--note "..."] <id>
heimdall bans reject  [--note "..."] <id>
heimdall bans unban <id>
```

The hub writes CLI decisions to Cloudflare on its next sync, within a minute.

## Caps

| Setting | Default | What it limits |
|---|---|---|
| `max_per_hour` | 20 | new bans written per hour, however they were approved |
| `max_active` | 1000 | bans in the lists at once |

A ban past a cap waits, marked **waiting**, until there's room.

## Who sees what

**/bans** is for operators and admins (a nav link next to Offenders).

Bans are hub-wide at Cloudflare, so admins see everything, including the full audit log. An operator sees the bans and candidates that touched hosts in an org they operate. Other orgs' hosts are left out of what they see, and counted only. An operator also sees the zones whose names lead only to their orgs, as on `/surface`.

## Setting it up for real

### 1. A second token, with write access

The read-only `[cloudflare]` token never writes. Bans use their own token.

```sh
heimdall bans token-url     # prints the pre-filled "create token" link (also on /bans)
```

The link opens Cloudflare's form for an account-owned token ([template URL format](https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/)), pre-filled with **Zone > Zone WAF > Edit** (`firewall_services`), which the custom rules need.

> **Add one permission by hand:** **Account > Account Filter Lists > Edit**, for the IP lists. Cloudflare doesn't document the key for that permission group, so Heimdall doesn't guess it in the link.

Then store the token:

```sh
sudo heimdall bans set-token      # prompts with echo off; or --stdin
sudo heimdall restart
sudo heimdall bans status
```

`set-token` works exactly like `cloudflare set-token`:

- the token is written owner-only (0600) to `/etc/heimdall/cloudflare-bans-token`;
- a `LoadCredential=heimdall-cloudflare-bans:…` line is added to the hub's unit;
- the token is never in `heimdall.toml` and never printed.

`HEIMDALL_CLOUDFLARE_BANS_TOKEN_FILE` points elsewhere for development.

If the token sees more than one account, set `[bans] account_id`.

### 2. Opt zones in

On `/bans`, under **Zones**, **turn on** each zone the ban rules should protect. Only proxied names are protected: a request that doesn't go through Cloudflare never meets the rule. `/surface` also shows each zone's ban rule state as a column.

## What Heimdall writes to Cloudflare

Every write:

- checks the pause switch first;
- goes into the ban audit log (who, what, when, result), shown on `/bans`;
- is **idempotent**: what's already there is adopted, never added twice.

A failed write leaves the ban as it was, retried with backoff (1 minute, doubling, at most an hour), so nothing is lost.

**Two account-level IP lists**, `heimdall_challenge` and `heimdall_block` (`challenge_list`, `block_list`), created when first needed. An action belongs to a rule, so each action needs its own list and rule.

If the account can't hold a second list (a plan limit), blocks **fall back** to the challenge list. That's weaker, but nothing is dropped, and `/bans` says so.

**Items** are each ban's target (an address, a /24 or /48, or an IPv6 /64), with a comment `heimdall ban #12, block until 2026-11-01`. Items are added and deleted in bulk operations (one pending per account), which Heimdall polls until they're done.

**One custom rule per list in each opted-in zone**, in the `http_request_firewall_custom` phase entrypoint:

| Rule ref | Expression | Action |
|---|---|---|
| `heimdall_bans_challenge` | `ip.src in $heimdall_challenge` | `managed_challenge` |
| `heimdall_bans_block` | `ip.src in $heimdall_block` | `block` |

Heimdall finds its own rules by ref or description ("Heimdall bans: …") and edits only those. Your other rules are never touched.

New rules go after your existing ones, so your own skip or allow rules still apply first. A zone with no custom rules yet gets its entrypoint ruleset created. Heimdall checks the rules again every 6 hours, in case someone edited them in the dashboard.

Turning a zone off removes Heimdall's rules from it.

If writing a zone's rules fails (the plan's rule limit, a missing permission), the zone is marked **error** with Cloudflare's message on `/bans` and `heimdall bans status`. Other zones and the lists carry on.

## Alerts

Three [anomaly rules](anomaly-signals.md) come with this feature. They run every 5 minutes whatever the ban mode, and notify like the others.

- **`login_then_succeeded`** (high): an address nothing vouches for failed to log in and then got in, on the same host and UTC day.
  - It uses the same vouching as the offender list: a label, the tailnet, a private network, your hosts, a sign-in or Cloudflare's edge never fire.
  - Needs the [login watch](failed-logins.md).
- **`dns_unproxied`** (medium, always notifies): a name that leads to one of your hosts went from proxied to not proxied (from the surface map's change log). Its origin is public now. Needs `[cloudflare]`.
- **`cname_takeover`** (high): a name that leads to one of your hosts or sites has a CNAME whose target doesn't exist (NXDOMAIN), so anyone who registers it can serve your name. Needs `[cloudflare]`.

Each event raises one anomaly per host, once: acknowledging it doesn't make it come back. Names that lead to none of your hosts raise nothing (an anomaly belongs to a host), but `/surface` still flags them for admins.

## Status and CLI

```sh
heimdall bans status [--json]                  # mode, pause, token, lists, last sync, counts, zones
heimdall bans list [--status X] [--candidates] [--json]
heimdall bans approve|reject [--note ...] <id>
heimdall bans unban <id>
heimdall bans pause|resume [--note ...]
heimdall bans set-token [--stdin] [--file path] [--unit path]
heimdall bans token-url
```

## All settings

```toml
[bans]
mode              = "off"     # off, shadow, propose, auto
account_id        = ""        # empty: the only account the write token sees
every             = "10m"     # how often candidates are scored
window            = "168h"    # how far back failures count (at most 720h)
propose_at        = 12.0
min_failures      = 5
block_hosts       = 3
block_succeeded   = true
duration          = "168h"
max_duration      = "2160h"
max_per_hour      = 20
max_active        = 1000
proposal_ttl      = "72h"
networks          = true
network_addresses = 4
shadow_digest     = false
challenge_list    = "heimdall_challenge"
block_list        = "heimdall_block"

[bans.weights]
hosts = 2.0
failures = 1.0
usernames = 0.5
succeeded = 10.0
days = 1.5
asn = 0.5
network = 0.6
```

## API calls used

All checked in October 2026; tests use local fakes only.

- [Accounts list](https://developers.cloudflare.com/api/resources/accounts/methods/list/) (when `account_id` is empty)
- [Lists](https://developers.cloudflare.com/api/resources/rules/subresources/lists/): `GET`/`POST /accounts/{id}/rules/lists`
- [List items](https://developers.cloudflare.com/api/resources/rules/subresources/lists/subresources/items/): `GET` (cursor paging), `POST` and `DELETE /accounts/{id}/rules/lists/{list}/items`, each returning an `operation_id`
- [Bulk operation status](https://developers.cloudflare.com/api/resources/rules/subresources/lists/subresources/bulk_operations/methods/get/): `GET /accounts/{id}/rules/lists/bulk_operations/{op}` (`pending`, `running`, `completed`, `failed`)
- [Phase entrypoint](https://developers.cloudflare.com/api/resources/rulesets/subresources/phases/methods/get/): `GET /zones/{zone}/rulesets/phases/http_request_firewall_custom/entrypoint`, and `POST /zones/{zone}/rulesets` to create it
- [Ruleset rules](https://developers.cloudflare.com/api/resources/rulesets/subresources/rules/): `POST /zones/{zone}/rulesets/{ruleset}/rules`, `PATCH` and `DELETE …/rules/{rule}`
- [Custom lists](https://developers.cloudflare.com/waf/tools/lists/custom-lists/), for what an IP list accepts: IPv4 /8–/32, IPv6 /12–/128
