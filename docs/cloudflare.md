# Cloudflare (optional, read-only)

> **Status: built and off by default. Tested only against fakes of the documented API shapes.** Run `heimdall cloudflare status` first: it shows what your token and each zone's plan actually allow. See [What might differ](#what-might-differ).

If your sites sit behind Cloudflare, Heimdall can read your zones with a **read-only** API token and tell you:

- **Origins exposed:** DNS records that aren't proxied (grey cloud) and point straight at one of your hosts, so anyone can find the server's real address and go around Cloudflare.
- **Dangling records:** A and AAAA records whose address is none of your hosts, not Cloudflare's, not private and not labelled. They're often left over from a server that's gone. If that address now belongs to someone else, they can serve your name.
- **Sites not behind Cloudflare:** a site's server name that's in a zone but not proxied, has no record, or isn't in any zone the token can see.
- **Security events:** for each zone, the last 24 hours of events by action (block, challenge, …), the top countries, networks (ASNs) and paths, and request totals, plus up to 30 days of daily counts.
- **Web offenders:** the client addresses Cloudflare blocked or challenged, per zone and day, for the threat list. This stores client addresses; see [Web offenders](#web-offenders).
- **IP labels from your IP lists:** the account-level IP lists you already keep (an "offices" list of `203.0.113.4`, "Alice Example - Developer") become IP labels, so privilege watch, anomalies and the IP addresses page know those addresses without anyone typing them in again. See [IP lists](#ip-lists).
- **Who an unknown address belongs to:** Radar's network name for addresses nobody has labelled, e.g. "AS64500 Example ISP (US)", shown as context (still *unknown*) wherever addresses appear, such as privilege watch sessions.

It also fixes the client address of ingest behind Cloudflare (see [CF-Connecting-IP](#the-real-client-address-behind-cloudflare)).

Heimdall never writes anything to Cloudflare with this token (only [bans](bans.md) do, with a second token of their own).

## Set it up

1. **Create a token.** The quick way: `heimdall cloudflare token-url` (also printed by `set-token`, and a button on the `/cloudflare` page for admins) prints a dashboard link with the read-only permissions below already filled in, on all zones. Add Radar and Account Filter Lists by hand (they have no template key), check the list, and click Create. Or by hand: in the Cloudflare dashboard, **My Profile > API Tokens > Create Token > Create Custom Token**. Give it only these permissions:

   | Permission | Needed for |
   |---|---|
   | Zone > Zone > Read | listing zones and their plans |
   | Zone > DNS > Read | DNS records |
   | Zone > Analytics > Read | security events, web offenders and request totals (GraphQL Analytics API) |
   | Account > Radar > Read | network names for unknown addresses (only with `radar = true`) |
   | Zone > Zone Settings > Read | optional: SSL/TLS mode, Always Use HTTPS and minimum TLS on the [attack surface](surface.md) |
   | Zone > SSL and Certificates > Read | optional: edge certificate expiry on the [attack surface](surface.md) |
   | Account > Account Filter Lists > Read | optional: IP labels from your account's [IP lists](#ip-lists) |

   Under **Zone Resources**, pick *Include > All zones from an account*, or just the zones you want. Nothing else: no Edit permissions, no account settings. A client IP filter (your hub's address) and an expiry date are good ideas.

   Permission names are from [Cloudflare's permissions reference](https://developers.cloudflare.com/fundamentals/api/reference/permissions/) and the [Radar guide](https://developers.cloudflare.com/radar/get-started/first-request/). Cloudflare's API page for the Radar lookup also lists *User Details Read*; if `status` says Radar has no permission with Radar Read, add that too (it's read-only).

2. **Turn it on** in `heimdall.toml` (`sudo heimdall config update` adds the section, off):
   ```toml
   [cloudflare]
   enabled         = true
   zones           = []       # zone names or IDs; empty = every zone the token can read
   sync_every      = "1h"     # 15m to 168h
   security_events = true
   radar           = true
   connecting_ip   = true     # see below
   ```

3. **Store the token.** It never goes in the config file:
   ```sh
   sudo heimdall cloudflare set-token     # prompts with echo off; or pipe it with --stdin
   ```
   This writes `/etc/heimdall/cloudflare-token` (owner-only, atomically, like `ai set-key`) and adds `LoadCredential=heimdall-cloudflare:/etc/heimdall/cloudflare-token` to the hub's unit, so the hub reads it as a private systemd credential. Outside systemd, set `HEIMDALL_CLOUDFLARE_TOKEN_FILE` to a 0600 file.

4. **Check and apply:**
   ```sh
   sudo heimdall cloudflare status   # token check, zones, plans, datasets, last syncs; never prints the token
   sudo heimdall restart
   sudo heimdall cloudflare sync     # optional: sync now instead of within a minute of start
   ```

The overview is at **/cloudflare** (operators and admins), and each site page gets a Cloudflare card.

## What's fetched, and what's stored

| What | From | Stored |
|---|---|---|
| Edge ranges | `https://www.cloudflare.com/ips-v4` and `/ips-v6`, daily, no token | as "Cloudflare" infra labels (source `cloudflare:edge`) |
| Zones | `GET /zones` (50 a page) | ID, name, plan name, status |
| DNS records | `GET /zones/{id}/dns_records` (500 a page) | A, AAAA and CNAME only: name, type, content, proxied, TTL |
| Security events | GraphQL `firewallEventsAdaptiveGroups` (or `firewallEventsAdaptive`, see plans) | counts only: per action, top 10 countries, ASNs and paths; daily rows kept 30 days |
| Web offenders | GraphQL `firewallEventsAdaptiveGroups` (or `firewallEventsAdaptive`) | per client address, zone and day: blocked and challenged events by action, first and last seen, ASN, network name, country; 30 days |
| Request totals | GraphQL `httpRequests1hGroups` | daily totals and a last-24-hours count |
| Network names | `GET /radar/entities/asns/ip` | ASN, organization name and country per address, 7 days (misses 1 day) |
| IP lists | `GET /accounts`, `GET /accounts/{id}/rules/lists` and, for mapped lists only, `.../lists/{id}/items` (500 a page), hourly | each IP list's ID, name, description and item count; a mapped list's addresses and comments as IP labels |

**Never stored:** individual events, query strings, user agents, paths of web offenders' requests, and the address of any request Cloudflare let through. The security summaries hold no client address (their raw-events fallback doesn't even ask for one). Client addresses are stored only as [web offenders](#web-offenders): requests Cloudflare blocked or challenged, from addresses nobody knows. Paths in the summaries are clipped to 120 characters.

Every request goes over HTTPS to `api.cloudflare.com` or `www.cloudflare.com` only (an in-process allowlist), with timeouts and response size caps. If Cloudflare is down or a request fails, the last good data stays: a failed zone list changes nothing, a zone whose records fail keeps its old ones, and the last sync's error is shown in `status` (and to admins on the overview).

Radar is asked about at most 20 addresses a minute and 2,000 a day, one a second, in the background: a page never waits for Cloudflare. Only public IPv4 addresses that no label or host explains are looked up. A Radar label is a guess of kind *unknown*: it adds context ("AS64500 Example ISP (US)") but never makes an address look known. After a permission error, lookups pause for 6 hours.

## IP lists

Ops teams often keep account-level IP lists in Cloudflare (**Manage Account > Configurations > Lists**) for their WAF rules: an "offices" list whose items are `203.0.113.4` with the comment "Alice Example - Developer", a "vpn" list of exit ranges, a list of CI runners. Heimdall can read them (read-only, with **Account > Account Filter Lists > Read** on the same token) and turn their items into [IP labels](ip-awareness.md), so a privilege watch session from one of those addresses is known, not an alert.

**Map each list.** Global admins see every IP list the token can read on **/cloudflare**, under **IP lists**, each with a kind:

| Kind | Its items are | The item's comment becomes |
|---|---|---|
| ignore (the default) | not labels | |
| `staff` | one person's address each | the person |
| `office` | a trusted network: an office, a VPN exit, a home network, not one person | the person (whose, or what) |
| `automation` | a deploy service or CI | the label's note |
| `infra` | your own servers | the label's note |

Every list starts ignored; nothing becomes a label until an admin picks a kind. Saving syncs at once (when there's a token), and the lists are read again every hour. ASN, hostname and redirect lists aren't offered, and neither are the lists [bans](bans.md) write.

**Item to label.** Each item's `ip` (an address or a CIDR range) becomes a label named after the list (`offices`), for every org: Cloudflare is hub-wide, like its zones, so its labels are too, the same as the edge ranges and deploy services. Items without an address (ASNs, hostnames, redirects) and repeats are skipped. The label's source is `cloudflare:list:<list id>`. Badges and an address's labels show it as `<list> · <comment>`, e.g. "offices · Alice Example - Developer".

**Read-only in Heimdall.** The **IP addresses** page lists the labels grouped by list, with the list's kind, item count, last sync and a link to it in the Cloudflare dashboard, and no remove button: change the list in Cloudflare. A list deleted at Cloudflare, or set back to ignore, loses its labels.

**Lists and manual labels are independent.** A sync never edits or removes a manual label, and removing a manual label never touches a list's. Both are shown wherever an address's labels are. When both cover an address, the more specific range still wins (a manual `/32` beats a list's `/24`); at the **same** range size the list's label comes first, whatever the kinds, since the list is what the team keeps current.

Each list's last sync (labels stored, error) is kept with the other synced sources (`ip_source_state`, source `cloudflare:list:<id>`), and the list read itself as `cloudflare:lists`. If the token lacks the permission, the sync records "the token can't read IP lists (add Account > Account Filter Lists > Read)", shown on the card and in `heimdall cloudflare status`; the rest of the Cloudflare sync carries on, and labels from the last good sync stay. `heimdall cloudflare sync` reads the lists too.

## Plans

Cloudflare limits analytics by plan. Heimdall asks for each zone what it can do and says so instead of failing:

| | Free | Pro (~$20/mo) | Business | Enterprise |
|---|---|---|---|---|
| Zones and DNS records | yes | yes | yes | yes |
| Aggregated security events (`firewallEventsAdaptiveGroups`) | usually **not** in the API* | yes | yes | yes |
| Raw security events (`firewallEventsAdaptive`) | yes, sampled* | yes | yes | yes |
| Request totals (`httpRequests1hGroups`) | yes | yes | yes | yes |
| How far back | 31 days on every plan for security events ([docs](https://developers.cloudflare.com/waf/analytics/security-events/)) | | | |

\* On a zone without the aggregated dataset, Heimdall falls back to the latest 1,000 raw events of the last 24 hours and counts them itself; the overview marks these **sampled** (totals are a floor) and stores no daily rows for them. If neither dataset is available the zone shows **not on this plan**. Per-zone limits vary; `heimdall cloudflare status` prints each dataset's availability and how many days back it reaches, read from the GraphQL [settings node](https://developers.cloudflare.com/analytics/graphql-api/features/discovery/settings/).

Every window Heimdall asks for spans at most 24 hours, so it fits each plan's maximum query span.

## Web offenders

Web offenders are the web half of Heimdall's [threat list](threats.md): the attacker addresses other services can pull. The SSH half comes from [failed logins](failed-logins.md). With `security_events = true`, each zone sync also records which client addresses Cloudflare blocked or challenged.

**Privacy change:** before this, Heimdall stored no client address from Cloudflare. It now stores the client IP of every request Cloudflare blocked or challenged on your zones, for 30 days, unless the address is friendly (see below). Requests Cloudflare let through are never recorded, and nothing about a request beyond what's listed here is kept. To collect none, set `security_events = false`. That also turns off the zone security summaries.

### What's stored

One row per client address, zone and UTC day:

| Field | What |
|---|---|
| address | the client IP, IPv4 or IPv6, as Cloudflare saw it |
| events | how many acted-on events came from it that day |
| per action | the same count split by action, e.g. `block 40, managed_challenge 2` |
| first and last seen | to the hour from the aggregated dataset, to the second from raw events |
| network | ASN, network name and country, as Cloudflare reports them for the event |
| sampled | whether the counts come from capped raw events (a floor, see below) |

**Not stored:** paths, query strings, hosts, user agents, rule IDs, ray IDs, headers, or any request Cloudflare allowed.

### Which actions count

Only requests Cloudflare stopped or made prove themselves. Cloudflare writes some names in two styles, and both are accepted:

| Counted (stored as) | Cloudflare's names |
|---|---|
| `block` | `block` |
| `challenge` | `challenge` (interactive) |
| `js_challenge` | `jschallenge`, `js_challenge` (non-interactive) |
| `managed_challenge` | `managedChallenge`, `managed_challenge` |
| `connection_close` | `connectionClose`, `connection_close` |

Not counted: `allow`, `bypass`, `skip`, `log` and `unknown`, plus the outcomes of a challenge (`challengeSolved`, `jschallengeSolved`, `managedChallenge…Solved`, `…Bypassed`, `managed_challenge_skipped`). A solved or bypassed challenge means a client passed, which is usually a real visitor. The action list is from Cloudflare's [security fields reference](https://developers.cloudflare.com/logs/reference/security-fields/). The query asks for these actions only (`action_in`), and Heimdall checks each answer against the list again.

### Token permission

**Zone > Analytics > Read**, the same permission as the security summaries. Nothing new to grant.

### Datasets and plans

| | Dataset | Fields | Counts |
|---|---|---|---|
| Aggregated (Pro and up, usually) | `firewallEventsAdaptiveGroups`, grouped by `clientIP`, `clientAsn`, `clientASNDescription`, `clientCountryName`, `action`, `datetimeHour` | up to 10,000 groups a day | exact, unless a day hits 10,000 groups |
| Sampled (Free, usually) | `firewallEventsAdaptive`, the same fields plus `datetime` | the latest 1,000 events a day | a **floor** |

A zone whose summary already fell back to raw events goes straight to raw events. A zone that refuses the aggregated dataset ("does not have access to the path") falls back too. If neither dataset is available, or the token can't read the zone's analytics, the zone is skipped. The summary's state on `/cloudflare` already says why.

A **floor** means the true numbers are at least this high. On a sampled day only the latest 1,000 acted-on events are seen, so a busy attacker may have sent more, and an address whose events were all earlier in the day may be missing entirely. Such rows are marked `sampled`. An aggregated day that returns the full 10,000 groups is marked the same way.

### When it syncs, and the budget

It runs in the zone sync, at `sync_every` (default 1h), right after each zone's summary: **one extra GraphQL query per zone per sync**. Each query asks for whole UTC days, at most 24 hours each, so it fits every plan's maximum query span:

- **today**, so far, on every sync;
- **yesterday**, until it has been fetched at least an hour after midnight UTC (late events have arrived by then). That fetch is final, and the day is never asked for again.

Older days are never fetched, so there is no backfill: if the hub is down for more than a day, the days it missed stay empty. With hourly syncs and 10 zones that's 240 GraphQL queries a day for this, well inside Cloudflare's GraphQL rate limit (300 queries per 5 minutes per user).

### Retention

30 days, the same as [failed logins](failed-logins.md). Rows for days more than 30 days ago are deleted on every sync. Deleting a zone from Cloudflare, or dropping it from `zones`, deletes its rows at the next sync.

### Friendly addresses are never stored

Before anything is written, each address is checked against what Heimdall knows, the same checks as the [ban guard](bans.md):

- a range labelled in **any** org, whatever its kind (staff, office, automation, infra, tailnet, private; manual or synced), except labels of kind *unknown*;
- the tailnet (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`), private networks, loopback, link-local, unspecified and multicast space;
- Cloudflare's published edge ranges;
- any host's report address;
- an address someone signed in to Heimdall from in the last 30 days;
- anything that isn't a public unicast address.

Each sync also deletes stored rows of any address that has become friendly since, for example after you label it.

### Which org a zone belongs to

Zones have no owner in Heimdall. A zone belongs to the orgs whose hosts or sites its records lead to: an A or AAAA record at a host's report address (following CNAMEs within the synced zones), or a record whose name is one of a site's server names. That's the same join the `/cloudflare` page uses to decide who sees a zone. It's rebuilt every sync. A zone that leads to no org's hosts or sites belongs to none: it shows in the hub-wide threat list, never in an org's. A zone that serves two orgs is in both lists.

## The real client address behind Cloudflare

With Cloudflare → a local proxy (Caddy) → the hub, the ingest listener sees the proxy's `X-Forwarded-For`, whose last hop is a Cloudflare edge server, not your server. So host report addresses and ingest logs would all say "Cloudflare".

With `[cloudflare] enabled = true`, `connecting_ip = true` and `ingest.behind_proxy = true`, ingest uses `CF-Connecting-IP` instead, but **only** when:

- the connection comes from loopback (the local proxy), as `behind_proxy` already requires, and
- the proxy's own, last `X-Forwarded-For` hop is inside Cloudflare's published edge ranges, and
- there's exactly one `CF-Connecting-IP` header holding one valid address.

Otherwise the header is ignored. A client that talks to your proxy directly and sends its own `CF-Connecting-IP` gets nowhere: the proxy's last hop is then the client's own address, not Cloudflare's. Earlier `X-Forwarded-For` entries are client-supplied and never trusted. Cloudflare overwrites `CF-Connecting-IP` on every request it proxies.

This needs no token: the edge ranges are public, and are built in until the first daily sync. That's why it runs whenever `[cloudflare]` is on, token or not. It's off when `[cloudflare]` is off, so a hub that isn't behind Cloudflare never trusts the header, and a hub owner who hasn't asked for it makes no calls to Cloudflare.

Note: this also changes what `ingest.allow_cidrs` and the per-address failed-login limit see: the real client instead of Cloudflare's edge. If you had listed Cloudflare's ranges in `allow_cidrs` to let traffic through, list your servers' addresses instead (or set `connecting_ip = false`).

Caveat: anything that reaches your origin through Cloudflare's network gets Cloudflare's view of the client, including requests from other Cloudflare customers' Workers, which Cloudflare labels with its own address. The ingest token is what authenticates a server; the address is for logs, rate limits and the overview.

## Access

Zones aren't owned by an org, so the UI shows a record only to people who can see what it points at:

- **/cloudflare** is for operators and admins. An operator sees the records that lead to hosts or sites in their orgs; a zone's security counts only when everything Heimdall matched in that zone is theirs (otherwise "shared zone").
- **Dangling records** (which lead to no org) and sync errors are shown to global admins only.
- The **site card** shows a site's names to anyone who can see the site, with the zone's counts under the same rule.

## Troubleshooting

- **`Token check: … Invalid API Token`** but zones list fine: an *account-owned* token fails the user token-verify endpoint and still works. Otherwise re-create the token and run `set-token` again.
- **`Zones: can't list`**: the token lacks Zone > Zone > Read, or its zone resources don't include any zone.
- **`events:no` / "not on this plan"**: the plan doesn't include the dataset in the API (common on Free); Heimdall uses sampled raw events if it can.
- **"no permission" for security events**: add Zone > Analytics > Read.
- **Radar: no permission**: add Account > Radar > Read (and, if that's not enough, User Details Read), or set `radar = false`.
- **IP lists: "the token can't read IP lists"**: add Account > Account Filter Lists > Read to the read-only token (no Edit), then save the mapping or wait for the hourly sync.
- **A record shows as dangling but it's yours**: label the address (it's then known), or check that the server reports from that address. A host that reports over IPv6 or through NAT has a different report address than its A record.
- **Report addresses all show Cloudflare**: turn on `ingest.behind_proxy` and check `status` says "CF-Connecting-IP trusted only from Cloudflare's edge".

## What might differ

Built from Cloudflare's documentation (October 2026), without a live account:

- GraphQL error wording for "not on this plan" and "no permission" is matched by text ("does not have access to the path", "not authorized"); an unrecognized error is shown as an error and retried next sync.
- The raw-events fallback on Free plans and its fields (`action`, `clientAsn`, `clientCountryName`, `clientRequestPath`) follow the [firewall events tutorial](https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-firewall-events/).
- The web offender fields `clientIP`, `clientAsn`, `clientCountryName`, `action` and `datetime` follow the tutorial above. `clientASNDescription` and the `datetimeHour` dimension come from the GraphQL schema, untested against a live zone. The action names are from the Logs [security fields reference](https://developers.cloudflare.com/logs/reference/security-fields/), and both spellings are accepted because GraphQL's style may differ.
- Radar's ASN lookup is documented for IPv4; IPv6 addresses aren't looked up.
- The `httpRequests1hGroups` request totals are assumed available on every plan; if not, the overview shows "—".
- IP lists: a token without account permissions may still list its account under `GET /accounts`, or not; either way the sync says the list permission is missing. The dashboard link for a list (`dash.cloudflare.com/<account>/configurations/lists/<id>`) is assumed from the dashboard's layout.
