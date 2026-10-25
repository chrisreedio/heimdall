# Cloudflare (optional, read-only)

> **Status: built and off by default. Tested only against fakes of the documented API shapes.** Run `heimdall cloudflare status` first: it shows what your token and each zone's plan actually allow. See [What might differ](#what-might-differ).

If your sites sit behind Cloudflare, Heimdall can read your zones with a **read-only** API token and tell you:

- **Origins exposed:** DNS records that aren't proxied (grey cloud) and point straight at one of your hosts, so anyone can find the server's real address and go around Cloudflare.
- **Dangling records:** A and AAAA records whose address is none of your hosts, not Cloudflare's, not private and not labelled. They're often left over from a server that's gone. If that address now belongs to someone else, they can serve your name.
- **Sites not behind Cloudflare:** a site's server name that's in a zone but not proxied, has no record, or isn't in any zone the token can see.
- **Security events:** for each zone, the last 24 hours of events by action (block, challenge, …), the top countries, networks (ASNs) and paths, and request totals, plus up to 30 days of daily counts.
- **Who an unknown address belongs to:** Radar's network name for addresses nobody has labelled, e.g. "AS64500 Example ISP (US)", shown as context (still *unknown*) wherever addresses appear, such as privilege watch sessions.

It also fixes the client address of ingest behind Cloudflare (see [CF-Connecting-IP](#the-real-client-address-behind-cloudflare)).

Heimdall never writes anything to Cloudflare.

## Set it up

1. **Create a token.** The quick way: `heimdall cloudflare token-url` (also printed by `set-token`, and a button on the `/cloudflare` page for admins) prints a dashboard link with the read-only permissions below already filled in, on all zones. Add Radar by hand (it has no template key), check the list, and click Create. Or by hand: in the Cloudflare dashboard, **My Profile > API Tokens > Create Token > Create Custom Token**. Give it only these permissions:

   | Permission | Needed for |
   |---|---|
   | Zone > Zone > Read | listing zones and their plans |
   | Zone > DNS > Read | DNS records |
   | Zone > Analytics > Read | security events and request totals (GraphQL Analytics API) |
   | Account > Radar > Read | network names for unknown addresses (only with `radar = true`) |
   | Zone > Zone Settings > Read | optional: SSL/TLS mode, Always Use HTTPS and minimum TLS on the [attack surface](surface.md) |
   | Zone > SSL and Certificates > Read | optional: edge certificate expiry on the [attack surface](surface.md) |

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
| Request totals | GraphQL `httpRequests1hGroups` | daily totals and a last-24-hours count |
| Network names | `GET /radar/entities/asns/ip` | ASN, organization name and country per address, 7 days (misses 1 day) |

**Never stored:** individual events, client addresses (the raw-events fallback doesn't even ask for them), query strings, user agents. Paths are clipped to 120 characters.

Every request goes over HTTPS to `api.cloudflare.com` or `www.cloudflare.com` only (an in-process allowlist), with timeouts and response size caps. If Cloudflare is down or a request fails, the last good data stays: a failed zone list changes nothing, a zone whose records fail keeps its old ones, and the last sync's error is shown in `status` (and to admins on the overview).

Radar is asked about at most 20 addresses a minute and 2,000 a day, one a second, in the background: a page never waits for Cloudflare. Only public IPv4 addresses that no label or host explains are looked up. A Radar label is a guess of kind *unknown*: it adds context ("AS64500 Example ISP (US)") but never makes an address look known. After a permission error, lookups pause for 6 hours.

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
- **A record shows as dangling but it's yours**: label the address (it's then known), or check that the server reports from that address. A host that reports over IPv6 or through NAT has a different report address than its A record.
- **Report addresses all show Cloudflare**: turn on `ingest.behind_proxy` and check `status` says "CF-Connecting-IP trusted only from Cloudflare's edge".

## What might differ

Built from Cloudflare's documentation (October 2026), without a live account:

- GraphQL error wording for "not on this plan" and "no permission" is matched by text ("does not have access to the path", "not authorized"); an unrecognized error is shown as an error and retried next sync.
- The raw-events fallback on Free plans and its fields (`action`, `clientAsn`, `clientCountryName`, `clientRequestPath`) follow the [firewall events tutorial](https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-firewall-events/).
- Radar's ASN lookup is documented for IPv4; IPv6 addresses aren't looked up.
- The `httpRequests1hGroups` request totals are assumed available on every plan; if not, the overview shows "—".
