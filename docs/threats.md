# Threat list: attacker addresses for other services

Heimdall's threat list holds the attacker addresses and networks the hub has seen across your fleet. Other services can pull it: a firewall, an ipset, fail2ban, a SIEM, or an AI assistant.

- **REST:** `GET /api/v1/threats` (addresses) and `GET /api/v1/threats/networks` (rollups), as JSON, CSV or plain text (one address per line).
- **MCP:** the `threats` and `threat_networks` tools, for AI assistants.

> **Listing never bans anything.** The threat list is separate from [bans](bans.md). Heimdall changes nothing because an address is on it. Whatever pulls the list decides what to do with it.

## Contents

- [What's in it](#whats-in-it)
- [What's never in it](#whats-never-in-it)
- [Set up](#set-up)
- [Tokens](#tokens)
- [Scope and org filtering](#scope-and-org-filtering)
- [Filters](#filters)
- [Formats](#formats)
- [Fields: addresses](#fields-addresses)
- [Fields: networks](#fields-networks)
- [Scores and /bans](#scores-and-bans)
- [Recipes](#recipes)
- [Web offenders](#web-offenders)
- [Security notes](#security-notes)

## What's in it

Each entry is an address that attacked your servers, from these sources:

| Source | What it is | Where it comes from |
|---|---|---|
| `ssh` | Failed SSH logins: hosts hit, failures, distinct usernames tried (a count), days, and whether a login then got in | Each server's opt-in login watch (`--watch-logins`). See [Failed logins](failed-logins.md). |
| `web` | Requests Cloudflare blocked or challenged: event count per action, zones, days | Cloudflare's web offenders, recorded by the zone sync when `[cloudflare]` is on with `security_events = true`. See [Web offenders](#web-offenders). |

Each address also carries:

- its network (ASN, network name and country), taken from Heimdall's Cloudflare Radar cache or the web data, and **never looked up fresh**;
- a **score** from the ban scorer, so the numbers match `/bans` (see [Scores and /bans](#scores-and-bans));
- its **ban status**, if it has a ban (shown to operators only).

The networks endpoint rolls the same addresses up per **/24** (IPv4) or **/48** (IPv6) prefix and per **ASN**.

The list covers up to the last 30 days, because failed-login counts are kept for 30 days. The default window is 7 days.

## What's never in it

| Never included | Why |
|---|---|
| **Friendly addresses**: any address IP awareness knows in **any** org. That covers labels (manual or synced: staff, office, automation, infrastructure), the tailnet (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`), private, loopback, link-local and multicast ranges, Cloudflare's edge ranges, your hosts' report addresses, and addresses anyone signed in to Heimdall from in the last 30 days. | A colleague who mistypes a password, or your own deploy service, must never end up in someone's firewall. The check is hub-wide, the same as for [bans](bans.md#who-is-a-candidate): if one org vouches for an address, it's dropped for everyone. For IPv6 the check covers the address's whole /64. |
| **Usernames** | The login watch never reports them. `usernames` is a count only. |
| **Host names, org names, log lines** | Hosts are counted, never named. Where you need names, the hub's `/offenders` page has them for signed-in users. |
| **Anything outside your scope** | Counts include only hosts (and zones) in orgs you can view. See [Scope and org filtering](#scope-and-org-filtering). |
| **Ban status, for viewers** | Bans are for operators, as on `/bans`. For users who aren't an operator anywhere, `ban` is always `null`. |
| **Fresh lookups** | Pulling the list never queues a Radar lookup, so it can't use up the day's Radar budget. A network is named only if it's already in the cache. |

## Set up

The threat list is served on the hub's **MCP listener**: the machine-facing endpoint, with bearer-token auth, published on the tailnet only. The web UI's listener is for people with sign-in sessions. If MCP is already on, there's nothing to set up. Otherwise:

```toml
# /etc/heimdall/heimdall.toml
[mcp]
enabled  = true
listen   = "127.0.0.1:8090"                        # always loopback
base_url = "https://hub.your-tailnet.ts.net:8444"  # the HTTPS address clients use
```

```sh
sudo tailscale serve --bg --https 8444 http://127.0.0.1:8090   # tailnet-only HTTPS
sudo systemctl restart heimdall
```

Use `tailscale serve`, never `tailscale funnel`. **Whatever pulls the list must be on the tailnet.**

Endpoints, relative to `base_url`:

| Endpoint | Returns |
|---|---|
| `GET /api/v1/threats` | Addresses |
| `GET /api/v1/threats/networks` | /24, /48 and ASN rollups |

Both also answer `HEAD`. Any other method gets `405`.

## Tokens

Every request needs `Authorization: Bearer <token>`. A token belongs to a user and has a **purpose**:

| Purpose | Prefix | Works for | Doesn't work for |
|---|---|---|---|
| `threats` | `hmd_threats_` | `/api/v1/threats`, `/api/v1/threats/networks` | `/mcp` (`403`) |
| `mcp` | `hmd_mcp_` | `/mcp`, including the `threats` and `threat_networks` tools | `/api/v1/threats*` (`403`) |

The design is least privilege. A threat-list token usually lives on a firewall or a log box. If it leaks, it reveals only the threat list, never the inventory, findings or sites that an MCP token reads. An MCP token gets the same threat data through the MCP tools, so there's no reason for it to also pull the REST list.

The purpose is stored with the token (migration 0030), and the hub checks it on every request. The prefix is only a label: changing it doesn't change what a token can do.

### Create a token

**In the UI:** open **AI assistants** (the link next to your email in the top bar, `/account/assistants`). Give the token a name (for example *edge firewall*), set **For** to **Threat list**, and click **Create token**.

The token is shown **once**, with a copy button and a ready-made `curl` command that keeps it out of your shell history. Heimdall stores only its hash.

**From the CLI** (on the hub, as an admin):

```sh
heimdall user mcp-token create --purpose threats --name "edge firewall" alice@example.com
```

The token goes to stdout and the instructions go to stderr, so `> file` captures only the token. `--purpose` defaults to `mcp`.

### List, revoke and rotate

| | UI | CLI |
|---|---|---|
| List | **AI assistants** lists your tokens, with what each is for and when it was last used. Admins see everyone's on **Users**. | `heimdall user mcp-token list alice@example.com` (has a `PURPOSE` column) |
| Revoke | **Revoke** beside the token (admins: on **Users**) | `heimdall user mcp-token revoke alice@example.com <id>` |
| Rotate | Create a new token, put it where the old one was, check a pull works, then revoke the old one. | The same, with `create`, then `revoke` |

A revoked token stops working on its next request. Disabling the user (`heimdall user disable`) stops all of their tokens.

Threat-list and MCP tokens share the limit of 10 active tokens per user, and the limit of 5 created every 10 minutes in the UI. Creating and revoking are recorded in the audit log (`mcp_token.create`, with the token's purpose, and `mcp_token.revoke`), from both the UI and the CLI.

## Scope and org filtering

The data is hub-wide. What you get depends on the token owner's access, just as in the web UI:

| Caller | Sees |
|---|---|
| **Global admin** | The whole hub: every host's failures and every zone's events, including zones that belong to no org. `org=acme` narrows this to failures on acme's hosts and events on acme's zones. |
| **Org user** (viewer, operator or admin of some orgs) | Only their orgs' hosts and zones. `org=` may name one of them. Naming any other org, or one that doesn't exist, returns `403`: you can't tell which. |
| **User with no roles** | `403` |

The filter changes the counts as well as the rows. If 203.0.113.50 failed on two acme hosts and one globex host, an acme user sees `hosts: 2`, with only acme's failures, days and "then succeeded". Users in other orgs never see how much globex was hit. An address that only hit globex isn't in an acme user's list at all.

The friendly check is always hub-wide, whatever the scope: if globex labels an address, it's never on acme's list either.

## Filters

All filters are query parameters (REST) or tool arguments (MCP), and they work the same way in both.

| Filter | Default | Allowed | Meaning |
|---|---|---|---|
| `since` | `7d` | `1m` to `30d` | How far back. Either a Go duration (`90m`, `36h`) or days (`7d`). The maximum matches how long failed logins are kept. |
| `org` | every org you can view | an org slug you can view | Only failures on this org's hosts, and events on its zones |
| `min_score` | `0` | a number ≥ 0 | Only addresses scoring at least this. `12` is the default ban threshold (`propose_at`). |
| `min_hosts` | `0` | `0` to `1000` | Only addresses that failed SSH logins on at least this many hosts. Web-only addresses count 0 hosts. |
| `source` | `all` | `ssh`, `web`, `all` | Which sensor saw it. An address seen by both is in all three. |
| `limit` | REST `1000`, MCP `25` | REST `1` to `10000`, MCP `1` to `100` | The most rows returned. `total` and `truncated` say what was cut. |
| `format` | `json` | `json`, `csv`, `plain` | REST only. See [Formats](#formats). |
| `kind` | both | `prefix`, `asn`, `all` | Networks only: /24 and /48 prefixes, ASNs, or both |
| `min_addresses` | `1` | `1` to `100000` | Networks only: the fewest listed addresses a network needs |

`min_score`, `min_hosts` and `source` pick the addresses first. The networks endpoint then rolls those addresses up, before its own `limit`.

A bad value returns `400` with a message such as `since: must be from 1m to 30d (failed logins are kept 30 days)`.

**Sort order.** Addresses are sorted by highest score first, then most SSH hosts, then most failures plus web events, then most recently seen, then address. Networks are sorted by most addresses first, then most failures plus events, then most hosts.

## Formats

Every response carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

| `format` | `Content-Type` | Body |
|---|---|---|
| `json` | `application/json` | The result object, documented field by field below |
| `csv` | `text/csv; charset=utf-8` | A header row, then one row per address or network. Cells that would start a spreadsheet formula (`=`, `+`, `-`, `@`) get a leading `'`. |
| `plain` | `text/plain; charset=utf-8` | One address per line, or one CIDR per line for networks. It has no header and no comments, in the same shape as published IP lists such as `https://forge.laravel.com/ips-v4.txt`. An empty list is an empty body. |

### JSON: addresses

`GET /api/v1/threats?since=7d&min_score=12`

```json
{
  "generated_at": "2026-10-25T12:00:00Z",
  "since": "2026-10-18T12:00:00Z",
  "org": "",
  "source": "all",
  "total": 2,
  "truncated": false,
  "addresses": [
    {
      "ip": "203.0.113.50",
      "sources": ["ssh", "web"],
      "first_seen": "2026-10-23T03:14:00Z",
      "last_seen": "2026-10-25T10:58:00Z",
      "ssh": {"hosts": 3, "failures": 412, "usernames": 25, "days": 3, "succeeded": false},
      "web": {"events": 42, "actions": {"block": 40, "managed_challenge": 2}, "zones": ["example.com"], "days": 2},
      "asn": 64500,
      "as_name": "Example ISP",
      "country": "US",
      "score": 33.2,
      "ban": {"status": "active", "action": "block", "target": "203.0.113.50", "kind": "address", "expires_at": "2026-11-01T11:00:00Z"}
    },
    {
      "ip": "2001:db8:5::7",
      "sources": ["ssh"],
      "first_seen": "2026-10-24T08:02:00Z",
      "last_seen": "2026-10-24T08:40:00Z",
      "ssh": {"hosts": 2, "failures": 60, "usernames": 8, "days": 1, "succeeded": false},
      "web": {"events": 0, "actions": {}, "zones": [], "days": 0},
      "asn": 0,
      "as_name": "",
      "country": "",
      "score": 13.9,
      "ban": null
    }
  ]
}
```

### JSON: networks

`GET /api/v1/threats/networks?min_addresses=2`

```json
{
  "generated_at": "2026-10-25T12:00:00Z",
  "since": "2026-10-18T12:00:00Z",
  "org": "",
  "source": "all",
  "total": 2,
  "truncated": false,
  "networks": [
    {
      "network": "198.51.100.0/24", "kind": "prefix", "asn": 64501, "as_name": "Example Hosting", "country": "NL",
      "addresses": 6, "failures": 230, "events": 0, "hosts": 4,
      "first_seen": "2026-10-19T22:10:00Z", "last_seen": "2026-10-25T09:30:00Z",
      "top": ["198.51.100.7", "198.51.100.12", "198.51.100.3", "198.51.100.40", "198.51.100.41"]
    },
    {
      "network": "AS64501", "kind": "asn", "asn": 64501, "as_name": "Example Hosting", "country": "NL",
      "addresses": 6, "failures": 230, "events": 0, "hosts": 4,
      "first_seen": "2026-10-19T22:10:00Z", "last_seen": "2026-10-25T09:30:00Z",
      "top": ["198.51.100.7", "198.51.100.12", "198.51.100.3", "198.51.100.40", "198.51.100.41"]
    }
  ]
}
```

### CSV

`GET /api/v1/threats?format=csv`

```csv
ip,sources,first_seen,last_seen,score,ssh_hosts,ssh_failures,ssh_usernames,ssh_days,ssh_succeeded,web_events,web_actions,web_zones,web_days,asn,as_name,country,ban_status,ban_action,ban_target
203.0.113.50,ssh web,2026-10-23T03:14:00Z,2026-10-25T10:58:00Z,33.2,3,412,25,3,false,42,block:40 managed_challenge:2,example.com,2,64500,Example ISP,US,active,block,203.0.113.50
2001:db8:5::7,ssh,2026-10-24T08:02:00Z,2026-10-24T08:40:00Z,13.9,2,60,8,1,false,0,,,0,,,,,,
```

The columns match the JSON fields. `sources` and `web_zones` are space-separated lists. `web_actions` is `action:count` pairs, space-separated and sorted, for example `block:3 managed_challenge:12`. An empty cell means none or unknown.

`GET /api/v1/threats/networks?format=csv`

```csv
network,kind,asn,as_name,country,addresses,failures,events,hosts,first_seen,last_seen,top
198.51.100.0/24,prefix,64501,Example Hosting,NL,6,230,0,4,2026-10-19T22:10:00Z,2026-10-25T09:30:00Z,198.51.100.7 198.51.100.12 198.51.100.3 198.51.100.40 198.51.100.41
AS64501,asn,64501,Example Hosting,NL,6,230,0,4,2026-10-19T22:10:00Z,2026-10-25T09:30:00Z,198.51.100.7 198.51.100.12 198.51.100.3 198.51.100.40 198.51.100.41
```

### Plain

`GET /api/v1/threats?format=plain&min_score=12`

```text
203.0.113.50
2001:db8:5::7
```

`GET /api/v1/threats/networks?format=plain&min_addresses=4`

```text
198.51.100.0/24
2001:db8:77::/48
```

Plain networks lists **prefixes only**, because an ASN isn't a range a firewall can match. IPv4 and IPv6 are mixed in both lists. Split them with `grep ':'` (IPv6) and `grep -v ':'` (IPv4) if your firewall needs separate sets.

## Fields: addresses

The top level of the result:

| Field | Type | Meaning |
|---|---|---|
| `generated_at` | string, RFC 3339 UTC | When the hub built the list |
| `since` | string, RFC 3339 UTC | The start of the window (`generated_at` minus `since`) |
| `org` | string | The `org` filter, or `""` for every org in scope |
| `source` | string | The `source` filter: `all`, `ssh` or `web` |
| `total` | integer | Matching addresses before `limit` |
| `truncated` | boolean | `true` if `limit` cut the list |
| `addresses` | array | The addresses, sorted as above. Never `null`. |

Each address:

| Field | Type | Meaning |
|---|---|---|
| `ip` | string | The address, IPv4 or IPv6, in canonical form. An IPv4-mapped IPv6 address is shown as IPv4. |
| `sources` | array of strings | `"ssh"`, `"web"`, or both, in that order |
| `first_seen` | string, RFC 3339 UTC | The earliest failure or event in the window, on hosts and zones you can see |
| `last_seen` | string, RFC 3339 UTC | The latest one |
| `ssh.hosts` | integer | Hosts it failed to log in to (in your scope). 0 when it isn't an SSH source. |
| `ssh.failures` | integer | Failed logins, summed over those hosts |
| `ssh.usernames` | integer | The most distinct usernames it tried on one host in one day. A count only: usernames are never reported. |
| `ssh.days` | integer | Distinct UTC days with a failure. 0 when it isn't an SSH source. |
| `ssh.succeeded` | boolean | A login from it got in after failing, on one of those hosts, the same day |
| `web.events` | integer | Requests Cloudflare blocked or challenged, on zones in your scope. On sampled days it's a floor. 0 when it isn't a web source. |
| `web.actions` | object, string to integer | Events per action: `block`, `challenge`, `js_challenge`, `managed_challenge`, `connection_close`. `{}` when none. |
| `web.zones` | array of strings | The zones it hit (in your scope), sorted. `[]` when none. |
| `web.days` | integer | Distinct UTC days with an event |
| `asn` | integer | Its network's AS number, from the Radar cache or the web data. 0 when unknown. |
| `as_name` | string | The network's name. `""` when unknown. |
| `country` | string | The network's two-letter country code. `""` when unknown. |
| `score` | number, one decimal | The ban score of its SSH evidence in your view. Web-only addresses score 0. See [Scores and /bans](#scores-and-bans). |
| `ban` | object or `null` | Its ban, if it has one and you're an operator in some org. Otherwise `null`. |
| `ban.status` | string | `proposed`, `pending`, `active` or `lifting` (an open ban), or `shadow` (shadow mode would ban it, and the record hasn't run out). An open ban wins over a shadow record. |
| `ban.action` | string | `challenge` or `block` |
| `ban.target` | string | What the ban covers: the address, its IPv6 /64, or a /24 or /48 network that holds it. The most specific one wins. |
| `ban.kind` | string | `address` or `network` |
| `ban.expires_at` | string, RFC 3339 UTC, or `null` | When it runs out, if known |

The schema is stable: `ssh` and `web` are always present, with zeros when a source didn't see the address.

## Fields: networks

The top level is the same as for addresses (`generated_at`, `since`, `org`, `source`, `total`, `truncated`), with `networks` in place of `addresses`.

Each network:

| Field | Type | Meaning |
|---|---|---|
| `network` | string | `203.0.113.0/24`, `2001:db8:1::/48`, or `AS64500` |
| `kind` | string | `prefix` (a /24 for IPv4 or a /48 for IPv6) or `asn` |
| `asn` | integer | The AS number: for a prefix, from its first address with one cached. 0 when unknown. |
| `as_name` | string | The network's name, `""` when unknown |
| `country` | string | Two-letter country code, `""` when unknown |
| `addresses` | integer | Listed addresses in it |
| `failures` | integer | Their SSH failures, summed |
| `events` | integer | Their web events, summed |
| `hosts` | integer | Distinct hosts (in your scope) its addresses failed on |
| `first_seen`, `last_seen` | string, RFC 3339 UTC | Earliest and latest across its addresses |
| `top` | array of strings | Up to 5 of its addresses, highest score first |

Only addresses with a cached ASN are counted in an ASN rollup.

## Scores and /bans

`score` is computed by the same code as the ban engine, with your hub's `[bans.weights]` and `min_failures`. It's computed whether or not bans are on. The parts are hosts, failures (log₂), distinct usernames, "then succeeded", extra days, and other offenders in the same ASN. See [Scoring](bans.md#scoring) for the table.

**When the numbers match `/bans` exactly:** the caller is a global admin, there's no `org` filter, and `since` equals `[bans] window` (7 days by default). That is the same evidence the ban engine scores.

**When they don't:** an org user, an `org` filter or a different window scores **only the evidence in that view**. Fewer hosts and failures mean a lower score, and "same network" counts only the offenders in that view. This keeps one org's view from revealing another org's evidence.

Other differences:

- Web events don't score yet. A web-only address has `score: 0`.
- The threat list has no network bans of its own: a /24's or /48's ban score is on `/bans`. The networks endpoint gives counts instead.
- `/bans` shows candidates IP awareness made friendly, as skipped. The threat list leaves them out.
- `min_score=12` matches the default `propose_at`. Use your own `[bans] propose_at` to get "everything bans would act on".

## Recipes

### curl, with the token kept off the command line

A token passed as a command-line argument shows up in `ps` and in shell history. Pass it to `curl` through `--config` instead.

**Interactively:** `read -rs` asks for the token without echoing it. `printf` is a shell builtin, so the token never reaches a process's arguments.

```sh
read -rs HMD_TOKEN   # paste the token, press Enter
printf 'header = "Authorization: Bearer %s"\n' "$HMD_TOKEN" |
  curl -fsS --config - 'https://hub.your-tailnet.ts.net:8444/api/v1/threats?since=24h&min_score=12' | jq .
unset HMD_TOKEN
```

**From a file**, for scripts:

```sh
sudo install -d -m 700 /etc/heimdall-threats
sudo sh -c 'umask 077; read -rs t; printf "header = \"Authorization: Bearer %s\"\n" "$t" > /etc/heimdall-threats/curl.conf'
sudo curl -fsS --config /etc/heimdall-threats/curl.conf 'https://hub.your-tailnet.ts.net:8444/api/v1/threats?format=plain'
```

`-f` makes `curl` fail on an HTTP error (`401`, `403`, `5xx`) instead of writing the error message out as if it were the list.

### A cron job feeding an ipset

This keeps an ipset of addresses that scored at least 12 in the last 7 days, and drops their SSH traffic. It swaps in a complete new set each run, so the firewall never sees a half-loaded list. If a pull fails, the old set stays.

```sh
#!/bin/sh
# /usr/local/sbin/heimdall-threats-ipset
set -eu
URL='https://hub.your-tailnet.ts.net:8444/api/v1/threats?format=plain&min_score=12&source=ssh'
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsS --max-time 60 --config /etc/heimdall-threats/curl.conf "$URL" > "$tmp"

load() { # set, family, address pattern
  ipset create "$1" hash:ip family "$2" -exist
  ipset create "$1-new" hash:ip family "$2" -exist
  ipset flush "$1-new"
  grep -E "$3" "$tmp" | sed "s/^/add $1-new /" | ipset restore -exist
  ipset swap "$1-new" "$1"
  ipset destroy "$1-new"
}
load heimdall-threats inet '^[0-9.]+$'
load heimdall-threats6 inet6 ':'
```

```sh
# Once: match the sets (persist these with your distribution's tooling).
iptables  -I INPUT -p tcp --dport 22 -m set --match-set heimdall-threats  src -j DROP
ip6tables -I INPUT -p tcp --dport 22 -m set --match-set heimdall-threats6 src -j DROP
```

```cron
# /etc/cron.d/heimdall-threats: every 10 minutes
*/10 * * * * root /usr/local/sbin/heimdall-threats-ipset
```

The machine running this must be on the tailnet. Keep your own way back in, such as the tailnet or a console, in case something goes wrong. Heimdall never lists what IP awareness knows, but your firewall acts on whatever it's given.

For whole networks, pull `/api/v1/threats/networks?format=plain&kind=prefix&min_addresses=4` into a `hash:net` set the same way.

**fail2ban** and similar tools can read the `plain` list the same way: one address per line.

### Ask an AI assistant

With an MCP token connected (see [MCP](mcp.md)), ask in plain words:

- *"Which addresses attacked the most of our hosts this week?"* calls `threats` with `min_hosts`.
- *"Show acme's threat list for the last 24 hours, score 12 and up."* calls `threats` with `org=acme`, `since=24h` and `min_score=12`.
- *"Which networks are the attacks coming from?"* calls `threat_networks`.

The tools take the same filters as REST (without `format`) and return the same JSON, capped at 100 rows. Each result is labelled as untrusted data. Network names come from outside sources, so an assistant treats them as data, never as instructions. Every tool call is recorded in the audit log as `mcp.call`.

## Web offenders

The `web` source is the client addresses Cloudflare **blocked or challenged** on your zones. Requests it let through never count, and neither do solved challenges. The Cloudflare zone sync records them per address, zone and UTC day, and keeps them 30 days. This needs `[cloudflare]` on with `security_events = true`. Without it, `web` is empty on every address and `source=web` returns nothing. What's stored and how it's fetched are covered in the Cloudflare guide's Web offenders section (`docs/cloudflare.md`).

- **One row per address.** An address seen by both sources has `"sources": ["ssh", "web"]`, with both halves filled in. `first_seen` and `last_seen` span both.
- **Zones and orgs.** A zone belongs to the orgs whose hosts or sites its DNS records lead to. The mapping is rebuilt every sync.
  - An org user sees events on their orgs' zones only. A zone shared by two of their orgs counts once.
  - `org=acme` limits the list to acme's zones.
  - A global admin also sees zones that belong to no org.
- **Friendly addresses** are dropped twice. The sync never stores them, and the threat list checks them again when it's pulled, in case an address became known after it was recorded.
- **Network.** ASN, network name and country come from the Radar cache when it has the address, else from what Cloudflare reported with the events.
- **Floors.** On zones without the aggregated dataset (usually Free), each day holds only the latest 1,000 events, so `events` is a floor.
- **Score.** Web events don't score yet, so a web-only address has `score: 0`. Use `source=web`, or `min_score=0` (the default), to see them. `min_hosts=1` or more leaves them out.
- **Rollups.** `/networks` adds web events to `events`, and counts web-only addresses in `addresses`.

## Security notes

- **Tailnet plus token.** The tailnet decides who can reach the endpoint. The token decides who the caller is, and so which orgs they see.
- **Least privilege.** A threat-list token reads the threat list and nothing else. It can't use `/mcp`, and an MCP token can't pull the REST list. See [Tokens](#tokens).
- **Shown once, stored hashed.** Heimdall keeps only a token's SHA-256 hash. A token is never in a URL, never logged, and never shown again after it's created.
- **DNS rebinding.** A request with an `Origin` header other than `mcp.base_url` is refused (`403`), as on `/mcp`.
- **Bounded requests.** Only `GET` and `HEAD` are accepted, with no body and a query of at most 2 KB. Responses are never cached (`no-store`).
- **Audit.** Creating and revoking tokens is recorded. MCP tool calls are recorded as `mcp.call`. REST pulls aren't recorded one by one, because a firewall pulling every few minutes would flood the log. The token's **Last used** time (updated at most once a minute) shows that it's in use.
