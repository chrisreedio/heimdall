# Attack surface

**/surface** (operators and admins) lists every public hostname and follows it all the way through:

**hostname → zone (and plan) → DNS record (proxied?) → Heimdall host → site on that host → open findings there, by severity**

The point is to answer one question first: *which public names run vulnerable software?* A name that leads to a host or site with critical or high findings ranks first. Known-exploited (KEV) findings rank above other critical ones, then come critical and high counts. After those come names with a high-risk flag (a likely subdomain takeover) or an exposed origin, then everything else.

`heimdall surface` prints the same map in the terminal (see [CLI](#cli)).

## Where names come from

- **Cloudflare zones**, when `[cloudflare]` is on: every A, AAAA and CNAME record the read-only token can see (see [cloudflare.md](cloudflare.md)).
- **Sites collectors report**: each server name in a site's nginx or Apache config. A name that isn't in any synced zone is still listed, marked **not on Cloudflare**. A name in a synced zone without a record shows **no record**. A name only a wildcard record covers follows the wildcard.

With Cloudflare off, the page still works. It lists the site names collectors report, each with its host, site, software and findings, all marked *not on Cloudflare*.

## What each row shows

| Column | |
|---|---|
| Name | the public hostname |
| Zone | the Cloudflare zone and plan, plus any zone-level flags (below) |
| Record | **proxied** (orange cloud), **not proxied** (grey) or *not on Cloudflare*; **origin exposed** when it's grey and leads straight to one of your hosts (following CNAMEs inside your zones); the record targets |
| Host | the hosts the name leads to: by report address, and the host of any site serving the name. Each shows its OS and its OS-package critical/high counts |
| Site | the sites serving the name, with their stack ("Laravel 11.31.0 · PHP 8.3 · nginx") |
| Findings | open findings behind the name: the hosts' OS packages plus the sites' own, by severity |
| Flags | risky records (below) |

**Filters:** *Vulnerable* (critical or high findings behind the name), *Exposed* (unproxied and pointing at one of your hosts), *Flagged*, *Unmatched* (leads to none of your hosts or sites) and *Not on Cloudflare*. You can also filter by zone.

## Risky records

| Flag | Level | Meaning |
|---|---|---|
| `takeover` | high | A CNAME to a name outside your zones that doesn't exist, where someone else could create it: it's on a hosting service (a Heroku app or S3 bucket with the same name), or its whole domain isn't registered. Whoever creates it serves your hostname. Delete the record or recreate the target. |
| `dead-cname` | info | A CNAME to a name outside your zones that doesn't exist, on a domain someone still holds (a retired service's hostname, say). Only that domain's owner could bring it back, so it's no takeover. Remove the record if the service is gone, but some providers publish their side later: Microsoft 365's DKIM `selector2` only exists once keys rotate. |
| `third-party` | info | A CNAME to a hosting service: Heroku, Azure App Service and Cloud Services, AWS S3 website endpoints, CloudFront, GitHub Pages, Netlify, Vercel, Cloudflare Pages and Workers, Fly.io, Render, Firebase and others. Fine while the target exists, and worth knowing about. |
| `wildcard` | medium | A `*.` record: every name under it that has no record of its own resolves there. |
| `dangling-cname` | medium | A CNAME to a name inside your own zones that has no A, AAAA or CNAME record. |
| `dangling` | medium | An A or AAAA record whose address is none of your hosts, isn't Cloudflare's, isn't private and isn't labelled (as on /cloudflare). The addresses Cloudflare documents for a proxied name with no server behind it, `192.0.2.x` and `100::`, used for redirect rules and Workers, never count. A host that reports to the hub over loopback or a private network (the hub's own box, for one) is only known by its private addresses: label its public address on /cloudflare. |

**How CNAME targets are checked:** during each zone sync, the hub resolves every CNAME target outside your synced zones. It uses the standard system resolver, 8 lookups at a time, each with a 5-second timeout, and at most 500 targets per sync. A target counts as missing only when it has no records at all: one with no addresses but TXT, MX or CNAME records exists. DKIM keys at Amazon SES, SendGrid or Microsoft 365 are like that. For a missing target, the hub asks whether its domain has name servers, which every registered domain has (it works the domain out from the name without the public suffix list, so it treats `co.uk`-style suffixes under country codes as suffixes). A timeout or server failure doesn't replace the previous answer, so a flaky resolver doesn't raise or clear the flag. Targets inside your zones aren't looked up: the synced records already answer for them.

## Zone settings

The **Zones** table shows each zone's settings, read-only:

| Setting | Flagged when |
|---|---|
| SSL/TLS encryption mode | **off** (no HTTPS through Cloudflare) or **flexible** (Cloudflare talks to your origin in plain HTTP), both high |
| Always Use HTTPS | off (medium) |
| Minimum TLS version | 1.0 or 1.1 (medium) |
| Edge certificate expiry | within 14 days (medium), or already expired (high) |

Each zone also shows how many of its names are **proxied** and how many are **not proxied**. A Cloudflare rule (WAF, IP block) only protects proxied names, so this is the coverage a later "ban rule deployed in this zone?" column will read.

These need two extra **optional** token permissions:

| Permission | For |
|---|---|
| Zone > Zone Settings > Read | SSL/TLS mode, Always Use HTTPS, minimum TLS (`GET /zones/{id}/settings/{name}`) |
| Zone > SSL and Certificates > Read | edge certificate expiry (`GET /zones/{id}/ssl/certificate_packs`) |

Without them the table shows **no permission** and the sync carries on. If a read fails, the last good values stay. A failed settings read is reported as a sync error. A failed certificate read is only stored, because certificates are a nice-to-have.

## Recent changes

On every zone sync after the first, the hub compares each zone's records with the previous sync and logs:

- a name **added** or **removed**;
- the proxy turned **off** (proxied → not proxied: the origin's address is now public) or **on**;
- the **target changed**: the addresses or CNAME target.

The page lists the last 30 days. The log keeps 90 days (table `surface_changes`). The first sync of a zone logs nothing, because there's nothing to compare it with. A zone whose DNS read fails is skipped until it reads again.

No anomaly is raised for these changes yet.

## Access

Zones belong to no org, so the map is cut down the same way /cloudflare is:

- An operator sees a name only if it leads to a host or site in one of their orgs. Other orgs' hosts and sites on a shared name are left out, along with their findings.
- Names that lead nowhere (unmatched, dangling) are for global admins only.
- A change is shown to the orgs the name led to before or after the change.
- Host and site pages show a short line, e.g. "Public as api.example.com (proxied)", to anyone who can see the page. The link to /surface appears only for operators.

## CLI

```sh
heimdall surface                      # the map, worst first
heimdall surface --org acme           # names leading to acme's hosts or sites
heimdall surface --json               # map, zones and 90 days of changes
heimdall surface --changes            # the DNS change log, ISO dates
```

```
NAME              ZONE         STATUS             RECORD           HOST         SITE       KEV  CRIT  HIGH  MED  LOW  FLAGS
shop.example.com  example.com  proxied            A 203.0.113.10   acme/web-01  /srv/shop  1    2     0     0    3    ssl-flexible
api.example.com   example.com  unproxied,exposed  A 203.0.113.11   acme/web-02  —          0    0     0     1    0    ssl-flexible
```

## What might differ

This was built from Cloudflare's API documentation (October 2026) without a live account:

- **Zone settings:** each setting's `result.value` is assumed to be a string ([zone settings](https://developers.cloudflare.com/api/resources/zones/subresources/settings/methods/get/)). A setting the API returns 404 for is left blank.
- **Certificate packs:** each pack's `certificates[].expires_on` (RFC 3339) is read, and only packs and certificates with status `active` count ([certificate packs](https://developers.cloudflare.com/api/resources/ssl/subresources/certificate_packs/methods/list/)).
- **DNS checks** use the hub's own resolver. A split-horizon resolver may answer differently than the public internet does.
