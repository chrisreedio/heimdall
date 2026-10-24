# Threat news

> **Status: Phase 1 is built** (feed sync, confirmed matches, the News page, the dashboard strip, the host page's "In the news" card and the Patch first boost). It's off by default: set `enabled = true` under `[news]` in `heimdall.toml` and restart the hub. The default source is pwn.watch's `incidents.json`. Phases 2 and 3 below are still proposals.

This uses a curated "what's being exploited right now" feed, such as [pwn.watch](https://pwn.watch), together with Heimdall's inventory.

## The problem

Heimdall already knows what every server runs, and it matches that against OSV, CISA KEV and EPSS. The result is accurate, but it's a long list: a typical host has dozens to hundreds of open findings, and most will never matter.

What's missing is **timeliness and context**: which issues are being exploited *this week*, in plain language, and whether they touch *my* servers. Security news has that context but no idea what you run. Heimdall has the inventory but no news.

## The idea

Fetch a curated incident feed, cross-reference each incident with the inventory **on the hub**, and show:

> **Ruby regex RCEs behind GitLab's CVSS 10 bugs** · critical · patch available
> **Affects 3 of your hosts:** web-01, web-02 (confirmed), worker-01 (possible)

The feed doesn't replace findings. It ranks them and explains them.

## Sources

### pwn.watch (first)

A curated tracker that publishes everything as JSON (`/incidents.json`, about 730 incidents) plus per-category feeds and incremental `changes.json`. Each incident has:

| Field | Example | Use |
|---|---|---|
| `category` | `patch`, `breach`, `supply-chain` | How it can be matched (see below) |
| `severity`, `patchStatus`, `status` | `critical`, `patched`, `live` | Ranking, and "can I do anything about it" |
| `cveIds` | `CVE-2026-89078`, … | **Exact match against findings** |
| `product`, `stacks`, `tags` | `Ruby (CRuby…)`, `ruby`, `rce` | Possible matches against packages and runtimes |
| `affectedVersions`, `fixedVersions` | "Ruby 3.4 before 3.4.12" | Shown as text, **not** used for matching |
| `summary`, `title`, `url` | plain English | What the UI shows, linking back to the source |
| `startedAt`, `updatedAt`, `closedAt` | dates | "New this week", and retention |

Items credit their source ("via pwn.watch", linking to the incident page), and the hub fetches at most hourly, respecting caching headers.

### Later: primary sources, no third party

CISA advisories, Ubuntu USN, Debian DSA, Red Hat RHSA and GitHub Security Advisories all publish machine-readable feeds. They lack pwn.watch's curation and summaries, but they keep the feature working if a third-party feed goes away. The feed format below is source-neutral, so those can be added as additional sources.

## How matching works

The core rule: **Heimdall's own findings decide whether a host is affected**, never the feed's free-text version ranges. Distros backport fixes without changing the upstream version, so "Ruby 3.4 before 3.4.12" is wrong for a patched Ubuntu build. OSV's distro data, which findings already use, gets that right.

| Match | Rule | Shown as | Alerts? |
|---|---|---|---|
| **Confirmed** | An incident CVE is an **open finding** on the host | "Affects web-01" | Yes: dashboard tile, digest |
| **Possible** | The incident's `stacks`, `product` or `tags` name something the host runs (an installed package, a runtime such as PHP or Ruby, a site framework such as Laravel, a container image), but no CVE matched | "Might affect worker-01: runs ruby 3.3" | No, informational only |
| **Supply chain** | A named malicious or hijacked package appears in a host's lockfiles or packages: confirmed if the version is listed, possible if only the name matches | as above | Confirmed only |
| **Not matchable** | Breaches and attacks with no CVE and no software to patch | News only, optionally filtered by tags you follow | No |

A host whose finding is fixed (upgraded, or patched by a backport) drops out of "confirmed" on its next report, exactly as its findings do.

The possible-match vocabulary is a small, reviewed mapping from stack names to what Heimdall sees, for example `ruby` → the `ruby` and `ruby3.x` packages plus the Ruby runtime fact, and `php` → `php*` packages, PHP-FPM and Laravel sites. That keeps fuzzy matching predictable instead of a substring search over package names.

## What changes in the product

- **News page:** incidents newest first, each with an "affects N hosts" badge (confirmed, then possible) linking to those hosts, and filters for "affects me", category and severity.
- **Dashboard:** a slim strip above the tiles reading "**2** in the news affect your hosts →", linking to the News page filtered to confirmed matches. It's a strip rather than a ninth tile, so the tiles stay a 4 × 2 grid.
- **Host page:** an "In the news" section listing incidents that match this host.
- **Patch first:** findings that appear in a live incident rank higher, like KEV does today. Exploited-in-the-wild news is a strong signal.
- **Digest (email or webhook):** new confirmed matches since the last digest, counts and titles only, like today's digest.
- **MCP:** a `news` tool, so "which of my servers are hit by this week's news?" works in Claude. Feed text is labelled as untrusted data, like every other MCP field.

## Fetching

- **Off by default.** Turn it on with:
  ```toml
  [news]
  enabled  = true                                  # default false
  sources  = ["https://pwn.watch/incidents.json"]  # the default; any https feed in the same shape
  interval = "1h"                                  # at least 1h
  ```
- The feed's hosts are added to the outbound allowlist (in its own list, like feed sync). Requests are HTTPS only, with an `If-Modified-Since`/ETag check, a size cap, a timeout and a User-Agent that identifies Heimdall.
- Use `changes.json` for incremental updates once the full list is cached.
- The response is validated strictly (types, lengths, https-only URLs, a known category set), and anything malformed is dropped. **The last good copy is kept**, and a broken feed never blocks feed sync, findings or the dashboard.

## Security and privacy

- **Nothing about your inventory leaves the hub.** The hub reads a public file and does all matching locally. That's the same model as OSV and KEV sync today.
- **Feed text is untrusted input.** Titles and summaries are rendered as escaped text, links must be https, and nothing in the feed can trigger an action. That matters because a compromised or wrong feed can't patch, alert-storm or inject markup.
- **Alerts come only from confirmed matches,** so a misleading feed entry can at worst add a "possible" note.

## Data model (sketch)

```
news_items    id, source, slug (unique per source), category, title, url, severity,
              patch_status, status, product, stacks (json), tags (json), cve_ids (json),
              summary, started_at, updated_at, closed_at, fetched_at
news_matches  item_id, host_id, kind (confirmed|possible|supply), reason, matched_at
```

Matches are recomputed when a feed changes and when a host reports, the same triggers as findings. Closed incidents are kept for 90 days, then pruned.

## Phase 1 as built

- **Fetching:** `heimdall serve` fetches each source at startup and every `interval`, and `heimdall feeds sync` does it on demand. The outbound client is allowlisted to the configured sources' hosts only. Requests are HTTPS, send `If-None-Match`/`If-Modified-Since`, time out after 60 seconds, are capped at 8 MB and identify as `heimdall/<version>`. `heimdall feeds status` shows a `news` row.
- **Validation:** an incident is dropped (and counted in the log) if a field has the wrong type or is too long, its `url` isn't https, its `category`, `status`, `severity` or `patchStatus` isn't a known value, its slug is malformed or repeated, or its dates don't parse. `cveIds` entries that aren't `CVE-YYYY-NNNN…` (for example `GHSA-…` or `MAL-…`) are ignored rather than matched. A feed that fails to download, isn't JSON, or has no valid incidents leaves the stored copy untouched.
- **Storage:** `news_items` (unique per source and slug), `news_matches` and `news_sources` (the ETag and Last-Modified per source), from migration 0006. Closed incidents are pruned 90 days after they close, and incidents from a source you remove from the config are deleted.
- **Matching:** an incident affects a host when one of its CVEs is an open finding there, as the advisory's ID or one of its aliases. Matches are recomputed after each news sync, after each full findings sync and after each host report, so a patched host drops off on its next report.
- **UI:** a News page (newest first; filters for All, Affects me and each category; per incident the severity, category, patch status, a two-line summary, "via <source>" and an "Affects N of your hosts" badge listing the hosts the viewer can see). Findings named by a **live** incident rank right after known-exploited ones and carry an "in the news" badge. Feed text is only ever rendered as escaped text.

## Phases

1. **Feed and confirmed matches:** opt-in pwn.watch source, CVE cross-referencing, News page, dashboard tile, and the Patch first boost.
2. **Possible and supply-chain matches:** the stack mapping, lockfile checks, digest entries, and the MCP `news` tool.
3. **Primary sources:** CISA, the distro advisories and GHSA, so the feature doesn't depend on any one third party.

## Open questions

- Should "possible" matches ever notify, for example for critical incidents on an exposed service?
- Per-user or per-org "follow" tags for breach news (for example `okta`, `cloudflare`)?
- Do we keep a history of which hosts were affected by an incident, and when they stopped being affected? That would be useful for reporting "we patched within N days".
