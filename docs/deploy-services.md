# Deploy services

When Laravel Forge, Ploi or a similar service logs in to a server over SSH to deploy, the [privilege watch](collector.md#privilege-watch) records the session's source address and, with `--watch-privilege-users`, the account. Heimdall recognizes those sessions as **automation** ("Laravel Forge") instead of an unknown address.

It does that in two ways:

- **By address (known).** The hub fetches each enabled service's published source addresses once a day and stores them as IP labels (source `service:<id>`, kind `automation`).
- **By account (a guess).** Each service's default account (`forge` for Forge, `ploi` for Ploi) is recognized too. People log in as `forge` as well, so a matching account alone is only a guess. A matching address always ranks above it.

## Privileged access

Every deploy is a privileged SSH session, often as root. By default a session **from a service's synced range** doesn't count toward the privilege watch's `privileged_access` anomaly, so deploys don't raise an alert each time. A session recognized only by its account (`forge` from an address outside Forge's ranges) still counts, and if nothing else is known about the address it also raises `privilege_unknown_source`: a name is easy to use, an address range is the service's own. A manual `automation` label isn't exempt either.

For example, with Forge's ranges synced: root SSH from a Forge address doesn't count; `forge` logging in from 203.0.113.9 counts and raises `privilege_unknown_source`.

To count deploy-service sessions too, per org:

```sh
heimdall ip policy --org acme --count-services on    # off (exempt) by default
```

or turn on **count deploy-service sessions as privileged access** for the org on the IP addresses page (`/ips`). Changes are audited (`ip_policy.set`). See [ip-awareness.md](ip-awareness.md#deploy-service-sessions-and-privileged-access) for the full rules and a worked example.

## Catalog

Only vendors that publish their addresses themselves are listed. The hub fetches exactly the URLs below and nothing else (each service's client is allowlisted to its own hosts).

| ID | Service | List fetched | Format | Account | Default |
|---|---|---|---|---|---|
| `forge` | Laravel Forge | `https://forge.laravel.com/ips-v4.txt` ([docs](https://laravel.com/forge/docs/introduction)) | one address a line | `forge` ([docs](https://laravel.com/forge/docs/ssh)) | on |
| `ploi` | Ploi | `https://ploi.io/api/ips`, needs your API token ([docs](https://developers.ploi.io/getting-started/ip-addresses)) | JSON `data.workers` | `ploi` ([docs](https://ploi.io/documentation/ssh/how-do-i-connect-with-ssh-mac-linux)) | on |
| `envoyer` | Laravel Envoyer | `https://envoyer.io/ips-v4.txt` ([docs](https://docs.envoyer.io/introduction)) | one address a line | yours to choose | off |
| `deployhq` | DeployHQ | `https://test.deployhq.com/ip_ranges` ([docs](https://www.deployhq.com/support/api/ip-ranges-api)) | JSON `all_ipv4` + `all_ipv6` | yours to choose | off |
| `buddy` | Buddy (US) | `https://buddy.works/api/ips` ([docs](https://buddy.works/docs/troubleshooting/ip-whitelist)) | JSON `runners` | yours to choose | off |
| `buddy-eu` | Buddy (EU) | `https://buddy.works/api/ips/eu` | JSON `runners` | yours to choose | off |
| `buddy-asia` | Buddy (Asia) | `https://buddy.works/api/ips/asia` | JSON `runners` | yours to choose | off |
| `github-actions` | GitHub Actions | `https://api.github.com/meta`, key `actions` ([docs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-ip-addresses)) | JSON `actions` | yours to choose | off |

Notes:

- **Ploi** shows its deploy (worker) addresses only to signed-in customers, and its API needs a token. Without one, Ploi sessions are still recognized by the `ploi` account, as a guess. To get the addresses, create an API token in your Ploi account and store it with `sudo heimdall ip-services set-key ploi`. It's stored like the AI key: an owner-only file, `/etc/heimdall/ploi-token`, loaded as the systemd credential `heimdall-ploi`, never in `heimdall.toml`. Ploi's uptime monitors only make HTTP checks, so they aren't used. If you'd rather not store a token, copy the worker addresses from Ploi into a [custom service](#your-own-deploy-tool).
- **Envoyer**'s text list has a few older addresses besides the four in its docs.
- **GitHub Actions** is about 7,000 Azure ranges that other Azure customers share, so a match means "could be GitHub Actions". It's off unless you list it.
- **Left out**, for lack of a list the hub could fetch: Laravel Cloud (it doesn't log in to your servers), RunCloud (an HTML page, for its agent port), ServerPilot (its agent connects out), SpinupWP (announces addresses by email), Cleavr (no published list found). Add any of them as a custom service.

## Configuration

```toml
[deploy_services]
services = ["forge", "ploi"]   # the default; [] turns them all off

# Your own deploy tool (repeat per tool):
[[deploy_services.custom]]
name  = "Acme Deploy"
cidrs = ["203.0.113.10", "198.51.100.0/28"]
url   = ""                     # optional https list
users = ["deploy"]             # accounts it logs in as
```

A hub without a `[deploy_services]` section uses the default (Forge and Ploi). `heimdall config update` appends the section, with its comments, to configs written before it existed.

### Your own deploy tool

`[[deploy_services.custom]]` covers a tool of your own, or a service not in the catalog. `cidrs` are fixed ranges. `url` is an optional https list: one address or CIDR a line (`#` comments allowed), or a JSON array of strings. The fixed and fetched ranges are stored together, as source `service:custom-<name>` (e.g. `service:custom-acme-deploy`). `users` are the accounts it logs in as. Each is a guess, like the catalog's.

## Commands

```sh
heimdall ip-services status         # each service: ranges stored, last sync, accounts, errors
sudo heimdall ip-services sync      # fetch now (or: sync forge)
sudo heimdall ip-services set-key ploi
```

## When a fetch fails

A failed fetch (the vendor is down, returns an error or an HTML page, or the list has an entry that isn't an address) keeps the **last good list**. The error is logged, shown by `ip-services status`, and the hub retries the next day. One bad entry fails the whole list: a half-parsed list is worse than yesterday's. Ranges broader than an IPv4 /8 or an IPv6 /16 are rejected the same way, since no deploy service publishes those. A list over 2 MB or 20,000 entries is rejected too.

Forge has a built-in copy of its list (taken Oct 24, 2026). It's stored only while no fetch has ever succeeded, for example when the hub can't reach the internet. Forge emails customers weeks before an address changes. No other service has a copy: their lists are larger or change without notice, and a stale copy could label someone else's address as a deploy service.

Turning a service off, or renaming a custom one, removes its labels on the next daily run or `ip-services sync`.

## Privacy

Only the public lists above are fetched, with a plain GET request. Nothing about your servers, sessions or users is sent. For Ploi, the request carries your API token, as Ploi's API requires.
