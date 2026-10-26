# IP awareness

The privilege watch records where each sudo, su or root SSH session came from (with `--watch-privilege-users`, see [collector.md](collector.md#privilege-watch)). An address on its own says little. Heimdall says whose it is: a person on the team, a deploy service, one of your own servers, the tailnet. When nobody knows, it says that too, and it can alert.

## Kinds of address

Every address gets a **verdict**: everything known about it, the most telling first. Its kind is one of:

| Kind | Means | Badge |
|---|---|---|
| `staff` | a person on the team: an office, a home connection, a VPN exit | the person, e.g. "alice" |
| `automation` | a deploy service or CI that logs in for you (Forge, Ploi, your own deploy tool, GitHub Actions) | its name, e.g. "Laravel Forge" |
| `infra` | your own servers, the hub, a proxy | the host names |
| `tailnet` | on your Tailscale tailnet (100.64.0.0/10, fd7a:115c:a1e0::/48), device or person not known | "Tailnet", or the device |
| `private` | a private network, loopback or link-local | "Private network" |
| `unknown` | nothing is known | "unknown address", in warning colors |

Knowledge comes from:

- **Manual labels** you add (below).
- **Synced labels** that a source keeps current: a deploy service's published ranges, the Tailscale API, Cloudflare. They're replaced wholesale on each sync and can't be edited by hand; the last good sync stays if a source is down.
- **Built-in ranges**: the tailnet's CGNAT range, private networks, loopback and link-local.
- **Your hosts**: the address each host's last report came from is labeled `infra` with the host's name.
- **Heimdall sign-ins** (a guess, below).
- **Account names**: a deploy service's SSH user (say `forge`) can mark a session `automation` even when the address isn't in its ranges.

A label applies to one org, or (added by a global admin or `--all-orgs`) to every org.

### Ranking and guesses

When several labels match, the verdict lists them all and the badge shows the first. Known labels come before guesses, then the most specific range (a `/32` before a `/24`), then the most telling kind (in the table's order). So a `/32` labeled `staff` beats the deploy service's `/24` it sits in, and a manual label beats a sign-in guess.

A **guess** is inferred, not known. Badges for guesses say "probably alice" and are shown in italics.

## Labeling addresses

Org admins label addresses on **IP addresses** (`/ips`, in the navigation for admins): an address or CIDR range, a kind, a name ("Office", "Alice's home") and optionally the person and a note. The page lists every label that applies to each org you administer, manual ones (removable) and synced ones grouped by source with when they last synced. Global admins also see and manage labels for every org. Adding and removing labels is audited.

Each privilege session's address links to its **IP page** (`/ips/<address>`), with the verdict and every label, and everywhere the address appears in the orgs you can see: privilege sessions (host, user, kind, when) and hosts whose reports come from it. Global admins also see Heimdall sign-ins from it; admins see audit log entries recorded from it (org admins only their orgs'). Admins get a **Label this address** button that opens the form prefilled.

From the CLI:

```sh
heimdall ip label add --org acme --kind staff --name "Office" --person alice@example.com 203.0.113.0/24
heimdall ip label add --all-orgs --kind automation --name "CI runners" 198.51.100.7
heimdall ip label list [--org acme]     # every label, manual and synced, with its ID
heimdall ip label rm --org acme 12
heimdall ip show [--org acme] [--user forge] 203.0.113.9
```

`ip show` prints the verdict: kind, best label, and every label with its source, range and whether it's a guess. `--org` is optional when there's one org.

## Signed in from here

If someone who can see the org signed in to Heimdall's web UI from the same address within 12 hours of a session, the session is probably them: the verdict gets a `staff` guess, "Signed in to Heimdall", with that person. It uses open sessions and past sign-ins from the audit log. Only users with a role in the org (or global admins) are matched, so one org's sign-ins never name people to another. Loopback and unspecified addresses are ignored.

### Behind `tailscale serve`

If the UI sits behind `tailscale serve` (the recommended setup), every request reaches Heimdall from `127.0.0.1`, so sign-ins have no useful address. Tell Heimdall:

```toml
[ui]
behind_tailscale_serve = true
```

Then, **only for requests from loopback**, the UI takes the client's address from the last `X-Forwarded-For` hop (the one tailscale serve adds) and records the tailnet identity from `Tailscale-User-Login` and `Tailscale-User-Name` on the session (shown on the IP page). Requests from anywhere else are never trusted with these headers. Leave it `false` if anything other than tailscale serve could reach the UI port on loopback, or if you use another proxy. The address is also what the audit log and sign-in throttling see. Restart the hub after changing it (`sudo heimdall restart`).

## On the host page

The **Privileged access** card lists recent sessions with a badge per source: "alice", "probably alice", "Laravel Forge", "web-02", "Tailnet", or **unknown address**. Each address links to its IP page. If any session in the last 24 hours came from an unknown address, a line says so with links to label them.

The dashboard's **Needs attention** section adds a line when privileged sessions in the last 7 days came from unknown addresses, linking the hosts.

## Alerts

Two privilege watch rules use the verdicts. Both are **high** (so they notify immediately), raise one anomaly per host, source and UTC day (later sessions add to its count), and honor [suppressions](anomaly-signals.md#keeping-the-noise-down) (`heimdall anomaly suppress --rule privilege_unknown_source ...`).

- **Privileged access from an unknown address** (`privilege_unknown_source`): a session whose source is `unknown`: no label, not the tailnet or a private network, not one of your hosts, no matching sign-in. A source that's a host name (sshd with `UseDNS yes`) can't be checked, so it counts as unknown. Sessions inside a maintenance window don't count, like `privileged_access`. Anything known never alerts here, deploy services included.
- **SSH from outside the tailnet** (`privilege_off_tailnet`): only for orgs with the tailnet-only policy on.

Sessions with no source (local, or "?") never alert under either rule.

The privilege watch's own rule, `privileged_access` (medium), counts every session outside a maintenance window, except deploy-service sessions (below).

### Deploy-service sessions and privileged access

A deploy service such as Laravel Forge SSHes in as root, or as its own account, on every deploy. Counted as privileged access, each deploy would raise an alert that says nothing new. So by default a session **from a deploy service's synced range** doesn't count toward `privileged_access`.

Only a verified address is exempt:

- **Exempt:** the source is inside an `automation` range kept in sync by a source, such as the published addresses the hub fetches from Forge or Ploi each day, or a `[[deploy_services.custom]]` tool's ranges ([deploy-services.md](deploy-services.md)). The account doesn't matter: Forge logging in as `root` from its range is exempt.
- **Not exempt:** a session recognized only by its account name, such as `forge` from a home connection. Anyone with the password or key can log in as `forge`, so the name proves nothing about who it is. It counts toward `privileged_access`, and if nothing else is known about the address it raises `privilege_unknown_source` too.
- **Not exempt:** a manual `automation` label. Anyone with admin access can add one, so it says whose an address is, not that it's the service's own.

The exemption only changes `privileged_access`. A deploy service's address is known, so it never raises `privilege_unknown_source` either way. `privilege_off_tailnet` has its own switch for deploy services, **Except deploy services** (below).

To count deploy-service sessions again, for example to keep a record of every deploy as an anomaly, turn on **count deploy-service sessions as privileged access** under the org on the IP addresses page (`/ips`) and press **Save policy**, or:

```sh
heimdall ip policy --org acme --count-services on    # count them
heimdall ip policy --org acme --count-services off   # exempt them (the default)
heimdall ip policy --org acme                        # show the policy
```

It's per org, off by default (deploy-service sessions are exempt), and each change is written to the audit log (`ip_policy.set`), with who made it.

A worked example. Forge's synced ranges include 198.51.100.7. On one day, outside any maintenance window, `web-01` reports:

| Session | Source | Counts toward `privileged_access`? | Also raises |
|---|---|---|---|
| root SSH as `root` | 198.51.100.7 (Forge's range) | no | nothing |
| sudo as `forge` | 198.51.100.7 (Forge's range) | no | nothing |
| root SSH as `forge` | 203.0.113.9 (unknown) | yes: the account name alone | `privilege_unknown_source` |
| sudo as `chris` | 192.0.2.7 (labeled staff) | yes | nothing |
| sudo as `chris` | none (local console) | yes | nothing |

That day's anomaly reads "3 privileged accesses outside a maintenance window ...: 2 sudo, 1 root SSH". With `--count-services on`, the Forge sessions count too: 5.

### The tailnet-only policy

For orgs that reach their servers only over Tailscale, turn on **SSH only from the tailnet** on the IP addresses page, or:

```sh
heimdall ip policy --org acme --tailnet-only on [--allow-services on|off] [--count-services on|off]
heimdall ip policy --org acme          # show it
```

With it on, any privileged session from an address that isn't on the tailnet, a private network or loopback raises `privilege_off_tailnet`, **even if the address is labeled** (a label says whose it is, not that it's allowed). This goes by the address alone, so a label can't make a public address count as internal, and maintenance windows don't exempt it. It replaces the unknown-address alert for those sessions, so one session never raises both.

Deploy services such as Forge and Ploi deploy over the public internet. **Except deploy services** (`--allow-services`, on by default) exempts addresses in an `automation` range kept in sync by a source, such as a deploy service's published ranges. A manual `automation` label, or a session recognized only by its account name, isn't exempt: anyone can claim a name, but a synced range is the service's own. Turn it off to alert on those too. It's separate from `--count-services`, which decides whether those sessions count toward `privileged_access` ([above](#deploy-service-sessions-and-privileged-access)).

"Automation" is generic: a deploy tool of your own can publish its ranges the same way.

## Deploy services

See [deploy-services.md](deploy-services.md).

## Tailscale

See [tailscale.md](tailscale.md).

## Cloudflare

See [cloudflare.md](cloudflare.md).
