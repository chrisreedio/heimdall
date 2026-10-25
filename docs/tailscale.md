# Tailscale (optional)

> **Status: built, off by default, and tested against a local fake of the Tailscale API** (the documented OAuth token exchange and device listing). Run `sudo heimdall tailscale sync` first; it prints exactly what it found.

If your team reaches servers over a Tailscale tailnet, Heimdall can ask the Tailscale API which person and device each tailnet address belongs to. A privilege session from `100.101.102.103` then shows **alice@example.com's laptop-01**, not just "Tailnet".

It also tells you which of your Heimdall hosts are on the tailnet, which helps before you allow SSH only from the tailnet: **Hosts → Not on tailnet** lists the ones that aren't yet.

It's **read only**. Heimdall lists the tailnet's devices and never changes anything in Tailscale: no devices, keys, tags or policy.

## Set it up

1. **Create an OAuth client** (recommended: it doesn't expire). `sudo heimdall tailscale set-key` prints the link (https://login.tailscale.com/admin/settings/oauth). In the Tailscale admin console go to **Settings → Trust credentials** (formerly *OAuth clients*), choose **OAuth**, and give it only the **Devices → Core → Read** scope (`devices:core:read`). Read-only scopes don't need tags. Copy the client ID and the secret (`tskey-client-…`); the secret is shown once.

   An **API access token** (`tskey-api-…`, from **Settings → Keys**) also works, but it has your full admin rights and expires after 1 to 90 days. `heimdall tailscale status` warns two weeks before it expires.

2. **Turn it on** in `heimdall.toml` (`sudo heimdall config update` adds the section, off, to an older file):
   ```toml
   [tailscale]
   enabled    = true
   tailnet    = "-"     # "-" = the credential's own tailnet; or its ID or name, e.g. "example.com"
   sync_every = "15m"   # 1m to 24h
   ```

3. **Store the credential.** It never goes in the config file:
   ```sh
   sudo heimdall tailscale set-key                    # prompts for the secret (echo off), then the client ID
   sudo heimdall tailscale set-key --client-id kXXXX --stdin < secret.txt   # or pipe it
   ```
   This writes `/etc/heimdall/tailscale-key` (owner-only, atomically, like `ai set-key`) and adds `LoadCredential=heimdall-tailscale:/etc/heimdall/tailscale-key` to the hub's unit, so the hub reads it as a private systemd credential. Outside systemd, set `HEIMDALL_TAILSCALE_KEY_FILE` to the file instead.

4. **Check it, then restart:**
   ```sh
   sudo heimdall tailscale sync      # one sync now: device, label and host counts; never the secret
   sudo heimdall restart
   heimdall tailscale status         # credential kind, last sync, hosts not on the tailnet, warnings
   ```

The hub syncs 30 seconds after it starts and then every `sync_every`.

## What's synced and stored

Heimdall calls two endpoints on `https://api.tailscale.com/api/v2` (its only new outbound host; allow it if you firewall the hub):

| Call | What for |
|---|---|
| `POST /oauth/token` (`grant_type=client_credentials`) | OAuth clients only: a one-hour access token, cached and renewed as needed |
| `GET /tailnet/{tailnet}/devices?fields=default` | the device list (needs `devices:core:read`) |
| `GET /tailnet/{tailnet}/keys/{keyId}` | API access tokens only: when the token expires (best effort) |

For each device it stores its ID, MagicDNS name, hostname, Tailscale addresses, owner's login (none for tagged devices), tags, OS, client version and whether an update is available, whether it's connected, when it was last seen, and its node key expiry (table `tailscale_devices`, replaced on each sync). It doesn't store routes, posture data, machine or node keys.

Each address also becomes an IP label (source `tailscale`, every org) that the rest of Heimdall uses to name addresses:

- a person's device: kind **staff**, person = the owner's login, name = the device's hostname
- a tagged device (e.g. `tag:server`), or a device that is one of your Heimdall hosts: kind **infra**
- the note says it's from Tailscale, with its tags, OS, and online or last seen

If a sync fails (network, revoked credential), the last good devices and labels stay, and `tailscale status` shows the error.

## Host page

Hosts get a **Tailnet** card, just above *Privileged access*, when Tailscale is on and has synced:

- the device's name (MagicDNS name on hover) and owner, its tailnet addresses
- online, or when it was last seen; tags; Tailscale client version, and "client update available"
- **node key expires …** within two weeks, or **node key expired** (disable key expiry for servers in the admin console)
- or **Not on the tailnet**, when no device matches

A host matches a device when its reports come from one of the device's addresses, or else when its name matches the device's MagicDNS name, then its hostname (ignoring case and any domain: `web-01.example.com` matches `web-01.tail1234.ts.net`). If two devices share a hostname, the most recently seen one wins.

## Stopped reporting, still online

A switched-off collector is the classic sign of tampering, but on its own it looks the same as a server that's down. Tailscale tells them apart: when a host has been quiet for `hosts.alert_after` (or `stale_after`) and its tailnet device was still online, or seen online well after the host's last report, Heimdall raises **`silent_online`** (high). The machine is up, so something stopped or blocked its collector. A server that's off or unplugged leaves the tailnet too, and raises only the usual `silence`.

It needs a Tailscale sync less than an hour old, so a stale sync never raises it. Maintenance windows and suppressions apply, and it's raised once per silence. See [anomaly signals](anomaly-signals.md).

## Troubleshooting

- **HTTP 401, "the credential was refused":** the secret was mistyped, revoked, or (an API access token) expired. Store a new one with `sudo heimdall tailscale set-key`, then `sudo heimdall restart`.
- **HTTP 403:** the OAuth client lacks the `devices:core:read` scope. Edit it in the admin console, or create a new one.
- **HTTP 404, "tailnet not found":** `tailnet` in `[tailscale]` is wrong. Use `"-"` (the credential's own tailnet).
- **"Tailscale sync is enabled but has no credential"** in the hub's log: the unit has no `LoadCredential=heimdall-tailscale:…` line. Re-run `set-key`, or add it yourself, then restart.
- **A host shows "Not on the tailnet" but is:** its Heimdall name and its tailnet hostname differ, and it reports over the public internet. Rename one to match, or have the collector report over the tailnet so the report address matches.
- **`auth key` refused by set-key:** `tskey-auth-…` keys are for adding devices, not for the API. Create an OAuth client as above.
