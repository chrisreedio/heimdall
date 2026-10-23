# MCP: ask your AI assistant about your fleet

Heimdall can serve its data to AI assistants (Claude Code, Claude Desktop, or any MCP client) over the **Model Context Protocol**, privately over your tailnet.

> **Read-only.** Every tool reads what the hub already has, through the same scoped paths as the web UI. A user's MCP access equals their UI access, and nothing an assistant does can reach a server.

## Set up (hub)

```toml
# /etc/heimdall/heimdall.toml
[mcp]
enabled  = true
listen   = "127.0.0.1:8090"                      # always loopback
base_url = "https://hub.your-tailnet.ts.net:8444"  # the HTTPS address clients use
```

```sh
sudo tailscale serve --bg --https 8444 http://127.0.0.1:8090   # tailnet-only HTTPS
sudo systemctl restart heimdall
hd user mcp-token create --name laptop you@example.com           # prints the token once
```

## Connect (your machine)

```sh
claude mcp add --transport http heimdall https://hub.your-tailnet.ts.net:8444/mcp \
  --header "Authorization: Bearer hmd_mcp_…"
```

Then ask things like *"what should I patch first?"*, *"which sites still run Laravel 10?"* or *"what changed on web-01?"*.

## Tools

| Tool | What it answers |
|---|---|
| `search` | Fleet search: `openssl < 3.0.13`, `php = 8.1`, `laravel < 11`, `php-fpm = 8.2`, `composer:vendor/pkg < x`, `CVE-…`, `site:…`, `host:…` |
| `patch_priorities` | Open findings across visible hosts: known-exploited first, then fixable, severity, EPSS |
| `host` | One host: OS and lifecycle, runtimes, findings, sites, containers |
| `sites` | Laravel/PHP apps: versions, lifecycle, `require.php` mismatches, findings |
| `anomalies` | Open tripwire alerts |
| `changes` | What changed between a host's last two check-ins |
| `drift` | Packages that differ across hosts sharing a tag |

## Tokens

| Command | |
|---|---|
| `hd user mcp-token create [--name …] <email>` | New token, shown once. Only its hash is stored. |
| `hd user mcp-token list <email>` | Tokens with their last use |
| `hd user mcp-token revoke <email> <id>` | Stops working immediately |

Disabling a user (`hd user disable`) also stops their tokens. Every tool call is recorded in the audit log as `mcp.call`.

## Security notes

- **Tailnet plus token.** The tailnet decides who can *reach* the endpoint. The per-user token decides who they *are*, and therefore which orgs they see.
- **Prompt injection.** Package names, hostnames and advisory summaries come from monitored hosts and public feeds. Every result is labelled as untrusted data, and the tools are read-only, so injected text can't make the assistant change anything in Heimdall or on your servers.
- **DNS rebinding.** Requests carrying an `Origin` header other than `mcp.base_url` are refused.
- **Bounded output.** Lists are capped at 100 items, with `truncated` and `total` fields.
