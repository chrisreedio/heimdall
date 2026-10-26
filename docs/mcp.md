# MCP: ask your AI assistant about your fleet

Heimdall can serve its data to AI assistants (Claude Desktop, Claude Code, or any MCP client) over the **Model Context Protocol**, privately over your tailnet.

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
```

Use `tailscale serve`, never `tailscale funnel`: Funnel would put the endpoint on the internet.

While MCP is off, admins who open **AI assistants** (`/account/assistants`) see this snippet instead of the page, and the Users page links to it.

## Get a token (each user)

Every signed-in user has an **AI assistants** page (the link next to your email in the top bar, at `/account/assistants`):

- **Create** a token with a name for the device, like *MacBook Claude Desktop*. The token is shown **once**, with a copy button. Heimdall stores only its hash.
- **List** your tokens, with when each was created and last used.
- **Revoke** any of them. A revoked token stops working on its next request.

Use one token per device or assistant, so you can revoke them one at a time. Each user can have up to 10 active tokens, and can create up to 5 every 10 minutes. Creating and revoking are recorded in the audit log (`mcp_token.create`, `mcp_token.revoke`), just like the CLI.

Admins see every user's active tokens in the **AI tokens** column on the Users page, and can revoke any of them there.

## Connect: Claude Desktop

1. On the AI assistants page, click **Download the Heimdall extension**. Your hub builds `heimdall.mcpb` with its own `mcp.base_url` already filled in.
2. Double-click `heimdall.mcpb` to open it in Claude Desktop. You can also drag it into the window, or use **Settings → Extensions → Advanced settings → Install Extension…**. Then click **Install**.
3. Paste your token into the extension's **Token** setting. Claude Desktop keeps it in the OS keychain, because the field is marked `sensitive`.
4. Make sure this computer is **on the tailnet**, then ask *"what should I patch first?"*

### How the extension works

The extension is an [MCP Bundle](https://github.com/modelcontextprotocol/mcpb) (manifest version 0.3) holding `manifest.json`, an icon and `server/index.js`. That file is a bridge with **no dependencies**: it uses only Node.js built-ins, and runs on the Node.js that ships with Claude Desktop.

- Claude Desktop starts the bridge and speaks MCP to it over stdio. The bridge POSTs each message to `<hub_url>/mcp` with `Authorization: Bearer <token>`, then writes the hub's reply back to Desktop. Notifications get `202 Accepted` and no reply.
- It never sends an `Origin` header, which the hub would refuse. It sends `MCP-Protocol-Version` after `initialize`, and would pass along an `Mcp-Session-Id` if the hub issued one. Today's hub doesn't: it's stateless.
- Each request times out after 30 seconds. Errors are written to stderr, which Claude Desktop shows in the extension's logs, and are returned to Claude as JSON-RPC errors. Examples: "Heimdall refused the token (HTTP 401)…" and "Can't find hub… Is this machine connected to the tailnet?"
- The token is never logged, and never stored in the bundle. The bridge sends it only to the configured URL, which must be `https://` (plain `http://` is allowed only for localhost).

### Without the extension

The page also gives a `claude_desktop_config.json` snippet that uses [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) from npm. It needs Node.js installed:

```json
{
  "mcpServers": {
    "heimdall": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://hub.your-tailnet.ts.net:8444/mcp", "--header", "Authorization:${AUTH_HEADER}"],
      "env": { "AUTH_HEADER": "Bearer hmd_mcp_…" }
    }
  }
}
```

**Windows:** keep `Authorization:${AUTH_HEADER}` with no space, and put `Bearer …` in `env`. Claude Desktop on Windows splits arguments at spaces, so `"Authorization: Bearer …"` in `args` breaks.

## Connect: Claude Code

```sh
read -rs HMD_TOKEN   # paste your token, then press Enter
claude mcp add --scope user --transport http heimdall https://hub.your-tailnet.ts.net:8444/mcp \
  --header "Authorization: Bearer $HMD_TOKEN"
unset HMD_TOKEN
```

Because `read -rs` doesn't echo, the token never lands in your shell history. Claude Code saves the header in `~/.claude.json`.

**Windows (PowerShell 7.1+):**

```powershell
$t = Read-Host "Heimdall token" -MaskInput
claude mcp add --scope user --transport http heimdall https://hub.your-tailnet.ts.net:8444/mcp --header "Authorization: Bearer $t"
Remove-Variable t
```

## Connect: other clients

| | |
|---|---|
| URL | `https://hub.your-tailnet.ts.net:8444/mcp` |
| Header | `Authorization: Bearer hmd_mcp_…` |
| Transport | Streamable HTTP, JSON responses, no session. There's no OAuth: the token is the only credential. |

## Why not a Claude custom connector?

Claude's custom connectors (remote MCP added in Claude's settings) are reached **from Anthropic's cloud, not from your computer**. The server must be reachable from the public internet ([About connectors](https://support.claude.com/en/articles/11175166-about-connectors)). Heimdall's MCP endpoint stays on the tailnet on purpose.

There's a second reason. Connectors authenticate with OAuth, or with a static header that one organization Owner enters for the whole organization ([Authentication for connectors](https://claude.com/docs/connectors/building/authentication)). Neither fits Heimdall's per-user, per-role tokens.

The Desktop extension and Claude Code run on your own machine, so they reach the hub over the tailnet. **That machine must be on the tailnet** (Tailscale running and signed in). Otherwise the bridge reports that it can't find the hub.

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
| `threats` | Attacker addresses: failed SSH logins (and Cloudflare web events) across visible hosts, with ban score, network and ban status. Filters: `since`, `org`, `min_score`, `min_hosts`, `source`, `limit`. See [Threat list](threats.md). |
| `threat_networks` | The threat list rolled up per /24, /48 and ASN, with the same filters plus `kind` and `min_addresses` |

The same threat list is also a REST API on this listener (`GET /api/v1/threats`), for firewalls and other services. It takes **threat-list tokens** only (`hmd_threats_…`, created with *For: Threat list* on the AI assistants page, or `--purpose threats` in the CLI). An MCP token gets `403` there, and a threat-list token gets `403` on `/mcp`. See [Threat list](threats.md#tokens).

## Tokens from the CLI

| Command | |
|---|---|
| `hd user mcp-token create [--name …] [--purpose mcp\|threats] <email>` | New token, shown once. Only its hash is stored. `--purpose threats` makes a [threat-list](threats.md) token. |
| `hd user mcp-token list <email>` | Tokens with their last use |
| `hd user mcp-token revoke <email> <id>` | Stops working immediately |

The CLI and the web page use the same store functions, so they share the same audit entries and limits on names. The 10-token cap and the creation rate limit apply only to the web page.

Disabling a user (`hd user disable`) also stops their tokens. Every tool call is recorded in the audit log as `mcp.call`.

## Security notes

- **Tailnet plus token.** The tailnet decides who can *reach* the endpoint. The per-user token decides who they *are*, and therefore which orgs they see.
- **Shown once.** The new token appears only in the response to the form POST, which is never cached (`no-store`) and never in a URL. Afterwards, only its name and dates are shown.
- **Prompt injection.** Package names, hostnames and advisory summaries come from monitored hosts and public feeds. Every result is labelled as untrusted data, and the tools are read-only, so injected text can't make the assistant change anything in Heimdall or on your servers.
- **DNS rebinding.** Requests carrying an `Origin` header other than `mcp.base_url` are refused.
- **Bounded output.** Lists are capped at 100 items, with `truncated` and `total` fields.
