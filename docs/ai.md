# AI analysis (optional)

> **Status: built, off by default, and not yet tested against a real Azure AI Foundry deployment.** Everything was developed against a local fake that mimics the documented API shapes. Run `heimdall ai test` first; see [What might differ on a real deployment](#what-might-differ-on-a-real-deployment).

Heimdall can ask **your own** Azure AI Foundry / Azure OpenAI model deployment for two things:

- **Daily brief:** a short summary of each org's fleet on the dashboard: what changed, what's urgent, and what to do first. It's written on a schedule (default daily), and an operator or admin can regenerate it.
- **Explain this host:** on-demand triage on a host page. It turns hundreds or thousands of findings into a short, prioritized plan, for example "patch these packages (copyable command), reboot, upgrade Laravel on this site, and these 55 kernel CVEs have no fix yet, so they can wait".

The output is **advisory text only**. Heimdall never runs a command a model suggests, and it shows a suggested command only if it has exactly the shape of the upgrade commands the host page already builds and names packages the host really has.

## Set it up

1. In the Azure portal, find your Azure OpenAI or AI Foundry resource. Note its endpoint (`https://<resource>.openai.azure.com`, or `https://<resource>.services.ai.azure.com`), a key from **Keys and Endpoint**, and the name of the model deployment you want to use.
2. Add this to `heimdall.toml`:
   ```toml
   [ai]
   enabled    = true
   endpoint   = "https://myres.openai.azure.com"   # https only; optionally ending in /openai/v1
   deployment = "6.1 sol"                          # your deployment's name, exactly
   api        = "responses"                        # or "chat"
   ```
3. Store the key. It never goes in the config file:
   ```sh
   sudo heimdall ai set-key      # prompts with echo off; or pipe it with --stdin
   ```
   This writes `/etc/heimdall/ai-key` (owner-only, atomically, like `sso set-secret`) and adds `LoadCredential=heimdall-ai:/etc/heimdall/ai-key` to the hub's unit, so the hub reads it as a private systemd credential.
4. Check it, then restart:
   ```sh
   sudo heimdall ai test         # one tiny request: prints the HTTP status, latency and model, never the key
   sudo heimdall restart
   heimdall ai status            # config, where the key comes from, the last brief per org
   ```

Outside systemd (development), point `HEIMDALL_AI_KEY_FILE` at an owner-only file instead.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Turns the feature on. Off means no outbound AI calls, no UI. |
| `endpoint` | `""` | The resource's base URL. Must be `https://`, with no credentials, query or fragment. Its path may be empty, `/openai` or `/openai/v1`. Its host becomes the AI client's only allowed destination. |
| `deployment` | `""` | Your deployment's name, sent as `model`. It's treated as an opaque label: Heimdall assumes nothing about which model it is. |
| `api` | `"responses"` | `responses` (the Responses API) or `chat` (Chat Completions). See below. |
| `reasoning_effort` | unset | Sent only if set (`none`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max`). Which values work depends on the model, so the default is to send nothing. |
| `brief_every` | `"24h"` | How often each org's brief is written. Use `"0"` for on demand only. The minimum is 1h. |
| `max_output_tokens` | `8000` | Caps the answer. For reasoning models this **includes reasoning tokens**, so don't set it too low. |
| `max_input_tokens` | `24000` | Per-run input budget, estimated at 4 bytes a token. The facts are trimmed (fewer findings, no summaries, fewer hosts) until they fit, and a run that can't fit isn't sent. |
| `timeout` | `"2m"` | Per run, including one retry. |

Runs happen in the background, at most two at a time. "Regenerate" is rate-limited to once a minute per host and per org brief.

## The API, and why

Researched on Microsoft Learn in October 2026:

- **v1 API, no `api-version`.** The GA v1 routes are `https://<resource>.openai.azure.com/openai/v1/responses` and `/openai/v1/chat/completions`. `https://<resource>.services.ai.azure.com/openai/v1/` is accepted too. v1 uses implicit versioning, so no `api-version` query is needed, and the deployment name goes in the `model` field.
  - [API version lifecycle (v1)](https://learn.microsoft.com/en-us/azure/foundry/openai/api-version-lifecycle)
  - [Endpoints](https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/endpoints)
  - [Switching endpoints: the deployment name is the model](https://learn.microsoft.com/en-us/azure/developer/ai/how-to/switching-endpoints)
  - The older deployment-based URL (`.../openai/deployments/<name>/chat/completions?api-version=2024-10-21`) isn't used. Every current resource serves v1.
- **Responses is the default.** Microsoft recommends the Responses API for Azure OpenAI models. Several newer models are Responses-only on Azure, including the `*-pro` and codex models, and every GPT-5.x/o-series model supports it. `api = "chat"` is there for deployments that only speak Chat Completions, such as some third-party models, which answer `400 Model not supported` on Responses.
  - [Reasoning models](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/reasoning)
  - [Responses API reference (v1)](https://learn.microsoft.com/en-us/rest/api/microsoft-foundry/azureopenai/responses?view=rest-microsoft-foundry-v1)
- **Auth:** the key is sent in the `api-key` header, the documented header for key auth. v1 also accepts `Authorization: Bearer <key>`, which is what Entra tokens use. Entra (managed identity) auth isn't implemented.
- **Structured output:** a strict JSON schema.
  - On Responses: `text: {format: {type: "json_schema", name, strict: true, schema}}`.
  - On Chat: `response_format: {type: "json_schema", json_schema: {name, strict: true, schema}}`.
  - Strict mode needs `additionalProperties: false` and every property `required`, with optional fields made nullable. It rejects `maxLength`, `pattern`, `minItems` and similar keywords, so Heimdall enforces lengths and counts after parsing.
  - [Structured outputs](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/structured-outputs)
- **Parameters:**
  - Reasoning models accept only `max_completion_tokens` on Chat (`max_output_tokens` on Responses), and both limits include reasoning tokens.
  - They reject `temperature`, `top_p`, the penalties and `max_tokens`, so Heimdall never sends those.
  - Reasoning effort is `reasoning: {effort}` on Responses and `reasoning_effort` on Chat, and is sent only when configured.
  - The instructions go in Responses' `instructions`, or a `system` message on Chat.
  - Responses requests send `store: false`, so the request and answer aren't kept on the provider for later retrieval.
- **Responses parsed:**
  - Responses: `status`, `incomplete_details.reason`, `output[]` message items' `output_text` and `refusal` parts (reasoning items are skipped), and `usage.input_tokens`/`output_tokens`.
  - Chat: `choices[0].message.content`/`refusal`, `finish_reason`, and `usage.prompt_tokens`/`completion_tokens`.
- **Errors:** the body is `{"error": {"code", "message"}}`. A blocked prompt is a 400 with `code: "content_filter"`. Filtered output is a 200 with `finish_reason: "content_filter"` or `status: "incomplete"`. A 429 carries `retry-after-ms` or `retry-after`. Heimdall retries a 429 or 5xx once, honoring those headers (waiting at most 20 seconds) when the timeout allows.
  - [Quotas and rate limits](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/quota)
  - [Content filtering](https://learn.microsoft.com/en-us/azure/ai-foundry/openai/concepts/content-filter?view=foundry-classic)

## Data sent to your AI provider

This is **exactly** what leaves the hub, as one JSON document per run. It's built in [`internal/ai/facts.go`](../internal/ai/facts.go), and that file and this list are kept in sync. Free text is trimmed to one line and a fixed length. Nothing else is sent: no raw snapshots, full package lists, IP addresses, tokens, user names or emails, audit log, or config.

**Explain this host** (one host):
- **Host:** its name and environment; its OS name and OS lifecycle (product, cycle, end-of-life flag and date); when it last reported and whether it's stale; whether a reboot is required; its package manager; and its pending update and pending security update counts.
- **Finding counts:** total, KEV, by severity, fixable, fix pending and no fix yet, plus how many findings are in the news.
- **Top findings:** up to 25, ranked like Patch first (KEV, in the news, fixable, severity, EPSS, CVSS). Each one has:
  - the package, installed version and fixed-in version, and whether the fix is already pending;
  - the advisory ID and up to 3 CVEs;
  - the severity, KEV flag, EPSS and in-the-news flag;
  - the advisory summary, trimmed to 160 characters.
- **No fix yet:** a count per package (up to 15) with its worst severity.
- **Runtimes:** name, version and lifecycle.
- **Sites:**
  - the first server name and the root path;
  - the framework, its version and lifecycle;
  - the PHP-FPM version, its lifecycle, the composer.json PHP requirement and whether it's met;
  - Composer finding counts, and up to 10 fixable Composer findings, with the same fields as the top findings minus the summary.
- **Open anomalies:** up to 30, each with its rule, severity, summary and when it was detected.
- **News:** the titles, severities and status of incidents that affect this host.
- **Plans and windows:** whether the host is in an open patch plan, and its current maintenance windows, described in a line each.
- **Suggested commands:** the commands Heimdall itself would offer for this host, built from the host's own package names. They cover the fixable OS findings, pending security updates, each site's fixable Composer packages, and a reboot if one is required.

**Daily brief** (one org):
- **Org and totals:** the org's slug, the period length, and the fleet totals: hosts reporting, KEV and critical findings, hosts with fixes, hosts on end-of-life software, reboots, stale hosts, pending security updates, and findings that appeared or were resolved in the period.
- **Hosts:** up to 60, most urgent first, with the same host fields as above but only the top 1–3 findings. Each also has its new and resolved finding counts for the period and its suggested upgrade and reboot commands. Sites are included only when they need attention (end of life, fixable findings, or an unmet PHP requirement).
- **Open anomalies:** up to 30, each with its host.
- **News:** up to 10 incidents that affect the org's hosts, with those hosts' names.
- **Maintenance windows:** the current ones.
- **Open patch plans:** each one's name and its host, done and verified counts.

When the input budget is tight, the less important parts go first: fewer findings, then no advisory summaries, then fewer hosts.

## Safety design

- **Off by default,** and a separate outbound allowlist. The AI client may reach only the endpoint's host, over HTTPS, through `internal/netx` (redirects included). Feed sync, SSO and news can't reach it, and it can't reach them. Responses are capped at 2 MB.
- **The key** never appears in the config file, the database, logs, the UI, or `ai test`/`ai status` output. Error messages from the provider are trimmed, kept to one line and scrubbed of the key before they're logged.
- **Prompt injection:** hostnames, package names, advisory summaries, anomaly summaries and news titles come from monitored hosts and public feeds, so they're treated as hostile.
  - All of that data goes in one section between `<<<BEGIN UNTRUSTED DATA>>>` and `<<<END UNTRUSTED DATA>>>`. It carries the same untrusted-data note the MCP endpoint attaches to every result, and the instructions say plainly that the section is data, never instructions.
  - The data is JSON from Go's encoder, which escapes `<` and `>`, so nothing inside it can fake the end marker. No reported text appears outside the section.
- **Output is checked, not trusted.**
  - The answer must parse as the schema's JSON object (`summary`, up to 8 `actions` of `{title, why, host, command}`, and `notes`). Text is stripped of control and bidi characters and trimmed to fixed lengths.
  - An action's `host` must be a hostname from the data. Otherwise both the host and its command are dropped.
  - A `command` is kept only if it's exactly one of these shapes, naming only packages that host has installed (or has in its sites' Composer lockfiles), with no duplicates and at most 60 packages:
    - `sudo apt-get [update && sudo apt-get] install --only-upgrade <pkgs>`
    - `sudo dnf upgrade [--refresh] <pkgs>`
    - `sudo apk [update && sudo apk] upgrade <pkgs>`, all matching the host's package manager
    - `composer update <vendor/pkg…> [--with-dependencies]`
    - `sudo reboot`

    Anything else, such as pipes, `;`, `$(…)`, flags or unknown packages, is dropped. The prose stays.
  - Results are rendered with `html/template` as escaped text (no `template.HTML`). Commands appear in the usual copy box. The shape check runs again at render time.
- **Nothing is executed.** The hub has no `os/exec` path for this, and the UI says so.
- **Hand off to agent.** With `[[agents]]` configured, a plan step whose command is a `composer update` for one of the host's sites gets a "Hand off to agent" button (operators and admins only). The message it posts is rebuilt from the site's own findings, never from the model's text. See [Hand off to an agent](deployment.md#hand-off-to-an-agent).
- **Access:**
  - Briefs are one per org and shown only for orgs the viewer can see. Host explanations follow the host page's access rules.
  - Generating or regenerating needs the operator or admin role in that org. The form is a POST with the CSRF token and Origin check every form uses.
  - Asking about a host outside your scope gets the same 404 as a missing host.
- **Audit:** every run writes an audit log entry (`ai.brief` or `ai.explain`) with the actor (`user:<id>`, or `hub:schedule` for scheduled briefs), the org, the host or org, and the deployment, status, input and output token counts, latency, facts size and the fixed error text. Prompts and answers are never logged.
- **Failures are calm.** The UI shows one of a few fixed messages (for example "The AI provider is rate limiting requests; try again in a few minutes"), never a stack trace or raw provider text. The last good result stays visible.

## Storage

Migration `0011_ai.sql` adds `ai_runs`: one row per run, holding the org, host (null for briefs), kind, status (`running`, `ok` or `error`), created and finished times, who asked, the deployment, the model the API reported, the token counts, the fixed error text, and the validated result JSON. The last 10 runs per org brief and per host are kept, and older ones are pruned when a run finishes. A `running` row older than the timeout plus a minute (for example, after a restart) is shown as timed out and doesn't block a new run.

## What might differ on a real deployment

These were built from the documentation and a local fake, not a live resource:

- **`404 DeploymentNotFound`** means a wrong `deployment` name or a resource that doesn't serve v1. Copy the name exactly from the Foundry portal's Deployments list. Spaces are allowed.
- **`400` on Responses** with "model not supported" or similar means the deployment only speaks Chat Completions. Set `api = "chat"`.
- **Structured output:** `ai test` notes it if the answer isn't JSON. Older or third-party models may not support strict `json_schema`. Heimdall then still accepts a plain JSON object (and strips a Markdown code fence), but a model that ignores the format will fail with "The model's answer wasn't in the expected format".
- **"Ran out of output tokens"** means a reasoning model spent its budget thinking. Raise `max_output_tokens`, or set `reasoning_effort = "low"` if the model supports it.
- **Endpoints:** `*.cognitiveservices.azure.com` endpoints aren't documented as v1 inference hosts. Prefer the `openai.azure.com` or `services.ai.azure.com` address shown on the resource.
- **Token counts** are whatever the API reports in `usage`. The input budget is only an estimate (4 bytes a token).
- **Egress:** if the hub's firewall limits outbound traffic, allow the endpoint's host on 443.

## Development

Dev builds (`go build -tags dev`) accept a plain-http **loopback** `ai.endpoint` (for example `http://127.0.0.1:19590`) and let `internal/netx` reach it, so you can run against a local fake model server. Release builds reject http endpoints outright. Tests use `httptest` servers that mimic the shapes above (success, 401, 404, 429 with retry, 500, timeout, malformed or oversized JSON, incomplete and filtered output, refusals, schema-invalid answers, injected markup and commands outside the allowlist). No test calls a real endpoint.
