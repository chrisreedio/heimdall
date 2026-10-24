#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Heimdall for Claude Desktop: a stdio-to-HTTP bridge for the hub's
// read-only MCP endpoint. Claude Desktop starts this script and speaks
// MCP to it over stdin/stdout (one JSON-RPC message per line); each
// message is POSTed to <hub>/mcp with the user's token, and the hub's
// reply is written back to stdout.
//
// Zero dependencies: Node built-ins only. Logs go to stderr, which Claude
// Desktop shows in its extension logs. The token is never logged.
"use strict";

const http = require("node:http");
const https = require("node:https");
const readline = require("node:readline");

const VERSION = process.env.HEIMDALL_BRIDGE_VERSION || "dev";
const TIMEOUT_MS = 30000; // per request
const MAX_RESPONSE = 16 << 20; // bytes
const TOKEN_RE = /^hmd_mcp_[A-Za-z0-9_-]{43}$/;

function log(msg) {
  process.stderr.write("[heimdall] " + msg + "\n");
}

// ── Configuration ─────────────────────────────────────────────────────────

// configError is why the bridge can't work at all, or "".
let configError = "";
let endpoint = null;

const token = (process.env.HEIMDALL_TOKEN || "").trim().replace(/^Bearer\s+/i, "");
const rawURL = (process.env.HEIMDALL_URL || "").trim();

function isLoopback(host) {
  host = host.replace(/^\[|\]$/g, "");
  return host === "localhost" || host === "::1" || /^127\./.test(host);
}

try {
  if (!rawURL) throw new Error("no hub URL");
  const u = new URL(rawURL);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && isLoopback(u.hostname))) {
    throw new Error("must be https:// (plain http only for localhost)");
  }
  if (!/\/mcp$/.test(u.pathname)) u.pathname = u.pathname.replace(/\/+$/, "") + "/mcp";
  u.search = "";
  u.hash = "";
  endpoint = u;
} catch (e) {
  configError = "The Heimdall URL in the extension's settings isn't usable (" + e.message +
    "). Use the address shown on the hub's AI assistants page, like https://hub.your-tailnet.ts.net:8444.";
}
if (!configError && !token) {
  configError = "No Heimdall token set. Create one on the hub's AI assistants page and paste it into the extension's settings.";
} else if (!configError && !TOKEN_RE.test(token)) {
  configError = "The token in the extension's settings doesn't look like a Heimdall MCP token (hmd_mcp_...). Paste the whole token.";
}

if (configError) log("error: " + configError);
else log("bridge " + VERSION + " ready; forwarding to " + endpoint.href);

// ── HTTP ──────────────────────────────────────────────────────────────────

let sessionId = ""; // Mcp-Session-Id, if the hub ever issues one
let protocolVersion = ""; // negotiated in initialize, sent on later requests

class BridgeError extends Error {}

// post sends one JSON-RPC message (or batch) and resolves to the list of
// JSON-RPC messages the hub sent back (empty for 202 Accepted).
function post(body) {
  return new Promise((resolve, reject) => {
    const lib = endpoint.protocol === "https:" ? https : http;
    const headers = {
      "Content-Type": "application/json",
      "Accept": "application/json, text/event-stream",
      "Authorization": "Bearer " + token,
      "User-Agent": "heimdall-mcpb/" + VERSION,
      "Content-Length": Buffer.byteLength(body),
    };
    // No Origin header: the hub refuses any Origin but its own.
    if (sessionId) headers["Mcp-Session-Id"] = sessionId;
    if (protocolVersion) headers["MCP-Protocol-Version"] = protocolVersion;

    const req = lib.request(endpoint, { method: "POST", headers, timeout: TIMEOUT_MS }, (res) => {
      const sid = res.headers["mcp-session-id"];
      if (typeof sid === "string" && sid) sessionId = sid;
      const chunks = [];
      let size = 0;
      res.on("data", (c) => {
        size += c.length;
        if (size > MAX_RESPONSE) {
          req.destroy(new BridgeError("the hub's response was larger than " + (MAX_RESPONSE >> 20) + " MB"));
          return;
        }
        chunks.push(c);
      });
      res.on("error", reject);
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        const status = res.statusCode || 0;
        if (status === 202 || status === 204) return resolve([]);
        if (status !== 200) return reject(new BridgeError(httpError(status, text)));
        const ctype = String(res.headers["content-type"] || "");
        try {
          if (ctype.startsWith("text/event-stream")) return resolve(parseSSE(text));
          if (!text.trim()) return resolve([]);
          const msg = JSON.parse(text);
          resolve(Array.isArray(msg) ? msg : [msg]);
        } catch (e) {
          reject(new BridgeError("the hub sent a reply that isn't JSON (" + ctype + ")"));
        }
      });
    });
    req.on("timeout", () => req.destroy(new BridgeError("the hub didn't answer within " + TIMEOUT_MS / 1000 + "s")));
    req.on("error", (e) => reject(e instanceof BridgeError ? e : new BridgeError(networkError(e))));
    req.end(body);
  });
}

function httpError(status, text) {
  const detail = text.trim().slice(0, 200);
  switch (status) {
    case 401:
      return "Heimdall refused the token (HTTP 401): it was revoked, its user was disabled, or it was mistyped. " +
        "Create a new token on the hub's AI assistants page and paste it into the extension's settings.";
    case 403:
      return "Heimdall refused the request (HTTP 403" + (detail ? ": " + detail : "") + ").";
    case 404:
      if (sessionId) { sessionId = ""; return "The hub ended this MCP session (HTTP 404). Restart the extension."; }
      return "Nothing answers at " + endpoint.href + " (HTTP 404). Check the Heimdall URL in the extension's settings.";
    case 413:
      return "The request was too large for the hub (HTTP 413).";
  }
  return "The hub answered HTTP " + status + (detail ? ": " + detail : "") + ".";
}

function networkError(e) {
  const where = endpoint.host;
  switch (e.code) {
    case "ENOTFOUND":
    case "EAI_AGAIN":
      return "Can't find " + where + ". Is this machine connected to the tailnet (Tailscale running and signed in)?";
    case "ECONNREFUSED":
      return "Connection to " + where + " was refused. Is MCP enabled on the hub and `tailscale serve` running?";
    case "ETIMEDOUT":
    case "ENETUNREACH":
    case "EHOSTUNREACH":
      return "Can't reach " + where + ". Is this machine connected to the tailnet?";
    case "ECONNRESET":
      return "The connection to " + where + " was reset.";
    case "CERT_HAS_EXPIRED":
    case "DEPTH_ZERO_SELF_SIGNED_CERT":
    case "UNABLE_TO_VERIFY_LEAF_SIGNATURE":
    case "ERR_TLS_CERT_ALTNAME_INVALID":
      return "The TLS certificate for " + where + " isn't valid (" + e.code + ").";
  }
  return "Can't reach " + where + ": " + (e.code || e.message);
}

// parseSSE returns the JSON-RPC messages in a text/event-stream body.
function parseSSE(text) {
  const out = [];
  for (const event of text.split(/\r?\n\r?\n/)) {
    const data = event.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).replace(/^ /, "")).join("\n");
    if (!data) continue;
    const msg = JSON.parse(data);
    for (const m of Array.isArray(msg) ? msg : [msg]) out.push(m);
  }
  return out;
}

// ── stdio ─────────────────────────────────────────────────────────────────

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function errorFor(id, message) {
  return { jsonrpc: "2.0", id, error: { code: -32000, message: /^Heimdall/.test(message) ? message : "Heimdall: " + message } };
}

const isRequest = (m) => m && typeof m === "object" && typeof m.method === "string" && m.id !== undefined && m.id !== null;

async function handle(msg) {
  const batch = Array.isArray(msg);
  const items = batch ? msg : [msg];
  const requests = items.filter(isRequest);
  if (configError) {
    requests.forEach((m) => send(errorFor(m.id, configError)));
    return;
  }
  const label = batch ? "batch of " + items.length : (msg && msg.method) || "response";
  try {
    const replies = await post(JSON.stringify(msg));
    for (const r of replies) {
      // Remember the protocol version the hub picked.
      const init = requests.find((m) => m.method === "initialize" && m.id === r.id);
      if (init && r.result && typeof r.result.protocolVersion === "string") protocolVersion = r.result.protocolVersion;
      send(r);
    }
  } catch (e) {
    log("error: " + label + ": " + e.message);
    requests.forEach((m) => send(errorFor(m.id, e.message)));
  }
}

const inflight = new Set();
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    log("error: ignoring a line on stdin that isn't JSON");
    send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
    return;
  }
  const p = handle(msg).finally(() => inflight.delete(p));
  inflight.add(p);
});
rl.on("close", async () => {
  await Promise.allSettled([...inflight]);
  process.exit(0);
});
process.stdout.on("error", (e) => {
  if (e.code === "EPIPE") process.exit(0);
});
