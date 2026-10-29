// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mcpb builds the Heimdall Desktop extension: an MCP Bundle
// (.mcpb, https://github.com/modelcontextprotocol/mcpb) that Claude
// Desktop installs with a double-click. The bundle holds a zero-dependency
// Node bridge that speaks MCP over stdio to Desktop and forwards each
// message to the hub's HTTP endpoint with the user's token.
//
// Each hub builds its own bundle, so the hub URL is already filled in.
// The token is never in the bundle: Desktop asks for it on install and
// keeps it in the OS keychain (user_config "sensitive").
package mcpb

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"time"
)

// ManifestVersion is the MCPB manifest spec version the bundle follows.
const ManifestVersion = "0.3"

// FileName is what the download for a hub whose connection is called
// name (mcp.name) is called: heimdall.mcpb, heimdall-acme.mcpb.
func FileName(name string) string { return name + ".mcpb" }

// DisplayName is the extension's name in Claude Desktop: "Heimdall", or
// "Heimdall (heimdall-acme)" for a hub that names its connection.
func DisplayName(name string) string {
	if name == "heimdall" {
		return "Heimdall"
	}
	return "Heimdall (" + name + ")"
}

//go:embed server/index.js
var bridgeJS []byte

//go:embed icon.png
var iconPNG []byte

// Build returns a .mcpb (a zip) for a hub whose MCP endpoint is at
// baseURL (mcp.base_url), labelled with the Heimdall release. name
// (mcp.name) is the extension's id, so extensions for two hubs with
// different names install side by side.
func Build(baseURL, release, name string) ([]byte, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("mcpb: base URL must be an absolute http(s) URL")
	}
	var manifest bytes.Buffer
	enc := json.NewEncoder(&manifest)
	enc.SetEscapeHTML(false) // keep ">=18.0.0" readable
	enc.SetIndent("", "  ")
	if err := enc.Encode(Manifest(baseURL, release, name)); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// A fixed timestamp keeps the bundle identical for identical inputs.
	mod := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, f := range []struct {
		name string
		data []byte
	}{
		{"manifest.json", manifest.Bytes()},
		{"server/index.js", bridgeJS},
		{"icon.png", iconPNG},
	} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: mod})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Manifest is the bundle's manifest.json.
func Manifest(baseURL, release, name string) map[string]any {
	version := semver(release)
	return map[string]any{
		"manifest_version": ManifestVersion,
		"name":             name,
		"display_name":     DisplayName(name),
		"version":          version,
		"description":      "Ask Claude about your servers: patch priorities, vulnerabilities, end-of-life software, Laravel sites and anomaly alerts, read-only from your Heimdall hub over your tailnet.",
		"long_description": "Connects Claude Desktop to a self-hosted Heimdall hub's read-only MCP endpoint. " +
			"The hub is reachable only on your tailnet, so this computer must be connected to it. " +
			"Your token stays in the system keychain and is sent only to your hub. " +
			"Every tool is read-only and scoped to your Heimdall roles.",
		"author":        map[string]any{"name": "Heimdall", "url": "https://github.com/realmwatch/heimdall"},
		"repository":    map[string]any{"type": "git", "url": "https://github.com/realmwatch/heimdall"},
		"homepage":      "https://github.com/realmwatch/heimdall",
		"documentation": "https://github.com/realmwatch/heimdall/blob/main/docs/mcp.md",
		"support":       "https://github.com/realmwatch/heimdall/issues",
		"license":       "AGPL-3.0-or-later",
		"icon":          "icon.png",
		"keywords":      []string{"security", "vulnerabilities", "patching", "inventory", "servers"},
		"server": map[string]any{
			"type":        "node",
			"entry_point": "server/index.js",
			"mcp_config": map[string]any{
				"command": "node",
				"args":    []string{"${__dirname}/server/index.js"},
				"env": map[string]string{
					"HEIMDALL_URL":            "${user_config.hub_url}",
					"HEIMDALL_TOKEN":          "${user_config.token}",
					"HEIMDALL_BRIDGE_VERSION": version,
				},
			},
		},
		"tools": []map[string]string{
			{"name": "search", "description": "Fleet search by package, version, CVE, site or host"},
			{"name": "patch_priorities", "description": "Open findings, known-exploited first"},
			{"name": "host", "description": "One host: OS, lifecycle, runtimes, findings, sites, containers"},
			{"name": "sites", "description": "Laravel and PHP apps with versions and findings"},
			{"name": "anomalies", "description": "Open tripwire alerts"},
			{"name": "changes", "description": "What changed between a host's last two check-ins"},
			{"name": "drift", "description": "Packages that differ across hosts sharing a tag"},
		},
		"compatibility": map[string]any{
			"platforms": []string{"darwin", "win32", "linux"},
			"runtimes":  map[string]string{"node": ">=18.0.0"},
		},
		"user_config": map[string]any{
			"hub_url": map[string]any{
				"type":        "string",
				"title":       "Heimdall URL",
				"description": "Your hub's MCP address (mcp.base_url). This computer must be on the tailnet to reach it.",
				"default":     baseURL,
				"required":    true,
			},
			"token": map[string]any{
				"type":        "string",
				"title":       "Token",
				"description": "Your personal MCP token (hmd_mcp_...), from the hub's AI assistants page. Stored in the system keychain.",
				"sensitive":   true,
				"required":    true,
			},
		},
	}
}

var semverRe = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)(-[0-9A-Za-z.-]+)?$`)

// semver turns a release ("v0.4.14", "v0.4.14-3-gabc123-dirty") into the
// semver the manifest needs; builds without one become 0.0.0-dev.
func semver(release string) string {
	m := semverRe.FindStringSubmatch(release)
	if m == nil {
		return "0.0.0-dev"
	}
	return m[1] + m[2]
}
