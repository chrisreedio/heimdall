// SPDX-License-Identifier: AGPL-3.0-or-later

package mcpb

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestBuild(t *testing.T) {
	const hub = "https://hub.example.ts.net:8444"
	b, err := Build(hub, "v0.4.15", "heimdall")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name], _ = io.ReadAll(rc)
		rc.Close()
	}
	var names []string
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	if want := []string{"icon.png", "manifest.json", "server/index.js"}; !slices.Equal(names, want) {
		t.Fatalf("files = %v, want %v", names, want)
	}
	if !bytes.Equal(files["server/index.js"], bridgeJS) || !bytes.HasPrefix(files["icon.png"], []byte("\x89PNG")) {
		t.Error("bridge or icon content differs")
	}
	// Zero dependencies: only Node built-ins (node:…).
	for _, m := range regexp.MustCompile(`require\(\s*["']([^"']+)["']`).FindAllStringSubmatch(string(bridgeJS), -1) {
		if !strings.HasPrefix(m[1], "node:") {
			t.Errorf("bridge requires %q, which isn't a Node built-in", m[1])
		}
	}

	var m struct {
		ManifestVersion string `json:"manifest_version"`
		Name            string `json:"name"`
		Version         string `json:"version"`
		License         string `json:"license"`
		Server          struct {
			Type       string `json:"type"`
			EntryPoint string `json:"entry_point"`
			MCPConfig  struct {
				Command string            `json:"command"`
				Args    []string          `json:"args"`
				Env     map[string]string `json:"env"`
			} `json:"mcp_config"`
		} `json:"server"`
		Compatibility struct {
			Platforms []string `json:"platforms"`
		} `json:"compatibility"`
		UserConfig map[string]struct {
			Type      string `json:"type"`
			Default   string `json:"default"`
			Sensitive bool   `json:"sensitive"`
			Required  bool   `json:"required"`
		} `json:"user_config"`
	}
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		t.Fatal(err)
	}
	if m.ManifestVersion != "0.3" || m.Name != "heimdall" || m.Version != "0.4.15" || m.License != "AGPL-3.0-or-later" {
		t.Errorf("manifest header: %+v", m)
	}
	if m.Server.Type != "node" || m.Server.EntryPoint != "server/index.js" || m.Server.MCPConfig.Command != "node" ||
		!slices.Equal(m.Server.MCPConfig.Args, []string{"${__dirname}/server/index.js"}) ||
		m.Server.MCPConfig.Env["HEIMDALL_URL"] != "${user_config.hub_url}" ||
		m.Server.MCPConfig.Env["HEIMDALL_TOKEN"] != "${user_config.token}" {
		t.Errorf("server: %+v", m.Server)
	}
	if !slices.Equal(m.Compatibility.Platforms, []string{"darwin", "win32", "linux"}) {
		t.Errorf("platforms: %v", m.Compatibility.Platforms)
	}
	if u := m.UserConfig["hub_url"]; u.Type != "string" || u.Default != hub || u.Sensitive {
		t.Errorf("hub_url: %+v", u)
	}
	if tok := m.UserConfig["token"]; tok.Type != "string" || !tok.Sensitive || !tok.Required || tok.Default != "" {
		t.Errorf("token: %+v", tok)
	}
	if bytes.Contains(files["manifest.json"], []byte("hmd_mcp_")) && !bytes.Contains(files["manifest.json"], []byte("hmd_mcp_...")) {
		t.Error("manifest carries a token")
	}

	// Same inputs, same bytes.
	if b2, _ := Build(hub, "v0.4.15", "heimdall"); !bytes.Equal(b, b2) {
		t.Error("bundle isn't deterministic")
	}
	if _, err := Build("not a url", "v1", "heimdall"); err == nil {
		t.Error("bad URL accepted")
	}
}

func TestSemver(t *testing.T) {
	for in, want := range map[string]string{
		"v0.4.14": "0.4.14", "0.4.14": "0.4.14", "v0.4.14-3-gabc123-dirty": "0.4.14-3-gabc123-dirty",
		"dev": "0.0.0-dev", "abc1234": "0.0.0-dev", "": "0.0.0-dev",
	} {
		if got := semver(in); got != want {
			t.Errorf("semver(%q) = %q, want %q", in, got, want)
		}
	}
}
