// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/config"
)

// set-name writes mcp.name into the config, keeping its comments, and
// refuses a name assistants wouldn't accept.
func TestMCPSetName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heimdall.toml")
	src := "# my hub\n[ui]\nlisten = \"127.0.0.1:8080\"\nbase_url = \"http://127.0.0.1:8080\"\n\n[mcp]\n# assistants\nenabled = false\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if err := run(t.Context(), []string{"-c", path, "mcp", "set-name", "heimdall-acme"}, &out, &errb); err != nil {
		t.Fatalf("set-name: %v (%s)", err, errb.String())
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MCP.Name != "heimdall-acme" || cfg.MCP.ConnectorName() != "heimdall-acme" {
		t.Errorf("mcp.name = %q", cfg.MCP.Name)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "# assistants") || !strings.Contains(string(b), "# my hub") {
		t.Errorf("comments lost:\n%s", b)
	}
	for _, bad := range []string{"Heimdall", "-x", "a b", strings.Repeat("a", 41)} {
		if err := run(t.Context(), []string{"-c", path, "mcp", "set-name", bad}, &out, &errb); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if cfg, _ := config.Load(path); cfg.MCP.Name != "heimdall-acme" {
		t.Errorf("a refused name changed the file: %q", cfg.MCP.Name)
	}
}
