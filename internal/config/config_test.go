// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTemplateMatchesDefaults(t *testing.T) {
	cfg, err := parse(Template("heimdall.db"))
	if err != nil {
		t.Fatalf("template does not parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("template does not validate: %v", err)
	}
	def := Default()
	if cfg.UI != def.UI || cfg.Ingest.RatePerHost != def.Ingest.RatePerHost ||
		cfg.Ingest.MaxBody != def.Ingest.MaxBody || cfg.Feeds != def.Feeds || cfg.Hosts != def.Hosts {
		t.Errorf("template and Default() disagree:\n%+v\n%+v", cfg, def)
	}
}

func TestTemplateWith(t *testing.T) {
	cfg, err := parse(TemplateWith(Setup{Database: "/var/lib/heimdall/heimdall.db", UIBaseURL: "https://hub.ts.net",
		IngestPublicURL: "https://ingest.example.com", BehindProxy: true, MCPBaseURL: "https://hub.ts.net:8444"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UI.BaseURL != "https://hub.ts.net" || cfg.Ingest.PublicURL != "https://ingest.example.com" ||
		!cfg.Ingest.BehindProxy || !cfg.MCP.Enabled || cfg.MCP.BaseURL != "https://hub.ts.net:8444" {
		t.Errorf("setup not applied: %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("rendered setup doesn't validate: %v", err)
	}
}

func TestTemplateQuotesDatabase(t *testing.T) {
	cfg, err := parse(Template(`/var/lib/heimdall/"odd".db`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database != `/var/lib/heimdall/"odd".db` {
		t.Errorf("database = %q", cfg.Database)
	}
}

func TestUnknownKeysRejected(t *testing.T) {
	_, err := parse([]byte("[ui]\nlisen = \"127.0.0.1:1\"\n"))
	if err == nil || !strings.Contains(err.Error(), "ui.lisen") {
		t.Fatalf("want unknown key error naming ui.lisen, got %v", err)
	}
}

func TestLoadResolvesRelativeDatabaseAndEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.toml")
	if err := os.WriteFile(path, Template("data/h.db"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "data/h.db"); cfg.Database != want {
		t.Errorf("database = %q, want %q", cfg.Database, want)
	}

	t.Setenv("HEIMDALL_UI_LISTEN", "127.0.0.1:9000")
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UI.Listen != "127.0.0.1:9000" {
		t.Errorf("env override not applied: %q", cfg.UI.Listen)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"public ingest without tls", func(c *Config) { c.Ingest.Listen = ":8443" }, "without TLS"},
		{"half tls", func(c *Config) { c.Ingest.TLSCert = "cert.pem" }, "set together"},
		{"nobody can log in", func(c *Config) { c.Auth.LocalLogin = false }, "nobody could log in"},
		{"entra incomplete", func(c *Config) { c.Auth.Entra.Enabled = true }, "client_id"},
		{"bad cidr", func(c *Config) { c.Ingest.AllowCIDRs = []string{"10.0.0.0/33"} }, "allow_cidrs"},
		{"db path with query", func(c *Config) { c.Database = "x.db?mode=memory" }, "database"},
		{"idle over max", func(c *Config) { c.UI.SessionIdle.Duration = 24 * time.Hour }, "session_idle"},
		{"plain http UI over the network", func(c *Config) { c.UI.BaseURL = "http://100.64.0.5:8080" }, "only allowed for loopback"},
		{"UI listening on the network", func(c *Config) { c.UI.Listen = "0.0.0.0:8080" }, "loopback"},
		{"UI base URL with a path", func(c *Config) { c.UI.BaseURL = "https://heimdall.internal/app" }, "no path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}

	cfg := Default()
	cfg.Ingest.Listen, cfg.Ingest.TLSCert, cfg.Ingest.TLSKey = ":8443", "c.pem", "k.pem"
	if err := cfg.Validate(); err != nil {
		t.Errorf("public ingest with TLS should be valid: %v", err)
	}
}

func TestUnmarshalers(t *testing.T) {
	var s ByteSize
	for in, want := range map[string]ByteSize{"5MB": 5 << 20, "512kb": 512 << 10, "100": 100, "1 GB": 1 << 30} {
		if err := s.UnmarshalText([]byte(in)); err != nil || s != want {
			t.Errorf("ByteSize(%q) = %d, %v; want %d", in, s, err, want)
		}
	}
	for _, in := range []string{"", "MB", "-1MB", "5TB", "0"} {
		if err := s.UnmarshalText([]byte(in)); err == nil {
			t.Errorf("ByteSize(%q) should fail", in)
		}
	}

	var r Rate
	if err := r.UnmarshalText([]byte("10/h")); err != nil || r != (Rate{10, time.Hour}) {
		t.Errorf("Rate(10/h) = %+v, %v", r, err)
	}
	for _, in := range []string{"10", "0/h", "10/w", "x/h"} {
		if err := r.UnmarshalText([]byte(in)); err == nil {
			t.Errorf("Rate(%q) should fail", in)
		}
	}

	var d Duration
	if err := d.UnmarshalText([]byte("-5m")); err == nil {
		t.Error("negative duration should fail")
	}
}
