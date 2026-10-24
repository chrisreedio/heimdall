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
		{"news over http", func(c *Config) { c.News.Sources = []string{"http://pwn.watch/incidents.json"} }, "must be an https URL"},
		{"news with credentials", func(c *Config) { c.News.Sources = []string{"https://u:p@feed.example/x.json"} }, "credentials"},
		{"news with no host", func(c *Config) { c.News.Sources = []string{"https:///x.json"} }, "must name a host"},
		{"news enabled without sources", func(c *Config) { c.News.Enabled, c.News.Sources = true, nil }, "sources is empty"},
		{"news too often", func(c *Config) { c.News.Enabled, c.News.Interval.Duration = true, 10*time.Minute }, "at least 1h"},
		{"ai without endpoint", func(c *Config) { c.AI.Enabled, c.AI.Deployment = true, "sol" }, "ai.endpoint: is required"},
		{"ai over http", func(c *Config) { aiOn(c, "http://r.openai.azure.com") }, "must be an https URL"},
		{"ai with credentials", func(c *Config) { aiOn(c, "https://u:p@r.openai.azure.com") }, "credentials"},
		{"ai with query", func(c *Config) { aiOn(c, "https://r.openai.azure.com/?api-version=1") }, "query"},
		{"ai with a deployment path", func(c *Config) { aiOn(c, "https://r.openai.azure.com/openai/deployments/x") }, "base URL"},
		{"ai without deployment", func(c *Config) { aiOn(c, "https://r.openai.azure.com"); c.AI.Deployment = "" }, "ai.deployment"},
		{"ai deployment with slash", func(c *Config) { aiOn(c, "https://r.openai.azure.com"); c.AI.Deployment = "a/../b" }, "ai.deployment"},
		{"ai bad api", func(c *Config) { aiOn(c, "https://r.openai.azure.com"); c.AI.API = "completions" }, "ai.api"},
		{"ai brief too often", func(c *Config) { aiOn(c, "https://r.openai.azure.com"); c.AI.BriefEvery.Duration = time.Minute }, "brief_every"},
		{"ai tiny output", func(c *Config) { aiOn(c, "https://r.openai.azure.com"); c.AI.MaxOutputTokens = 10 }, "max_output_tokens"},
		{"ai bad effort", func(c *Config) { aiOn(c, "https://r.openai.azure.com"); c.AI.ReasoningEffort = "ultra" }, "reasoning_effort"},
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

	cfg = Default()
	if cfg.News.Enabled || len(cfg.News.Sources) != 1 || cfg.News.Sources[0] != DefaultNewsSource || cfg.News.Interval.Duration != time.Hour {
		t.Errorf("news defaults: %+v", cfg.News)
	}
	cfg.News.Enabled = true
	cfg.News.Sources = append(cfg.News.Sources, "https://Feeds.Example.com:8443/incidents.json")
	if err := cfg.Validate(); err != nil {
		t.Errorf("news enabled should be valid: %v", err)
	}
	if got := cfg.News.Hosts(); len(got) != 2 || got[0] != "pwn.watch" || got[1] != "feeds.example.com" {
		t.Errorf("news hosts: %v", got)
	}
}

func aiOn(c *Config, endpoint string) {
	c.AI.Enabled, c.AI.Endpoint, c.AI.Deployment = true, endpoint, "6.1 sol"
}

func TestAIConfig(t *testing.T) {
	cfg := Default()
	if cfg.AI.Enabled || cfg.AI.API != AIResponses || cfg.AI.BriefEvery.Duration != 24*time.Hour {
		t.Errorf("ai defaults: %+v", cfg.AI)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("ai off with no endpoint should be valid: %v", err)
	}
	// Plain http to loopback only in dev builds (a local fake server).
	aiOn(&cfg, "http://127.0.0.1:9999")
	if err := cfg.Validate(); (err == nil) != devBuild {
		t.Errorf("http loopback endpoint (dev build %v): %v", devBuild, err)
	}
	for _, ep := range []string{"https://MyRes.openai.azure.com", "https://myres.services.ai.azure.com/openai/v1/", "https://myres.cognitiveservices.azure.com/openai"} {
		aiOn(&cfg, ep)
		if err := cfg.Validate(); err != nil {
			t.Errorf("%s: %v", ep, err)
		}
	}
	if h := cfg.AI.Host(); h != "myres.cognitiveservices.azure.com" {
		t.Errorf("host %q", h)
	}
	// The template's [ai] section parses (and is off).
	c, err := parse(Template("h.db"))
	if err != nil || c.AI.Enabled || c.AI.MaxInputTokens != 24000 {
		t.Errorf("template: %+v %v", c.AI, err)
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
