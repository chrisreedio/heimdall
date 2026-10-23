// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config loads and validates heimdall.toml.
//
// Decoding is strict: unknown keys are an error, so a typo never silently
// falls back to a default. Secrets are never read from this file.
package config

import (
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Database string  `toml:"database"`
	UI       UI      `toml:"ui"`
	Auth     Auth    `toml:"auth"`
	Ingest   Ingest  `toml:"ingest"`
	Feeds    Feeds   `toml:"feeds"`
	Hosts    Hosts   `toml:"hosts"`
	Notify   Notify  `toml:"notify"`
	MCP      MCP     `toml:"mcp"`
	Updates  Updates `toml:"updates"`
}

// Updates controls the daily check for a newer release (admins see a
// banner). It reads only the latest version number from GitHub.
type Updates struct {
	Check bool `toml:"check"`
}

// MCP configures the read-only Model Context Protocol endpoint for AI
// assistants. Like the UI it listens on loopback; expose it over HTTPS
// with `tailscale serve` or a local proxy.
type MCP struct {
	Enabled bool   `toml:"enabled"`
	Listen  string `toml:"listen"`
	BaseURL string `toml:"base_url"` // the https origin clients use (checked against Origin headers)
}

// Notify configures the counts-only digest. Secrets (SMTP password, the
// webhook URL, which embeds a token) come from systemd credentials.
type Notify struct {
	Every         Duration `toml:"every"` // 0 = digests off
	EmailTo       []string `toml:"email_to"`
	EmailFrom     string   `toml:"email_from"`
	SMTPHost      string   `toml:"smtp_host"`
	SMTPPort      int      `toml:"smtp_port"`
	SMTPUsername  string   `toml:"smtp_username"`
	Webhook       bool     `toml:"webhook"`        // URL from credential "heimdall-webhook"
	WebhookFormat string   `toml:"webhook_format"` // "slack" or "json"
}

type UI struct {
	Listen      string   `toml:"listen"`
	BaseURL     string   `toml:"base_url"`
	SessionIdle Duration `toml:"session_idle"`
	SessionMax  Duration `toml:"session_max"`
}

type Auth struct {
	LocalLogin bool  `toml:"local_login"`
	Entra      Entra `toml:"entra"`
}

type Entra struct {
	Enabled        bool     `toml:"enabled"`
	Tenant         string   `toml:"tenant"`
	ClientID       string   `toml:"client_id"`
	AllowedTenants []string `toml:"allowed_tenants"`
	AppRoleMapping bool     `toml:"app_role_mapping"`
}

type Ingest struct {
	Listen      string   `toml:"listen"`
	TLSCert     string   `toml:"tls_cert"`
	TLSKey      string   `toml:"tls_key"`
	MaxBody     ByteSize `toml:"max_body"`
	RatePerHost Rate     `toml:"rate_per_host"`
	AllowCIDRs  []string `toml:"allow_cidrs"`
	// PublicURL is the https URL servers use to reach ingest (shown in the
	// UI's install commands), e.g. https://ingest.example.com.
	PublicURL string `toml:"public_url"`
	// BehindProxy trusts the last X-Forwarded-For hop, but only on
	// connections from loopback (a local TLS-terminating proxy).
	BehindProxy bool `toml:"behind_proxy"`
}

type Feeds struct {
	SyncInterval Duration `toml:"sync_interval"`
	OSV          bool     `toml:"osv"`
	KEV          bool     `toml:"kev"`
	EPSS         bool     `toml:"epss"`
	EndOfLife    bool     `toml:"endoflife"`
}

type Hosts struct {
	StaleAfter Duration `toml:"stale_after"`
	// Snapshot retention: older than KeepFor are deleted, but each host
	// always keeps at least KeepMin (and its latest).
	KeepFor Duration `toml:"keep_snapshots_for"`
	KeepMin int      `toml:"keep_snapshots_min"`
}

// Default returns the configuration used for any key the file leaves out.
func Default() Config {
	return Config{
		Database: "heimdall.db",
		UI: UI{
			Listen:      "127.0.0.1:8080",
			BaseURL:     "http://127.0.0.1:8080",
			SessionIdle: Duration{30 * time.Minute},
			SessionMax:  Duration{12 * time.Hour},
		},
		Auth: Auth{
			LocalLogin: true,
			Entra:      Entra{Tenant: "organizations", AppRoleMapping: true},
		},
		Ingest: Ingest{
			Listen:      "127.0.0.1:8443",
			MaxBody:     5 << 20,
			RatePerHost: Rate{N: 10, Per: time.Hour},
		},
		Feeds: Feeds{
			SyncInterval: Duration{6 * time.Hour},
			OSV:          true,
			KEV:          true,
			EPSS:         true,
			EndOfLife:    true,
		},
		Hosts:   Hosts{StaleAfter: Duration{72 * time.Hour}, KeepFor: Duration{180 * 24 * time.Hour}, KeepMin: 30},
		Notify:  Notify{SMTPPort: 587, WebhookFormat: "slack"},
		MCP:     MCP{Listen: "127.0.0.1:8090", BaseURL: "http://127.0.0.1:8090"},
		Updates: Updates{Check: true},
	}
}

// Load reads the file at path, applies HEIMDALL_* environment overrides,
// resolves relative paths against the file's directory and validates.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg, err := parse(b)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	applyEnv(&cfg, os.LookupEnv)
	if !filepath.IsAbs(cfg.Database) {
		cfg.Database = filepath.Join(filepath.Dir(path), cfg.Database)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func parse(b []byte) (Config, error) {
	cfg := Default()
	md, err := toml.Decode(string(b), &cfg)
	if err != nil {
		return Config{}, err
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return Config{}, fmt.Errorf("unknown keys: %s", strings.Join(keys, ", "))
	}
	return cfg, nil
}

func applyEnv(cfg *Config, lookup func(string) (string, bool)) {
	for name, dst := range map[string]*string{
		"HEIMDALL_DATABASE":      &cfg.Database,
		"HEIMDALL_UI_LISTEN":     &cfg.UI.Listen,
		"HEIMDALL_UI_BASE_URL":   &cfg.UI.BaseURL,
		"HEIMDALL_INGEST_LISTEN": &cfg.Ingest.Listen,
	} {
		if v, ok := lookup(name); ok {
			*dst = v
		}
	}
}

func (c Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if err := ValidateDatabasePath(c.Database); err != nil {
		add("database: %w", err)
	}

	if host, _, err := net.SplitHostPort(c.UI.Listen); err != nil {
		add("ui.listen: %w", err)
	} else if !isLoopback(host) {
		// The UI has no TLS of its own; put HTTPS in front with a local
		// proxy such as `tailscale serve` or Caddy.
		add("ui.listen: must be a loopback address (e.g. 127.0.0.1:8080) behind a local HTTPS proxy")
	}
	if u, err := url.Parse(c.UI.BaseURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "" && u.Path != "/" {
		add("ui.base_url: must be an absolute http(s) URL with no path")
	} else if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		// Session cookies would cross the network unencrypted.
		add("ui.base_url: plain http is only allowed for loopback; use https (e.g. Caddy or `tailscale cert`)")
	}
	if c.UI.SessionIdle.Duration > c.UI.SessionMax.Duration {
		add("ui.session_idle must not exceed ui.session_max")
	}

	if !c.Auth.LocalLogin && !c.Auth.Entra.Enabled {
		add("auth: local_login is disabled and entra is not enabled; nobody could log in")
	}
	if e := c.Auth.Entra; e.Enabled {
		if e.Tenant == "" {
			add("auth.entra.tenant is required")
		}
		if e.ClientID == "" {
			add("auth.entra.client_id is required")
		}
		if len(e.AllowedTenants) == 0 {
			add("auth.entra.allowed_tenants must list at least one tenant ID")
		}
		if slices.Contains(e.AllowedTenants, "") {
			add("auth.entra.allowed_tenants contains an empty entry")
		}
	}

	host, _, err := net.SplitHostPort(c.Ingest.Listen)
	if err != nil {
		add("ingest.listen: %w", err)
	}
	switch {
	case (c.Ingest.TLSCert == "") != (c.Ingest.TLSKey == ""):
		add("ingest: tls_cert and tls_key must be set together")
	case c.Ingest.TLSCert == "" && err == nil && !isLoopback(host):
		// Without TLS, ingest must sit behind a local TLS-terminating proxy.
		add("ingest: listening on %q without TLS; set tls_cert/tls_key or bind to loopback behind a proxy", c.Ingest.Listen)
	}
	if c.Ingest.MaxBody <= 0 {
		add("ingest.max_body must be positive")
	}
	for _, cidr := range c.Ingest.AllowCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			add("ingest.allow_cidrs: %w", err)
		}
	}

	if m := c.MCP; m.Enabled {
		if host, _, err := net.SplitHostPort(m.Listen); err != nil || !isLoopback(host) {
			add("mcp.listen: must be a loopback address behind a local HTTPS proxy (e.g. tailscale serve)")
		}
		if u, err := url.Parse(m.BaseURL); err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname()))) {
			add("mcp.base_url: must be https (plain http only for loopback)")
		}
	}
	if n := c.Notify; n.Every.Duration > 0 {
		if len(n.EmailTo) == 0 && !n.Webhook {
			add("notify: every is set but neither email_to nor webhook is configured")
		}
		if len(n.EmailTo) > 0 && (n.SMTPHost == "" || n.EmailFrom == "") {
			add("notify: email needs smtp_host and email_from")
		}
		if n.SMTPPort <= 0 || n.SMTPPort > 65535 {
			add("notify.smtp_port is invalid")
		}
		if n.WebhookFormat != "slack" && n.WebhookFormat != "json" {
			add("notify.webhook_format must be slack or json")
		}
		if n.Every.Duration < time.Hour {
			add("notify.every must be at least 1h")
		}
	}
	return errors.Join(errs...)
}

// ValidateDatabasePath rejects paths the SQLite driver would misparse.
func ValidateDatabasePath(p string) error {
	switch {
	case p == "":
		return errors.New("path is required")
	case strings.ContainsAny(p, "?#"):
		return errors.New("path must not contain '?' or '#'")
	case strings.ContainsFunc(p, unicode.IsControl):
		return errors.New("path must not contain control characters")
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

//go:embed default.toml
var defaultTemplate string

// Template returns the commented config file written by `heimdall init`.
func Template(database string) []byte { return TemplateWith(Setup{Database: database}) }

// Setup holds the choices `heimdall init` (and the hub installer) can make
// up front. Empty fields keep the template's defaults.
type Setup struct {
	Database        string
	UIBaseURL       string // e.g. https://hub.tailnet.ts.net
	IngestPublicURL string // what servers use, e.g. https://ingest.example.com
	BehindProxy     bool   // ingest sits behind a local proxy (Caddy or tailscale serve)
	MCPBaseURL      string // non-empty enables MCP with this origin
}

// TemplateWith renders the commented default config with s applied.
func TemplateWith(s Setup) []byte {
	t := defaultTemplate
	set := func(old, new string) {
		if !strings.Contains(t, old) {
			panic("config template is missing " + old) // caught by tests
		}
		t = strings.Replace(t, old, new, 1)
	}
	if s.Database != "" {
		set(`database = "heimdall.db"`, `database = `+strconv.Quote(s.Database))
	}
	if s.UIBaseURL != "" {
		set(`base_url     = "http://127.0.0.1:8080"`, `base_url     = `+strconv.Quote(s.UIBaseURL))
	}
	if s.IngestPublicURL != "" {
		set(`# public_url  = "https://ingest.example.com"`, `public_url    = `+strconv.Quote(s.IngestPublicURL))
	}
	if s.BehindProxy {
		set(`behind_proxy  = false`, `behind_proxy  = true`)
	}
	if s.MCPBaseURL != "" {
		set("enabled  = false\nlisten   = \"127.0.0.1:8090\"\nbase_url = \"http://127.0.0.1:8090\"",
			"enabled  = true\nlisten   = \"127.0.0.1:8090\"\nbase_url = "+strconv.Quote(s.MCPBaseURL))
	}
	return []byte(t)
}

// Duration is a time.Duration written as a string such as "30m".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(b []byte) error {
	if string(b) == "0" || string(b) == "" { // explicitly off (e.g. notify.every)
		d.Duration = 0
		return nil
	}
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	if v <= 0 {
		return fmt.Errorf("duration %q must be positive", b)
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// ByteSize is a size written as "5MB", "512KB" or a plain byte count.
// Units are binary (1KB = 1024 bytes).
type ByteSize int64

func (s *ByteSize) UnmarshalText(b []byte) error {
	str := strings.ToUpper(strings.TrimSpace(string(b)))
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(str, u.suffix) {
			str, mult = strings.TrimSpace(strings.TrimSuffix(str, u.suffix)), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(str, 10, 64)
	if err != nil || n <= 0 || n > (1<<40)/mult {
		return fmt.Errorf("invalid size %q", b)
	}
	*s = ByteSize(n * mult)
	return nil
}

// Rate is a limit written as "10/h": N events per s, m, h or d.
type Rate struct {
	N   int
	Per time.Duration
}

func (r *Rate) UnmarshalText(b []byte) error {
	n, unit, ok := strings.Cut(string(b), "/")
	per := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[unit]
	count, err := strconv.Atoi(n)
	if !ok || per == 0 || err != nil || count <= 0 {
		return fmt.Errorf("invalid rate %q (want e.g. \"10/h\")", b)
	}
	*r = Rate{N: count, Per: per}
	return nil
}
