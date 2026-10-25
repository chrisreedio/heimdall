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
	"regexp"
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
	News     News    `toml:"news"`
	AI       AI      `toml:"ai"`
	// Agents are coding agents (Discord bots) that "Hand off to agent"
	// can ask for a pull request. None by default, which hides the button.
	Agents []Agent `toml:"agents"`

	DeployServices DeployServices `toml:"deploy_services"` // services.go
}

// Agent is one coding agent: a Discord bot that reads a channel and can
// open pull requests. Heimdall posts a fix request to the channel's
// webhook and @mentions only this bot. The webhook URL is a credential,
// stored with `heimdall notify set-webhook discord <name>`, never here.
type Agent struct {
	Name          string `toml:"name"`            // shown in the confirm step, e.g. "pr-bot"
	DiscordUserID string `toml:"discord_user_id"` // the bot's user ID (17-20 digits)
	Destination   string `toml:"destination"`     // "discord:<name>", a stored webhook
}

var (
	agentNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	discordIDRe = regexp.MustCompile(`^[0-9]{17,20}$`)
)

// MaxAgents caps [[agents]].
const MaxAgents = 10

// AgentUsesDestination reports whether an agent posts to spec
// ("discord:agents"), so `notify set-webhook` keeps it out of alerts.
func (c Config) AgentUsesDestination(spec string) bool {
	for _, a := range c.Agents {
		if a.Destination == spec {
			return true
		}
	}
	return false
}

func validateAgents(agents []Agent, add func(string, ...any)) {
	if len(agents) > MaxAgents {
		add("agents: at most %d", MaxAgents)
	}
	seen := map[string]bool{}
	for i, a := range agents {
		if !agentNameRe.MatchString(a.Name) {
			add("agents[%d].name: must be 1-32 lowercase letters, digits or '-', e.g. \"pr-bot\"", i)
		} else if seen[a.Name] {
			add("agents[%d].name: %q is listed twice", i, a.Name)
		}
		seen[a.Name] = true
		if !discordIDRe.MatchString(a.DiscordUserID) {
			add("agents[%d].discord_user_id: must be the bot's Discord user ID, 17-20 digits", i)
		}
		if kind, _, ok := NotifyDestination(a.Destination); !ok || kind != "discord" {
			add("agents[%d].destination: must be discord:<name>, a webhook stored with `heimdall notify set-webhook discord <name>`", i)
		}
	}
}

// AI configures optional server-side analysis with the operator's own
// Azure AI Foundry / Azure OpenAI deployment: a daily fleet brief and an
// on-demand "explain this host". Off by default. The API key is never in
// this file: it's the systemd credential "heimdall-ai" (heimdall ai set-key).
type AI struct {
	Enabled bool `toml:"enabled"`
	// Endpoint is the resource's https base URL, e.g.
	// https://myres.openai.azure.com or https://myres.services.ai.azure.com,
	// optionally ending in /openai/v1.
	Endpoint string `toml:"endpoint"`
	// Deployment is the model deployment's name (sent as "model"). Opaque:
	// Heimdall assumes nothing about which model it is.
	Deployment string `toml:"deployment"`
	// API is "responses" (the default) or "chat" (Chat Completions).
	API string `toml:"api"`
	// ReasoningEffort is sent only when set (none, minimal, low, medium,
	// high, xhigh, max); which values work depends on the model.
	ReasoningEffort string   `toml:"reasoning_effort"`
	BriefEvery      Duration `toml:"brief_every"`       // scheduled fleet brief; 0 = on demand only
	MaxOutputTokens int      `toml:"max_output_tokens"` // includes reasoning tokens
	MaxInputTokens  int      `toml:"max_input_tokens"`  // per run, estimated at 4 bytes a token
	Timeout         Duration `toml:"timeout"`           // per request
}

// AI API styles.
const (
	AIResponses = "responses"
	AIChat      = "chat"
)

// Host returns the endpoint's hostname, the AI client's only allowed
// outbound destination.
func (a AI) Host() string {
	if u, err := url.Parse(a.Endpoint); err == nil {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

// devBuild is set by dev.go (go build -tags dev). It allows a plain-http
// loopback ai.endpoint, for a local fake model server. Release builds
// never contain that file.
var devBuild = false

var (
	aiDeploymentRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$`)
	aiEfforts      = []string{"", "none", "minimal", "low", "medium", "high", "xhigh", "max"}
)

func (a AI) validate(add func(string, ...any)) {
	if !a.Enabled {
		return
	}
	if err := validateAIEndpoint(a.Endpoint); err != nil {
		add("ai.endpoint: %w", err)
	}
	if !aiDeploymentRe.MatchString(a.Deployment) {
		add("ai.deployment: set it to your model deployment's name (letters, digits, '.', '_', '-', spaces)")
	}
	if a.API != AIResponses && a.API != AIChat {
		add("ai.api must be %q or %q", AIResponses, AIChat)
	}
	if !slices.Contains(aiEfforts, a.ReasoningEffort) {
		add("ai.reasoning_effort must be empty or one of none, minimal, low, medium, high, xhigh, max")
	}
	if a.BriefEvery.Duration != 0 && a.BriefEvery.Duration < time.Hour {
		add("ai.brief_every must be at least 1h (or \"0\" for on demand only)")
	}
	if a.MaxOutputTokens < 256 || a.MaxOutputTokens > 128000 {
		add("ai.max_output_tokens must be between 256 and 128000")
	}
	if a.MaxInputTokens < 1000 || a.MaxInputTokens > 200000 {
		add("ai.max_input_tokens must be between 1000 and 200000")
	}
	if a.Timeout.Duration < 5*time.Second || a.Timeout.Duration > 10*time.Minute {
		add("ai.timeout must be between 5s and 10m")
	}
}

// validateAIEndpoint accepts an https base URL with no credentials, query
// or fragment, and a path of "" or /openai/v1.
func validateAIEndpoint(s string) error {
	u, err := url.Parse(s)
	switch {
	case s == "":
		return errors.New("is required, e.g. https://myres.openai.azure.com")
	case err != nil || len(s) > 512 || strings.ContainsFunc(s, unicode.IsControl):
		return errors.New("is not a valid URL")
	case u.Scheme == "http" && devBuild && isLoopback(u.Hostname()):
		// dev builds only: a local fake model server
	case u.Scheme != "https":
		return errors.New("must be an https URL")
	}
	switch p := strings.TrimSuffix(u.Path, "/"); {
	case u.Hostname() == "" || u.Opaque != "":
		return errors.New("must name a host")
	case u.User != nil:
		return errors.New("must not contain credentials (the key is stored with `sudo heimdall ai set-key`)")
	case u.RawQuery != "" || u.Fragment != "" || u.ForceQuery:
		return errors.New("must not have a query or fragment")
	case p != "" && p != "/openai/v1" && p != "/openai":
		return errors.New("must be the resource's base URL (optionally ending in /openai/v1)")
	}
	return nil
}

// News configures threat news: curated incident feeds cross-referenced
// with findings on the hub. Off by default, like every outbound call a
// hub owner hasn't turned on.
type News struct {
	Enabled  bool     `toml:"enabled"`
	Sources  []string `toml:"sources"` // https URLs of incident feeds (pwn.watch's incidents.json shape)
	Interval Duration `toml:"interval"`
}

// DefaultNewsSource is pwn.watch's full incident list.
const DefaultNewsSource = "https://pwn.watch/incidents.json"

// MaxNewsSources caps [news] sources.
const MaxNewsSources = 10

// Hosts returns the hostnames of the configured news sources, which
// become the news fetcher's outbound allowlist.
func (n News) Hosts() []string {
	var out []string
	for _, src := range n.Sources {
		if u, err := url.Parse(src); err == nil && u.Hostname() != "" {
			if h := strings.ToLower(u.Hostname()); !slices.Contains(out, h) {
				out = append(out, h)
			}
		}
	}
	return out
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
	// Destinations are chat and webhook destinations, "slack:<name>",
	// "discord:<name>" or "webhook:<name>" (JSON). Their URLs are
	// credentials, stored by `heimdall notify set-webhook`, never here.
	Destinations []string `toml:"destinations"`
	// AlertAnomalies sends high-signal anomalies (watches disabled,
	// privileged access outside a window, high severity) right away.
	AlertAnomalies bool `toml:"alert_anomalies"`
}

var notifyDestRe = regexp.MustCompile(`^(slack|discord|webhook):([a-z0-9][a-z0-9-]{0,31})$`)

// NotifyDestination splits "slack:ops" into its kind and name.
func NotifyDestination(s string) (kind, name string, ok bool) {
	m := notifyDestRe.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
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
	// AlertAfter: a host quiet for this long raises a silence anomaly and an
	// immediate notification (once per silence). 0 disables it.
	AlertAfter Duration `toml:"alert_after"`
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
			RatePerHost: Rate{N: 30, Per: time.Hour}, // hourly reports plus event-driven ones
		},
		Feeds: Feeds{
			SyncInterval: Duration{6 * time.Hour},
			OSV:          true,
			KEV:          true,
			EPSS:         true,
			EndOfLife:    true,
		},
		Hosts:   Hosts{StaleAfter: Duration{72 * time.Hour}, AlertAfter: Duration{3 * time.Hour}, KeepFor: Duration{180 * 24 * time.Hour}, KeepMin: 30},
		Notify:  Notify{SMTPPort: 587, WebhookFormat: "slack", AlertAnomalies: true},
		MCP:     MCP{Listen: "127.0.0.1:8090", BaseURL: "http://127.0.0.1:8090"},
		Updates: Updates{Check: true},
		News:    News{Sources: []string{DefaultNewsSource}, Interval: Duration{time.Hour}},
		AI: AI{API: AIResponses, BriefEvery: Duration{24 * time.Hour}, MaxOutputTokens: 8000,
			MaxInputTokens: 24000, Timeout: Duration{2 * time.Minute}},
		DeployServices: DefaultDeployServices(),
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
	for i, d := range c.Notify.Destinations {
		if _, _, ok := NotifyDestination(d); !ok {
			add("notify.destinations: %q must be slack:<name>, discord:<name> or webhook:<name> (name: a-z, 0-9, -)", d)
		} else if slices.Contains(c.Notify.Destinations[:i], d) {
			add("notify.destinations: %q is listed twice", d)
		}
	}
	if n := c.Notify; n.Every.Duration > 0 {
		if len(n.EmailTo) == 0 && !n.Webhook && len(n.Destinations) == 0 {
			add("notify: every is set but no destination is configured (email_to, webhook or destinations)")
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
	if n := c.News; n.Enabled {
		if len(n.Sources) == 0 {
			add("news: enabled but sources is empty")
		}
		if len(n.Sources) > MaxNewsSources {
			add("news.sources: at most %d sources", MaxNewsSources)
		}
		if n.Interval.Duration < time.Hour {
			// Be polite to feeds run by volunteers.
			add("news.interval must be at least 1h")
		}
	}
	for _, src := range c.News.Sources {
		if err := validateNewsSource(src); err != nil {
			add("news.sources: %q %w", src, err)
		}
	}
	c.AI.validate(add)
	validateAgents(c.Agents, add)
	c.DeployServices.validate(add)
	return errors.Join(errs...)
}

// validateNewsSource accepts only a plain https URL: no credentials, no
// fragment, and a hostname to put on the allowlist.
func validateNewsSource(src string) error {
	u, err := url.Parse(src)
	switch {
	case err != nil || len(src) > 2048 || strings.ContainsFunc(src, unicode.IsControl):
		return errors.New("is not a valid URL")
	case u.Scheme != "https":
		return errors.New("must be an https URL")
	case u.Hostname() == "" || u.Opaque != "":
		return errors.New("must name a host")
	case u.User != nil:
		return errors.New("must not contain credentials")
	case u.Fragment != "":
		return errors.New("must not contain a fragment")
	}
	return nil
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
