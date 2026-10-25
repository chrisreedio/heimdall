// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// DeployServices says which deploy and server-management services'
// published source addresses the hub keeps, so a privilege watch session
// from Laravel Forge reads as automation, not an unknown address. Only the
// vendors' public lists are fetched; nothing is sent. See
// docs/deploy-services.md.
type DeployServices struct {
	// Services are catalog IDs (internal/ipinfo/services). Forge and Ploi
	// by default; the rest are opt-in.
	Services []string `toml:"services"`
	// Custom are your own tools: fixed ranges and/or a list URL, plus the
	// account names they log in as.
	Custom []CustomService `toml:"custom"`
}

// CustomService is a deploy tool of your own.
type CustomService struct {
	Name  string   `toml:"name"`  // shown on sessions, e.g. "Acme Deploy"
	CIDRs []string `toml:"cidrs"` // addresses or ranges it connects from
	URL   string   `toml:"url"`   // optional https list (one address or CIDR a line, or a JSON array)
	Users []string `toml:"users"` // accounts it logs in as, e.g. "deploy"
}

// DeployServiceIDs is the service catalog's IDs, for validation (the
// catalog lives in internal/ipinfo/services; a test keeps the two in step).
var DeployServiceIDs = []string{"forge", "ploi", "envoyer", "deployhq", "buddy", "buddy-eu", "buddy-asia", "github-actions"}

// MaxCustomServices caps [[deploy_services.custom]].
const MaxCustomServices = 20

// DefaultDeployServices is what's on with no [deploy_services] section.
func DefaultDeployServices() DeployServices {
	return DeployServices{Services: []string{"forge", "ploi"}}
}

// ID is the custom service's source ID: its name in lowercase with runs of
// anything but letters and digits as '-' (labels' source is "service:<ID>").
func (c CustomService) ID() string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(c.Name)) {
		if r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r)
			dash = false
		} else {
			dash = true
		}
	}
	return "custom-" + b.String()
}

// unixUserRe is a portable login name (useradd's default rule, plus '.').
var unixUserRe = regexp.MustCompile(`^[a-z_][a-z0-9._-]{0,31}$`)

func (d DeployServices) validate(add func(string, ...any)) {
	for i, id := range d.Services {
		if !slices.Contains(DeployServiceIDs, id) {
			add("deploy_services.services: %q isn't a known service (one of %s)", id, strings.Join(DeployServiceIDs, ", "))
		} else if slices.Contains(d.Services[:i], id) {
			add("deploy_services.services: %q is listed twice", id)
		}
	}
	if len(d.Custom) > MaxCustomServices {
		add("deploy_services.custom: at most %d", MaxCustomServices)
	}
	seen := map[string]bool{}
	for i, c := range d.Custom {
		name := strings.TrimSpace(c.Name)
		switch {
		case name == "" || len(name) > 100 || c.ID() == "custom-":
			add("deploy_services.custom[%d].name: 1-100 characters, with at least one letter or digit", i)
		case seen[c.ID()]:
			add("deploy_services.custom[%d].name: %q is listed twice", i, name)
		}
		seen[c.ID()] = true
		if len(c.CIDRs) == 0 && c.URL == "" {
			add("deploy_services.custom[%d]: set cidrs, url or both", i)
		}
		if len(c.CIDRs) > 1000 {
			add("deploy_services.custom[%d].cidrs: at most 1000", i)
		}
		for _, s := range c.CIDRs {
			if err := checkServicePrefix(s); err != "" {
				add("deploy_services.custom[%d].cidrs: %q %s", i, s, err)
			}
		}
		if c.URL != "" {
			if err := validateNewsSource(c.URL); err != nil {
				add("deploy_services.custom[%d].url: %w", i, err)
			}
		}
		for _, u := range c.Users {
			if !unixUserRe.MatchString(u) {
				add("deploy_services.custom[%d].users: %q isn't a login name", i, u)
			}
		}
	}
}

// checkServicePrefix accepts an address or a CIDR no broader than /8
// (IPv4) or /16 (IPv6); "" means it's fine.
func checkServicePrefix(s string) string {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		if _, err := netip.ParseAddr(s); err != nil {
			return "isn't an IP address or CIDR range"
		}
		return ""
	}
	p, err := netip.ParsePrefix(s)
	switch {
	case err != nil:
		return "isn't an IP address or CIDR range"
	case p.Addr().Unmap().Is4() && p.Bits() < 8, !p.Addr().Is4() && p.Bits() < 16:
		return "is too broad for a deploy service"
	}
	return ""
}

// HostOf returns rawURL's lowercase hostname ("" if it doesn't parse), for
// the fetch allowlist.
func HostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// deployServicesTemplate is the [deploy_services] section of the config
// template, appended to default.toml (kept here, with the section's code).
const deployServicesTemplate = `
[deploy_services]
# Deploy services you use, so a privilege watch session from one (e.g.
# Laravel Forge deploying over SSH) shows as automation, not an unknown
# address. The hub fetches each service's PUBLIC address list daily
# (nothing is sent) and knows its usual account ("forge", "ploi").
# Catalog: forge, ploi, envoyer, deployhq, buddy, buddy-eu, buddy-asia,
# github-actions (very large; Azure ranges shared with others).
# Ploi shows its deploy addresses only to customers: run
# ` + "`sudo heimdall ip-services set-key ploi`" + ` to fetch them, or list them
# as a custom service. See docs/deploy-services.md.
services = ["forge", "ploi"]
# Your own deploy tool (repeat per tool):
# [[deploy_services.custom]]
# name  = "Acme Deploy"
# cidrs = ["203.0.113.10", "198.51.100.0/28"]
# url   = ""                     # optional https list, one address or CIDR a line
# users = ["deploy"]             # accounts it logs in as
`

func init() {
	defaultTemplate = strings.TrimRight(defaultTemplate, "\n") + "\n" + deployServicesTemplate
}
