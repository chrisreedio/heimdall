// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Cloudflare reads your Cloudflare zones with a read-only API token:
// DNS records (to spot exposed origins and dangling records), security
// event counts, and Radar's ASN for unknown addresses. Off by default.
// When on, Cloudflare's published edge ranges are also fetched (no token
// needed), so ingest behind Cloudflare logs the real client address. The
// token is never in this file: it's the systemd credential
// "heimdall-cloudflare" (heimdall cloudflare set-token). See docs/cloudflare.md.
type Cloudflare struct {
	Enabled bool `toml:"enabled"`
	// Zones limits the sync to these zones (names or zone IDs); empty is
	// every zone the token can read.
	Zones          []string `toml:"zones"`
	SyncEvery      Duration `toml:"sync_every"`
	SecurityEvents bool     `toml:"security_events"` // daily security event counts per zone
	Radar          bool     `toml:"radar"`           // ASN lookups for unknown addresses
	// ConnectingIP: behind ingest.behind_proxy, when the proxy's peer is a
	// Cloudflare edge address, take the client from CF-Connecting-IP.
	ConnectingIP bool `toml:"connecting_ip"`
	// ProbeDangling: check whether anything answers at dangling records'
	// addresses, with a plain TCP connect from the hub to 443 and 80.
	ProbeDangling bool `toml:"probe_dangling"`
	// APIBase is the API's base URL; only tests change it.
	APIBase string `toml:"api_base"`
}

// CloudflareAPI is the Cloudflare API's base URL.
const CloudflareAPI = "https://api.cloudflare.com/client/v4"

// CloudflareDefaults are [cloudflare]'s defaults (off).
var CloudflareDefaults = Cloudflare{SyncEvery: Duration{time.Hour}, SecurityEvents: true, Radar: true,
	ConnectingIP: true, ProbeDangling: true, APIBase: CloudflareAPI}

// MaxCloudflareZones caps [cloudflare] zones.
const MaxCloudflareZones = 200

// Host returns the API's hostname, the client's only allowed destination
// besides www.cloudflare.com (the edge ranges).
func (c Cloudflare) Host() string {
	if u, err := url.Parse(c.APIBase); err == nil {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

var cfZoneRe = regexp.MustCompile(`^([0-9a-f]{32}|[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+)$`)

func (c Cloudflare) validate(add func(string, ...any)) {
	if len(c.Zones) > MaxCloudflareZones {
		add("cloudflare.zones: at most %d", MaxCloudflareZones)
	}
	for _, z := range c.Zones {
		if !cfZoneRe.MatchString(z) {
			add("cloudflare.zones: %q must be a zone name (example.com, lowercase) or a 32-character zone ID", z)
		}
	}
	if c.SyncEvery.Duration < 15*time.Minute || c.SyncEvery.Duration > 7*24*time.Hour {
		add("cloudflare.sync_every must be between 15m and 168h")
	}
	u, err := url.Parse(c.APIBase)
	switch {
	case err != nil || strings.ContainsFunc(c.APIBase, unicode.IsControl):
		add("cloudflare.api_base is not a valid URL")
	case u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "":
		add("cloudflare.api_base: %w", errors.New("must be a plain https URL"))
	}
}

// cloudflareTemplate is [cloudflare] in the commented default config (and
// what `heimdall config update` appends).
const cloudflareTemplate = `
[cloudflare]
# Read your Cloudflare zones with a read-only API token: DNS records (origin
# addresses exposed by grey-cloud records, dangling records, sites not
# behind Cloudflare), daily security event counts, and Radar's network
# name for unknown addresses. Also fetches Cloudflare's published edge
# ranges (no token), so ingest behind Cloudflare sees the real client.
# The token is never in this file: run ` + "`sudo heimdall cloudflare set-token`" + `,
# then ` + "`heimdall cloudflare status`" + `. See docs/cloudflare.md.
enabled         = false
zones           = []       # zone names or IDs; empty = every zone the token can read
sync_every      = "1h"
security_events = true     # counts by action, country, network and path (no client IPs)
radar           = true     # look up the network (ASN) of addresses nobody knows
connecting_ip   = true     # trust CF-Connecting-IP only from Cloudflare's edge (behind_proxy)
probe_dangling  = true     # TCP connect (443, 80; nothing sent) to dangling records' addresses: does anything answer?
`

func init() { defaultTemplate += cloudflareTemplate }
