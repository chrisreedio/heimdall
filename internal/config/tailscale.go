// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"regexp"
	"time"
)

// Tailscale configures the read-only sync with the Tailscale API, which
// names the person and device behind each tailnet address. The credential
// (an OAuth client or an API access token) is never in this file: it's
// stored with `heimdall tailscale set-key` and loaded as a systemd
// credential.
type Tailscale struct {
	Enabled bool `toml:"enabled"`
	// Tailnet is the tailnet's ID or name; "-" (the default) is the
	// credential's own tailnet.
	Tailnet   string   `toml:"tailnet"`
	SyncEvery Duration `toml:"sync_every"`
}

// defaultTailscale is [tailscale] when the file leaves keys out.
var defaultTailscale = Tailscale{Tailnet: "-", SyncEvery: Duration{15 * time.Minute}}

// A tailnet ID (e.g. T1234CNTRL), an organization domain (example.com), a
// tailnet DNS name (tail1234.ts.net) or a login email (alice@example.com).
var tailnetRe = regexp.MustCompile(`^(-|[A-Za-z0-9][A-Za-z0-9._@+-]{0,253})$`)

func (t Tailscale) validate(add func(string, ...any)) {
	if !tailnetRe.MatchString(t.Tailnet) {
		add(`tailscale.tailnet must be "-" (the credential's tailnet) or the tailnet's ID or name`)
	}
	if t.SyncEvery.Duration < time.Minute || t.SyncEvery.Duration > 24*time.Hour {
		add("tailscale.sync_every must be between 1m and 24h")
	}
}
