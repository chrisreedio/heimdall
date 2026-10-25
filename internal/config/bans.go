// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"regexp"
	"time"
)

// Bans turns repeat offenders (failed SSH logins across the fleet) into
// Cloudflare bans: an account-level IP list that a custom rule in each
// opted-in zone challenges or blocks. Off by default. In shadow mode it
// only records what it would have done, so the weights can be calibrated
// on real data first. Writes need a second, separate token, never in this
// file: the systemd credential "heimdall-cloudflare-bans" (heimdall bans
// set-token). See docs/bans.md.
type Bans struct {
	// Mode: off, shadow (record only), propose (an operator approves each
	// ban) or auto (ban within the caps; over them, propose).
	Mode string `toml:"mode"`
	// AccountID is the Cloudflare account that holds the lists; empty: the
	// only account the write token can see.
	AccountID string   `toml:"account_id"`
	Every     Duration `toml:"every"`  // how often candidates are scored
	Window    Duration `toml:"window"` // how far back failures count
	// ProposeAt is the score at which a candidate is proposed (or, in
	// shadow mode, recorded).
	ProposeAt   float64 `toml:"propose_at"`
	MinFailures int     `toml:"min_failures"` // fewer never scores (unless it then succeeded)
	// Block instead of the default challenge: an address that hit at least
	// BlockHosts hosts, or (BlockSucceeded) failed and then logged in.
	BlockHosts     int  `toml:"block_hosts"`
	BlockSucceeded bool `toml:"block_succeeded"`
	// Duration is a first ban's length; each repeat doubles it, up to
	// MaxDuration.
	Duration    Duration `toml:"duration"`
	MaxDuration Duration `toml:"max_duration"`
	MaxPerHour  int      `toml:"max_per_hour"` // new bans written per hour
	MaxActive   int      `toml:"max_active"`   // bans in the lists at once
	ProposalTTL Duration `toml:"proposal_ttl"` // an undecided proposal lapses after this
	// Networks: propose a /24 (IPv4) or /48 (IPv6) when many addresses in
	// it each stay under the threshold. Never one that holds an address
	// IP awareness vouches for.
	Networks         bool       `toml:"networks"`
	NetworkAddresses int        `toml:"network_addresses"` // offending addresses a network needs
	ShadowDigest     bool       `toml:"shadow_digest"`     // shadow mode: a daily "would have banned" message
	ChallengeList    string     `toml:"challenge_list"`
	BlockList        string     `toml:"block_list"`
	Weights          BanWeights `toml:"weights"`
}

// BanWeights are the score's parts (docs/bans.md#scoring).
type BanWeights struct {
	Hosts     float64 `toml:"hosts"`     // per host it failed on (up to 10)
	Failures  float64 `toml:"failures"`  // × log2(1 + failures)
	Usernames float64 `toml:"usernames"` // per distinct username (up to 20)
	Succeeded float64 `toml:"succeeded"` // failed, then logged in
	Days      float64 `toml:"days"`      // per extra day it came back (up to 7)
	ASN       float64 `toml:"asn"`       // per other offender in its network (ASN, up to 10)
	Network   float64 `toml:"network"`   // a network's score: × the sum of its addresses' scores
}

// Ban modes.
const (
	BansOff     = "off"
	BansShadow  = "shadow"
	BansPropose = "propose"
	BansAuto    = "auto"
)

// BansDefaults are [bans]' defaults: off, and conservative.
var BansDefaults = Bans{Mode: BansOff, Every: Duration{10 * time.Minute}, Window: Duration{7 * 24 * time.Hour},
	ProposeAt: 12, MinFailures: 5, BlockHosts: 3, BlockSucceeded: true,
	Duration: Duration{7 * 24 * time.Hour}, MaxDuration: Duration{90 * 24 * time.Hour},
	MaxPerHour: 20, MaxActive: 1000, ProposalTTL: Duration{72 * time.Hour},
	Networks: true, NetworkAddresses: 4, ChallengeList: "heimdall_challenge", BlockList: "heimdall_block",
	Weights: BanWeights{Hosts: 2, Failures: 1, Usernames: 0.5, Succeeded: 10, Days: 1.5, ASN: 0.5, Network: 0.6}}

// On reports whether bans do anything (shadow included).
func (b Bans) On() bool { return b.Mode != "" && b.Mode != BansOff }

// Writes reports whether the mode writes to Cloudflare.
func (b Bans) Writes() bool { return b.Mode == BansPropose || b.Mode == BansAuto }

var (
	cfAccountRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// Cloudflare list names: lowercase letters, digits and underscores, at
	// most 50 characters.
	cfListRe = regexp.MustCompile(`^[a-z0-9_]{1,50}$`)
)

func (b Bans) validate(cf Cloudflare, add func(string, ...any)) {
	switch b.Mode {
	case BansOff, BansShadow:
	case BansPropose, BansAuto:
		if !cf.Enabled {
			add("bans.mode = %q needs [cloudflare] enabled (the zones come from its sync)", b.Mode)
		}
	default:
		add(`bans.mode must be "off", "shadow", "propose" or "auto"`)
	}
	if b.AccountID != "" && !cfAccountRe.MatchString(b.AccountID) {
		add("bans.account_id must be a 32-character Cloudflare account ID")
	}
	if b.Every.Duration < time.Minute || b.Every.Duration > 24*time.Hour {
		add("bans.every must be between 1m and 24h")
	}
	if b.Window.Duration < time.Hour || b.Window.Duration > 30*24*time.Hour {
		add("bans.window must be between 1h and 720h (failed logins are kept 30 days)")
	}
	if b.ProposeAt <= 0 || b.ProposeAt > 1000 {
		add("bans.propose_at must be above 0")
	}
	if b.MinFailures < 1 || b.BlockHosts < 1 || b.NetworkAddresses < 2 {
		add("bans.min_failures and block_hosts must be at least 1, network_addresses at least 2")
	}
	if b.Duration.Duration < time.Hour || b.MaxDuration.Duration < b.Duration.Duration || b.MaxDuration.Duration > 365*24*time.Hour {
		add("bans.duration must be at least 1h, and max_duration between it and 8760h")
	}
	if b.MaxPerHour < 1 || b.MaxPerHour > 1000 || b.MaxActive < 1 || b.MaxActive > 100000 {
		add("bans.max_per_hour must be 1-1000 and max_active 1-100000")
	}
	if b.ProposalTTL.Duration < time.Hour {
		add("bans.proposal_ttl must be at least 1h")
	}
	if !cfListRe.MatchString(b.ChallengeList) || !cfListRe.MatchString(b.BlockList) || b.ChallengeList == b.BlockList {
		add("bans.challenge_list and block_list must differ and be 1-50 lowercase letters, digits or _")
	}
	w := b.Weights
	for _, v := range []float64{w.Hosts, w.Failures, w.Usernames, w.Succeeded, w.Days, w.ASN, w.Network} {
		if v < 0 || v > 100 {
			add("bans.weights must be between 0 and 100")
			break
		}
	}
}

// bansTemplate is [bans] in the commented default config (and what
// `heimdall config update` appends).
const bansTemplate = `
[bans]
# Turn repeat offenders (failed SSH logins, see docs/failed-logins.md) into
# Cloudflare bans: an account-level IP list that one custom rule per
# opted-in zone challenges or blocks. Addresses IP awareness knows (staff,
# automation, infra, the tailnet, private networks, Cloudflare) are never
# banned. Modes: off; shadow (only records what it would have banned, to
# calibrate the weights below on real data); propose (an operator approves
# each ban on /bans); auto (bans within the caps). Writes use a second,
# separate token: ` + "`sudo heimdall bans set-token`" + `. See docs/bans.md.
mode           = "off"
account_id     = ""      # empty: the only account the write token sees
every          = "10m"
window         = "168h"  # how far back failures count
propose_at     = 12.0    # the score that proposes a ban
min_failures   = 5
block_hosts    = 3       # block (not challenge) an address that hit this many hosts
block_succeeded = true   # ...or that failed and then logged in
duration       = "168h"  # a first ban; repeats double it
max_duration   = "2160h"
max_per_hour   = 20
max_active     = 1000
proposal_ttl   = "72h"
networks       = true    # propose a /24 or /48 when many of its addresses each stay under the threshold
network_addresses = 4
shadow_digest  = false   # shadow mode: a daily "would have banned" message
challenge_list = "heimdall_challenge"
block_list     = "heimdall_block"

[bans.weights]
hosts     = 2.0   # per host it failed on (up to 10)
failures  = 1.0   # x log2(1 + failures)
usernames = 0.5   # per distinct username (up to 20)
succeeded = 10.0  # failed, then logged in
days      = 1.5   # per extra day it came back (up to 7)
asn       = 0.5   # per other offender in the same network (ASN, up to 10)
network   = 0.6   # a /24 or /48: x the sum of its addresses' scores
`

func init() { defaultTemplate += bansTemplate }
