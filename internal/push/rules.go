// SPDX-License-Identifier: AGPL-3.0-or-later

package push

import (
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// Event kinds a user can choose for. Each has a default mode.
const (
	KindKEV       = "kev"       // a known-exploited finding newly appears on a host
	KindNews      = "news"      // threat news newly matches a host
	KindAnomaly   = "anomaly"   // a high-signal anomaly (notify.AlertRule)
	KindPrivilege = "privilege" // privileged access from an unknown address
	KindBan       = "ban"       // a ban proposal waiting for approval (operators)
	KindSilent    = "silent"    // a host stopped reporting
	KindFleet     = "fleet"     // the digest's counts: security updates, end of life, collectors behind
)

// Kinds are every kind, in the order the settings page lists them.
var Kinds = []string{KindKEV, KindNews, KindAnomaly, KindPrivilege, KindBan, KindSilent, KindFleet}

// Modes.
const (
	Immediate = "immediate"
	Digest    = "digest"
	Off       = "off"
)

// defaults are each kind's mode until the user picks one.
var defaults = map[string]string{
	KindKEV: Immediate, KindNews: Immediate, KindAnomaly: Immediate, KindPrivilege: Immediate,
	KindBan: Immediate, KindSilent: Immediate, KindFleet: Digest,
}

// DefaultMode is a kind's mode until the user picks one.
func DefaultMode(kind string) string { return defaults[kind] }

// ModesFor lists the modes a kind can have: the fleet counts exist only
// as a digest.
func ModesFor(kind string) []string {
	if kind == KindFleet {
		return []string{Digest, Off}
	}
	return []string{Immediate, Digest, Off}
}

// ValidMode reports whether a kind can have a mode.
func ValidMode(kind, mode string) bool {
	for _, m := range ModesFor(kind) {
		if m == mode {
			return true
		}
	}
	return false
}

// ModeOf is a user's mode for a kind.
func ModeOf(p store.PushSettings, kind string) string {
	if m, ok := p.Modes[kind]; ok && ValidMode(kind, m) {
		return m
	}
	return defaults[kind]
}

// bypassQuiet are the kinds that don't wait for quiet hours to end: a
// known-exploited hole and someone privileged on a host from nowhere
// known are worth waking up for.
var bypassQuiet = map[string]bool{KindKEV: true, KindPrivilege: true}

// Location is a user's time zone (UTC when unset or unknown).
func Location(p store.PushSettings) *time.Location {
	if p.TimeZone == "" {
		return time.UTC
	}
	loc, err := time.LoadLocation(p.TimeZone)
	if err != nil {
		return time.UTC
	}
	return loc
}

// ValidTimeZone reports whether name is an IANA time zone the hub knows.
func ValidTimeZone(name string) bool {
	if name == "" || len(name) > 64 || name == "Local" {
		return false
	}
	_, err := time.LoadLocation(name)
	return err == nil
}

// InQuiet reports whether now falls in the user's quiet hours, which run
// from QuietStart to QuietEnd on the user's wall clock (across midnight
// when the end is earlier). Equal hours mean none.
func InQuiet(p store.PushSettings, now time.Time) bool {
	if !p.Quiet || p.QuietStart == p.QuietEnd {
		return false
	}
	h := now.In(Location(p)).Hour()
	if p.QuietStart < p.QuietEnd {
		return h >= p.QuietStart && h < p.QuietEnd
	}
	return h >= p.QuietStart || h < p.QuietEnd
}

// Decision is what happens to an event for one user.
type Decision int

const (
	Drop     Decision = iota // the user turned the kind off
	Send                     // now
	Hold                     // until quiet hours end
	ToDigest                 // in the next daily digest
)

// Decide applies a user's settings to an event of a kind at now.
func Decide(p store.PushSettings, kind string, now time.Time) Decision {
	switch ModeOf(p, kind) {
	case Off:
		return Drop
	case Digest:
		return ToDigest
	}
	if InQuiet(p, now) && !bypassQuiet[kind] {
		return Hold
	}
	return Send
}

// digestHour is when the daily digest goes, on the user's wall clock;
// lastDigestHour is the latest it still goes that day, for a hub that
// was down at 8 or a user whose quiet hours run past it.
const (
	digestHour     = 8
	lastDigestHour = 20
)

// DigestDue reports whether a user's daily digest should go now, and the
// local date to record it under.
func DigestDue(p store.PushSettings, now time.Time) (bool, string) {
	local := now.In(Location(p))
	day := local.Format("2006-01-02")
	if p.DigestDay == day || local.Hour() < digestHour || local.Hour() > lastDigestHour || InQuiet(p, now) {
		return false, day
	}
	return true, day
}
