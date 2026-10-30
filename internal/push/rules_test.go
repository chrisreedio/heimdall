// SPDX-License-Identifier: AGPL-3.0-or-later

package push

import (
	"testing"
	"time"
	_ "time/tzdata"

	"github.com/realmwatch/heimdall/internal/store"
)

func chicago(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestModes(t *testing.T) {
	t.Parallel()
	p := store.DefaultPushSettings
	noon := time.Date(2026, 10, 30, 17, 0, 0, 0, time.UTC)
	for _, k := range []string{KindKEV, KindNews, KindAnomaly, KindPrivilege, KindBan, KindSilent} {
		if got := Decide(p, k, noon); got != Send {
			t.Errorf("%s by default: %v, want Send", k, got)
		}
	}
	if Decide(p, KindFleet, noon) != ToDigest {
		t.Error("the fleet summary isn't a digest by default")
	}
	p.Modes = map[string]string{KindAnomaly: Off, KindSilent: Digest, KindNews: "bogus", KindFleet: Immediate}
	if Decide(p, KindAnomaly, noon) != Drop || Decide(p, KindSilent, noon) != ToDigest {
		t.Error("chosen modes not applied")
	}
	if Decide(p, KindNews, noon) != Send || Decide(p, KindFleet, noon) != ToDigest {
		t.Error("an invalid choice should fall back to the default")
	}
	if ValidMode(KindFleet, Immediate) || !ValidMode(KindKEV, Digest) {
		t.Error("ValidMode")
	}
}

// Quiet hours run on the user's wall clock, across midnight, and hold
// everything but known-exploited findings and unknown-address privilege.
func TestQuietHours(t *testing.T) {
	t.Parallel()
	loc := chicago(t)
	p := store.DefaultPushSettings // 10 PM to 7 AM
	p.TimeZone = "America/Chicago"
	at := func(y int, m time.Month, d, h, min int) time.Time { return time.Date(y, m, d, h, min, 0, 0, loc) }
	cases := []struct {
		t     time.Time
		quiet bool
	}{
		{at(2026, 10, 30, 21, 59), false},
		{at(2026, 10, 30, 22, 0), true},
		{at(2026, 10, 31, 3, 0), true},
		{at(2026, 10, 31, 6, 59), true},
		{at(2026, 10, 31, 7, 0), false},
		{at(2026, 10, 31, 12, 0), false},
		// DST ends Nov 1, 2026 at 2 AM (CDT to CST); 7 AM is still the end.
		{at(2026, 11, 1, 1, 30), true},
		{at(2026, 11, 1, 6, 30), true},
		{at(2026, 11, 1, 7, 30), false},
		// DST starts Mar 8, 2026 at 2 AM (CST to CDT).
		{at(2026, 3, 8, 6, 30), true},
		{at(2026, 3, 8, 7, 1), false},
	}
	for _, c := range cases {
		if got := InQuiet(p, c.t.UTC()); got != c.quiet {
			t.Errorf("%s: quiet %v, want %v", c.t, got, c.quiet)
		}
	}
	// The same instant is noon for a UTC user: not quiet.
	night := at(2026, 10, 30, 23, 0).UTC()
	utc := store.DefaultPushSettings
	if InQuiet(utc, at(2026, 10, 30, 7, 0).UTC()) { // 12:00 UTC
		t.Error("UTC user quiet at noon")
	}
	if Decide(p, KindAnomaly, night) != Hold || Decide(p, KindBan, night) != Hold || Decide(p, KindSilent, night) != Hold {
		t.Error("quiet hours don't hold")
	}
	if Decide(p, KindKEV, night) != Send || Decide(p, KindPrivilege, night) != Send {
		t.Error("known-exploited and unknown-address privilege should bypass quiet hours")
	}
	// Off, and equal hours, mean no quiet hours.
	p.Quiet = false
	if InQuiet(p, night) {
		t.Error("quiet hours off, still quiet")
	}
	p.Quiet, p.QuietStart, p.QuietEnd = true, 9, 9
	if InQuiet(p, night) {
		t.Error("equal hours should mean none")
	}
	// A daytime range.
	p.QuietStart, p.QuietEnd = 9, 17
	if !InQuiet(p, at(2026, 10, 30, 12, 0).UTC()) || InQuiet(p, at(2026, 10, 30, 17, 0).UTC()) {
		t.Error("daytime quiet hours")
	}
	// An unknown zone is UTC.
	p.TimeZone = "Mars/Olympus"
	if Location(p) != time.UTC || ValidTimeZone("Mars/Olympus") || !ValidTimeZone("America/Chicago") || ValidTimeZone("Local") {
		t.Error("time zones")
	}
}

func TestDigestDue(t *testing.T) {
	t.Parallel()
	loc := chicago(t)
	p := store.DefaultPushSettings
	p.TimeZone = "America/Chicago"
	if due, _ := DigestDue(p, time.Date(2026, 10, 30, 7, 59, 0, 0, loc)); due {
		t.Error("before 8 AM")
	}
	due, day := DigestDue(p, time.Date(2026, 10, 30, 8, 0, 0, 0, loc))
	if !due || day != "2026-10-30" {
		t.Fatalf("8 AM: %v %s", due, day)
	}
	p.DigestDay = day
	if due, _ := DigestDue(p, time.Date(2026, 10, 30, 9, 0, 0, 0, loc)); due {
		t.Error("twice in a day")
	}
	// Quiet hours past 8 hold the digest until they end.
	p.DigestDay, p.QuietEnd = "", 9
	if due, _ := DigestDue(p, time.Date(2026, 10, 30, 8, 30, 0, 0, loc)); due {
		t.Error("digest during quiet hours")
	}
	if due, _ := DigestDue(p, time.Date(2026, 10, 30, 9, 0, 0, 0, loc)); !due {
		t.Error("digest after quiet hours")
	}
	if due, _ := DigestDue(p, time.Date(2026, 10, 30, 21, 0, 0, 0, loc)); due {
		t.Error("a digest that late should wait for tomorrow")
	}
}
