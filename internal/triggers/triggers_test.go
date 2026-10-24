// SPDX-License-Identifier: AGPL-3.0-or-later

package triggers

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	got, err := Parse(" timer=enabled,active;changes=disabled,inactive ")
	if err != nil || got.String() != "changes=disabled,inactive; timer=enabled,active" {
		t.Fatalf("%q %v", got.String(), err)
	}
	if got.ChangeWatch() != "off" {
		t.Errorf("change watch = %q", got.ChangeWatch())
	}
	for _, bad := range []string{"timer", "timer=", "Timer=on", "timer=a b", "timer=x\r\nX-Evil: 1", "a=b; a=c",
		strings.Repeat("a=b;", 9), "timer=" + strings.Repeat("a", 300), "t=a,b,c"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if s, err := Parse(""); s != nil || err != nil {
		t.Errorf("empty: %v %v", s, err)
	}
}

func TestOn(t *testing.T) {
	for state, want := range map[string]bool{
		"enabled,active": true, "static,active": true, "present": true,
		"enabled,inactive": false, "disabled,active": false, "masked,inactive": false,
		"missing,inactive": false, "absent": false, "unknown,unknown": false, "": false,
	} {
		if On(state) != want {
			t.Errorf("On(%q) = %v", state, !want)
		}
	}
	if w := (State{"hook": "present", "cron": "absent"}).ChangeWatch(); w != "on" {
		t.Errorf("apk hook: %q", w)
	}
	if w := (State{"changes": "unknown,unknown"}).ChangeWatch(); w != "" {
		t.Errorf("unknown: %q", w)
	}
}

func TestWindows(t *testing.T) {
	got, err := Parse("task=enabled,running; changes=enabled,ready")
	if err != nil || got.String() != "changes=enabled,ready; task=enabled,running" {
		t.Fatalf("%q %v", got.String(), err)
	}
	if got.ChangeWatch() != "on" {
		t.Errorf("change watch = %q", got.ChangeWatch())
	}
	// Every state collect.ps1 can send is accepted.
	for _, en := range []string{"enabled", "disabled", "missing", "unknown"} {
		for _, st := range []string{"ready", "running", "queued", "disabled", "no-triggers", "none", "unknown"} {
			if _, err := Parse("task=" + en + "," + st + "; changes=" + en + "," + st); err != nil {
				t.Errorf("%s,%s: %v", en, st, err)
			}
		}
	}
	// Windows entries take only Windows values; systemd's or made-up ones
	// are rejected whole.
	for _, bad := range []string{"task=enabled,active", "task=enabled", "task=present", "task=enabled,bogus",
		"task=Enabled,Ready", "task=enabled,ready; changes=enabled,active", "task=enabled,ready; changes=present"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for state, want := range map[string]bool{
		"enabled,ready": true, "enabled,running": true, "enabled,queued": true,
		"disabled,disabled": false, "enabled,no-triggers": false, "missing,none": false,
		"enabled,unknown": false, "unknown,unknown": false, "disabled,ready": false,
	} {
		if On(state) != want {
			t.Errorf("On(%q) = %v", state, !want)
		}
	}
	for header, want := range map[string]string{
		"task=enabled,ready; changes=disabled,disabled": "off",
		"task=enabled,ready; changes=missing,none":      "off",
		"task=enabled,ready; changes=enabled,unknown":   "",
		"task=enabled,ready; changes=unknown,unknown":   "",
	} {
		s, err := Parse(header)
		if err != nil || s.ChangeWatch() != want {
			t.Errorf("%q: change watch %q, want %q (%v)", header, s.ChangeWatch(), want, err)
		}
	}
}
