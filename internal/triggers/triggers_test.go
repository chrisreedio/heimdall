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
