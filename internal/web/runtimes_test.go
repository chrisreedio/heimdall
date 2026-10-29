// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/report"
)

// Versions of one runtime share a block, newest first; blocks keep the
// report's order.
func TestRuntimeGroups(t *testing.T) {
	gs := runtimeGroups([]report.Runtime{
		{Name: "nodejs", Version: "24.22.2"},
		{Name: "php", Version: "8.3.36", Use: &report.PHPUse{Unused: true}},
		{Name: "php", Version: "8.10.1"},
		{Name: "php", Version: "8.5.12"},
		{Name: "python", Version: "3.12.3"},
	})
	if len(gs) != 3 || gs[0].Name != "nodejs" || gs[1].Name != "php" || gs[2].Name != "python" {
		t.Fatalf("groups = %+v", gs)
	}
	var got []string
	for _, v := range gs[1].Versions {
		got = append(got, v.Version)
	}
	if want := []string{"8.10.1", "8.5.12", "8.3.36"}; len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("php versions = %v, want %v", got, want)
	}
	if gs[1].Unused != 1 || gs[0].Unused != 0 {
		t.Errorf("unused: php %d, nodejs %d", gs[1].Unused, gs[0].Unused)
	}
}

// A runtime's end of life shows from a year out, not 90 days.
func TestSupportState(t *testing.T) {
	d := time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		l    *report.Lifecycle
		want string
	}{
		{nil, "unknown"},
		{&report.Lifecycle{Known: true, EOL: true, EOLDate: &d}, "eol"},
		{&report.Lifecycle{Known: true, EOLDate: &d, DaysLeft: 60}, "soon"},
		{&report.Lifecycle{Known: true, EOLDate: &d, DaysLeft: 365}, "soon"},
		{&report.Lifecycle{Known: true, EOLDate: &d, DaysLeft: 366}, "ok"},
		{&report.Lifecycle{Known: true}, "ok"},
	} {
		if got := supportState(c.l); got != c.want {
			t.Errorf("supportState(%+v) = %s, want %s", c.l, got, c.want)
		}
	}
}
