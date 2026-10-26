// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

func TestSilentOnline(t *testing.T) {
	e := newEnv(t)
	up, down := e.host("web-01"), e.host("web-02")
	e.host("web-03") // never reported
	e.push(up, snap{pkgs: base})
	e.push(down, snap{pkgs: base})
	reported := e.now
	quiet := 2 * time.Hour
	check := func() int {
		t.Helper()
		n, err := e.eng.CheckSilentOnline(t.Context(), quiet)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	devices := func(synced time.Time, devs ...store.TailnetDevice) {
		t.Helper()
		if err := e.st.ReplaceTailnetDevices(t.Context(), devs, "oauth", time.Time{}, synced); err != nil {
			t.Fatal(err)
		}
	}

	// Without a Tailscale sync there's nothing to compare.
	e.now = reported.Add(3 * time.Hour)
	if n := check(); n != 0 {
		t.Fatalf("no sync: raised %d", n)
	}
	// web-01 is still online; web-02 left the tailnet when it went quiet;
	// web-03 never reported, so it isn't silent.
	devices(e.now,
		store.TailnetDevice{ID: "d1", Hostname: "web-01", Online: true, LastSeen: e.now},
		store.TailnetDevice{ID: "d2", Hostname: "web-02", LastSeen: reported.Add(5 * time.Minute)},
		store.TailnetDevice{ID: "d3", Hostname: "web-03", Online: true, LastSeen: e.now})
	if n := check(); n != 1 {
		t.Fatalf("raised %d, want 1 (web-01)", n)
	}
	as, _ := e.st.Anomalies(t.Context(), up.ID)
	if len(as) == 0 || as[0].Rule != "silent_online" || as[0].Severity != "high" {
		t.Fatalf("anomalies %+v", as)
	}
	if n := check(); n != 0 {
		t.Errorf("raised twice for one silence: %d", n)
	}
	// A stale sync doesn't count.
	e.now = e.now.Add(2 * time.Hour)
	devices(e.now.Add(-2*time.Hour), store.TailnetDevice{ID: "d2", Hostname: "web-02", Online: true, LastSeen: e.now})
	if n := check(); n != 0 {
		t.Errorf("stale sync raised %d", n)
	}
}
