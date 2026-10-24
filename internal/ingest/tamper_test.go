// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
)

// report is the fixture as sent n minutes after it was first collected:
// same inventory, new collected_at and uptime.
func (e *env) report(n int) []byte {
	at := fixtureTime.Add(time.Duration(n) * time.Minute).Format(time.RFC3339)
	b := strings.Replace(string(e.body), `"collected_at": "2026-10-22T04:17:03Z"`, `"collected_at": "`+at+`"`, 1)
	return []byte(strings.Replace(b, `"uptime_seconds": 1209600`, fmt.Sprintf(`"uptime_seconds": %d`, 1209600+n*60), 1))
}

func (e *env) count(table string) int {
	e.t.Helper()
	n, err := e.st.CountRows(e.t.Context(), table)
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

func TestUnchangedReportsAreHeartbeats(t *testing.T) {
	e := newEnv(t, func(c *config.Ingest) { c.RatePerHost.N = 100 })
	e.expect(req{}, http.StatusCreated)
	pkgs := e.count("packages")
	for i := 1; i < 24; i++ {
		e.now = e.now.Add(time.Hour)
		if w := e.expect(req{body: e.report(i * 60)}, http.StatusOK); !strings.Contains(w.Body.String(), "unchanged") {
			t.Fatalf("report %d: %q", i, w.Body.String())
		}
	}
	if s, hb, p := e.count("snapshots"), e.count("heartbeats"), e.count("packages"); s != 1 || hb != 23 || p != pkgs {
		t.Fatalf("after 24 identical reports: %d snapshots, %d heartbeats, %d packages (want 1, 23, %d)", s, hb, p, pkgs)
	}
	sum, err := e.st.LatestSnapshot(t.Context(), e.host.ID)
	if err != nil || !sum.ReceivedAt.Equal(e.now) {
		t.Fatalf("last report = %v (%v), want %v", sum.ReceivedAt, err, e.now)
	}

	// A heartbeat's payload resent much later is a replay, like a snapshot's.
	e.now = e.now.Add(time.Hour)
	e.expect(req{body: e.report(60)}, http.StatusConflict)
	if a := e.anomalies(); len(a) != 1 || a[0] != "replay" {
		t.Fatalf("anomalies = %v, want [replay]", a)
	}

	// A real change is stored in full.
	changed := strings.Replace(string(e.report(25*60)), `"3.0.14-1~deb12u2"`, `"3.0.15-1~deb12u1"`, 1)
	e.expect(req{body: []byte(changed)}, http.StatusCreated)
	if s := e.count("snapshots"); s != 2 {
		t.Fatalf("snapshots = %d, want 2", s)
	}
}

func TestTriggerDisabled(t *testing.T) {
	e := newEnv(t, func(c *config.Ingest) { c.RatePerHost.N = 100 })
	on := "timer=enabled,active; changes=enabled,active"
	e.expect(req{triggers: on}, http.StatusCreated)
	e.now = e.now.Add(time.Hour)
	e.expect(req{body: e.report(60), triggers: on}, http.StatusOK)
	if a := e.anomalies(); len(a) != 0 {
		t.Fatalf("anomalies = %v", a)
	}

	// The bus is down: unknown never alerts, and the last known state stays.
	e.now = e.now.Add(time.Hour)
	e.expect(req{body: e.report(120), triggers: "timer=unknown,unknown; changes=unknown,unknown"}, http.StatusOK)
	if got, _ := e.st.HostTriggers(t.Context(), e.host.ID); got != "changes=enabled,active; timer=enabled,active" {
		t.Fatalf("stored = %q", got)
	}

	e.now = e.now.Add(time.Hour)
	e.expect(req{body: e.report(180), triggers: "timer=enabled,active; changes=disabled,inactive"}, http.StatusOK)
	if a := e.anomalies(); len(a) != 1 || a[0] != "trigger_disabled" {
		t.Fatalf("anomalies = %v, want [trigger_disabled]", a)
	}
	// Still off: once per change, not every report.
	e.now = e.now.Add(time.Hour)
	e.expect(req{body: e.report(240), triggers: "timer=enabled,active; changes=disabled,inactive"}, http.StatusOK)
	// No header (an older collector): stored state is left alone, no alert.
	e.now = e.now.Add(time.Hour)
	e.expect(req{body: e.report(300)}, http.StatusOK)
	// Malformed or oversized headers are ignored; the report still counts.
	e.now = e.now.Add(time.Hour)
	e.expect(req{body: e.report(360), triggers: "timer=<script>"}, http.StatusOK)
	e.now = e.now.Add(time.Hour)
	e.expect(req{body: e.report(420), triggers: "timer=" + strings.Repeat("a", 300)}, http.StatusOK)
	// The timer going off is flagged the same way.
	e.now = e.now.Add(time.Hour)
	e.expect(req{body: e.report(480), triggers: "timer=masked,inactive; changes=disabled,inactive"}, http.StatusOK)
	if a := e.anomalies(); len(a) != 2 {
		t.Fatalf("anomalies = %v, want two trigger_disabled", a)
	}
}

func TestNoTriggerAlertWithoutHistory(t *testing.T) {
	e := newEnv(t, nil)
	// A host that never had the path unit (or only now starts reporting
	// triggers) has nothing to compare with.
	e.expect(req{triggers: "timer=enabled,active; changes=missing,inactive"}, http.StatusCreated)
	if a := e.anomalies(); len(a) != 0 {
		t.Fatalf("anomalies = %v", a)
	}
}
