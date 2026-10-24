// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/history"
	"github.com/chrisreedio/heimdall/internal/store"
)

func TestUptimeInconsistent(t *testing.T) {
	t0 := time.Date(2026, 10, 20, 14, 0, 0, 0, time.UTC)
	day := int64(86400)
	// report builds a push received at t0+at, collected skew later, with uptime up.
	report := func(at time.Duration, skew time.Duration, up int64) store.SnapshotFacts {
		return store.SnapshotFacts{ID: 1, HeartbeatID: int64(at), Source: "push", ReceivedAt: t0.Add(at),
			CollectedAt: t0.Add(at + skew), UptimeSeconds: up}
	}
	imp := report(time.Hour, 0, 30*day+7*day)
	imp.Source = "import"
	prev := report(0, 0, 30*day)
	tests := []struct {
		name  string
		prev  store.SnapshotFacts
		cur   store.SnapshotFacts
		alert bool
	}{
		{"hourly heartbeat", prev, report(time.Hour, 0, 30*day+3600), false},
		{"daily report", prev, report(24*time.Hour, 0, 31*day), false},
		{"reboot", prev, report(time.Hour, 0, 300), false},
		{"paused VM falls behind", prev, report(2*time.Hour, 0, 30*day+600), false},
		{"within tolerance", prev, report(time.Hour, 0, 30*day+3600+9*60), false},
		{"host clock stepped back", prev, report(time.Hour, -30*time.Minute, 30*day+3600), false},
		{"delivery delayed on the previous report", report(0, -40*time.Minute, 30*day), report(time.Hour, 0, 30*day+3600+40*60), false},
		{"uptime unknown", report(0, 0, -1), report(time.Hour, 0, 30*day), false},
		{"uptime zero (container)", report(0, 0, 0), report(time.Hour, 0, 30*day), false},
		{"import", prev, imp, false},
		{"just past tolerance", prev, report(time.Hour, 0, 30*day+3600+11*60), true},
		{"a week of uptime in an hour", prev, report(time.Hour, 0, 37*day), true},
		{"boot moved earlier on both clocks", prev, report(24*time.Hour, 5*time.Minute, 33*day), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, ok := uptimeInconsistent(tt.prev, tt.cur)
			if ok != tt.alert {
				t.Fatalf("alert = %v, want %v (%s)", ok, tt.alert, a.Summary)
			}
			if ok && (a.Rule != "uptime_inconsistent" || !strings.Contains(a.Summary, "booted")) {
				t.Errorf("anomaly: %+v", a)
			}
		})
	}
	a, _ := uptimeInconsistent(prev, report(time.Hour, 0, 37*day))
	if want := "Uptime grew 7d 0h in 1h 0m: the host now claims it booted Sep 13, 2026 3:00 PM UTC, but its previous report said Sep 20, 2026 2:00 PM UTC"; a.Summary != want {
		t.Errorf("summary:\n got %s\nwant %s", a.Summary, want)
	}
}

func TestOSChanged(t *testing.T) {
	f := func(os string) store.SnapshotFacts { return store.SnapshotFacts{OSID: os} }
	tests := []struct {
		prev, cur string
		alert     bool
	}{
		{"debian", "debian", false},
		{"", "debian", false}, // older snapshot without an ID
		{"debian", "", false},
		{"ubuntu", "debian", true},
		{"centos", "rocky", true},
	}
	for _, tt := range tests {
		a, ok := osChanged(f(tt.prev), f(tt.cur))
		if ok != tt.alert {
			t.Errorf("%s→%s: alert = %v", tt.prev, tt.cur, ok)
		}
		if ok && (a.Severity != "medium" || a.Detail["key"] != tt.prev+"→"+tt.cur) {
			t.Errorf("%s→%s: %+v", tt.prev, tt.cur, a)
		}
	}
}

func TestCollectorDowngrade(t *testing.T) {
	sha := fmt.Sprintf("%064x", 7)
	f := func(v, sha string) store.SnapshotFacts {
		return store.SnapshotFacts{CollectorVer: v, CollectorSHA256: sha}
	}
	tests := []struct {
		name                string
		prev, cur           store.SnapshotFacts
		anyTrusted, trusted bool
		alert               bool
	}{
		{"upgrade", f("0.4.12", sha), f("0.4.13", sha), false, false, false},
		{"same version", f("0.4.13", sha), f("0.4.13", sha), false, false, false},
		{"dev build of the same release", f("0.4.13", sha), f("0.4.13-dev.4", sha), false, false, false},
		{"older, nothing trusted", f("0.4.13", sha), f("0.4.10", sha), false, false, true},
		{"older, no checksum", f("0.4.13", sha), f("0.3.0", ""), false, false, true},
		{"older minor beats newer patch", f("0.5.0", sha), f("0.4.99", sha), false, false, true},
		{"older but a trusted release", f("0.4.13", sha), f("0.4.10", sha), true, true, false},
		{"older and untrusted: collector_changed covers it", f("0.4.13", sha), f("0.4.10", sha), true, false, false},
		{"unparsable", f("0.4.13", sha), f("dev", sha), false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, ok := collectorDowngrade(tt.prev, tt.cur, tt.anyTrusted, tt.trusted)
			if ok != tt.alert {
				t.Fatalf("alert = %v, want %v", ok, tt.alert)
			}
			if ok && !strings.HasPrefix(a.Summary, "Collector went back from "+tt.prev.CollectorVer+" to "+tt.cur.CollectorVer) {
				t.Errorf("summary: %s", a.Summary)
			}
		})
	}
}

func TestPackageDrop(t *testing.T) {
	tests := []struct {
		name          string
		before, after int
		alert         bool
	}{
		{"apt autoremove of 5", 540, 535, false},
		{"no change", 540, 540, false},
		{"growth", 100, 200, false},
		{"25% of a big host", 1000, 750, false},
		{"40% but only 16 packages", 40, 24, false},
		{"exactly 30%", 100, 70, false},
		{"packages unavailable", 540, 0, false},
		{"gutted", 540, 212, true},
		{"31% and 31 packages", 100, 69, true},
		{"20 of 60", 60, 40, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, ok := packageDrop(tt.before, tt.after, history.Diff{}, 9)
			if ok != tt.alert {
				t.Fatalf("alert = %v, want %v", ok, tt.alert)
			}
			if ok && (a.Rule != "package_drop" || a.Severity != "high") {
				t.Errorf("anomaly: %+v", a)
			}
		})
	}
}

// many is n filler packages plus base.
func many(n int) map[string]string {
	out := with(base)
	for i := range n {
		out[fmt.Sprintf("lib%03d", i)] = "1.0-1"
	}
	return out
}

// without drops the first n filler packages.
func without(m map[string]string, n int) map[string]string {
	out := with(m)
	for i := range n {
		delete(out, fmt.Sprintf("lib%03d", i))
	}
	return out
}

func (e *env) everyDayWindow() {
	e.t.Helper()
	if _, err := e.st.CreateWindow(e.t.Context(), "test", store.Window{OrgSlug: "acme", Weekdays: 127,
		StartTime: "00:00", Duration: 24 * time.Hour, Timezone: "UTC"}); err != nil {
		e.t.Fatal(err)
	}
}

// step is one report in a sequence and the rules it should raise.
type step struct {
	s    snap
	want []string
}

func (e *env) run(h store.IngestHost, steps []step) {
	e.t.Helper()
	for i, st := range steps {
		if got := e.push(h, st.s); !slices.Equal(got, st.want) {
			e.t.Errorf("step %d: got %v, want %v", i+1, got, st.want)
		}
	}
}

// Each rule end to end: alerts, and the legitimate sequences that don't.
func TestConsistencyRules(t *testing.T) {
	week := int64(7 * 86400)
	tests := []struct {
		name   string
		gap    time.Duration
		window bool
		trust  bool
		start  map[string]string // packages while learning
		steps  []step
	}{
		{name: "first report", steps: nil},
		{name: "hourly heartbeat stream", gap: time.Hour, steps: []step{
			{snap{pkgs: base}, nil}, {snap{pkgs: base}, nil}, {snap{pkgs: base}, nil}, {snap{pkgs: base}, nil}}},
		{name: "normal reboot", steps: []step{
			{snap{pkgs: base, uptime: 120}, []string{"unexpected_reboot"}}, {snap{pkgs: base}, nil}}},
		{name: "kernel upgrade then reboot, in a window", window: true, steps: []step{
			{snap{pkgs: with(base, "linux-image-6.1.0-27", "6.1.115-1")}, nil},
			{snap{pkgs: with(base, "linux-image-6.1.0-27", "6.1.115-1"), kernel: "6.1.0-27", uptime: 90}, nil},
			{snap{pkgs: with(base, "linux-image-6.1.0-27", "6.1.115-1"), kernel: "6.1.0-27"}, nil}}},
		{name: "uptime unavailable", gap: time.Hour, steps: []step{
			{snap{pkgs: base, noUptime: true}, nil}, {snap{pkgs: base, noUptime: true}, nil}, {snap{pkgs: base}, nil}}},
		{name: "uptime outruns the clock in a heartbeat", gap: time.Hour, steps: []step{
			{snap{pkgs: base, uptime: 40 * 86400}, []string{"uptime_inconsistent"}}, {snap{pkgs: base}, nil}}},
		{name: "uptime outruns the clock, even in a window", window: true, steps: []step{
			{snap{pkgs: base, uptime: 31*86400 + week}, []string{"uptime_inconsistent"}}}},
		{name: "imports are exempt from uptime", steps: []step{
			{snap{pkgs: base, uptime: 31*86400 + week, source: "import", skew: -48 * time.Hour}, nil}}},
		{name: "OS changed", steps: []step{{snap{pkgs: base, os: "ubuntu"}, []string{"os_changed"}}}},
		{name: "reinstall in a window", window: true, steps: []step{{snap{pkgs: base, os: "ubuntu"}, nil}}},
		{name: "collector upgrade", steps: []step{{snap{pkgs: base, ver: "0.4.13"}, nil}, {snap{pkgs: base, ver: "0.4.13"}, nil}}},
		{name: "collector upgrade to a trusted release", trust: true, steps: []step{
			{snap{pkgs: base, ver: "0.4.13", sha: fmt.Sprintf("%064x", 1)}, nil}}},
		{name: "collector downgraded", steps: []step{
			{snap{pkgs: base, ver: "0.4.13"}, nil}, {snap{pkgs: base, ver: "0.4.10"}, []string{"collector_downgrade"}}}},
		{name: "collector downgraded with a trust list", trust: true, steps: []step{
			{snap{pkgs: base, ver: "0.1.0", sha: fmt.Sprintf("%064x", 2)}, []string{"collector_changed"}}}},
		{name: "apt autoremove of 5", start: many(60), steps: []step{
			{snap{pkgs: without(many(60), 5)}, []string{"package_change"}}}},
		{name: "package drop", start: many(60), steps: []step{
			{snap{pkgs: without(many(60), 25)}, []string{"package_drop"}}}},
		{name: "package drop in a window", window: true, start: many(60), steps: []step{
			{snap{pkgs: without(many(60), 25)}, nil}}},
		{name: "inventory reverted", steps: []step{
			{snap{pkgs: with(base, "socat", "1.7")}, []string{"package_change"}},
			{snap{pkgs: base}, []string{"package_change", "inventory_reverted"}}}},
		{name: "rollback in a window", window: true, steps: []step{
			{snap{pkgs: with(base, "curl", "7.88.1-11")}, nil}, {snap{pkgs: base}, nil}}},
		{name: "back to an old kernel, same packages", steps: []step{
			{snap{pkgs: base, kernel: "6.1.0-27", uptime: 100}, []string{"unexpected_reboot"}},
			{snap{pkgs: base, kernel: "6.1.0-26", uptime: 100}, []string{"unexpected_reboot"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.gap = tt.gap
			h := e.host("web-01")
			if tt.trust {
				e.st.TrustCollector(t.Context(), "test", fmt.Sprintf("%064x", 1), "0.4.13", "")
			}
			start := base
			if tt.start != nil {
				start = tt.start
			}
			sha := ""
			if tt.trust {
				sha = fmt.Sprintf("%064x", 1)
			}
			for range LearningSnapshots + 1 {
				if got := e.push(h, snap{pkgs: start, sha: sha}); len(got) != 0 {
					t.Fatalf("learning raised %v", got)
				}
			}
			if tt.window {
				e.everyDayWindow()
			}
			e.run(h, tt.steps)
		})
	}
}

func TestPackageDropSuppressedFallsBack(t *testing.T) {
	e := newEnv(t)
	h := e.host("web-01")
	for range LearningSnapshots + 1 {
		e.push(h, snap{pkgs: many(60)})
	}
	if err := e.st.Suppress(t.Context(), "test", 0, h, "package_drop", e.now.Add(72*time.Hour), "rebuilding", e.now); err != nil {
		t.Fatal(err)
	}
	if got := e.push(h, snap{pkgs: without(many(60), 25)}); !slices.Equal(got, []string{"package_change"}) {
		t.Errorf("suppressed drop: %v", got)
	}
}
