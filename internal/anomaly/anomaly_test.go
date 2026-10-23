// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"cmp"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/snapshot"
	"github.com/chrisreedio/heimdall/internal/store"
)

type env struct {
	t   *testing.T
	st  *store.Store
	now time.Time
	eng *Engine
	seq int
	gap time.Duration // between pushes; 0 = a day
}

func newEnv(t *testing.T) *env {
	path := filepath.Join(t.TempDir(), "h.db")
	if err := store.Create(path); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	st.CreateOrg(t.Context(), "test", "acme", "")
	st.CreateEnv(t.Context(), "test", "acme", "prod", "")
	e := &env{t: t, st: st, now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)} // a Monday
	e.eng = &Engine{Store: st, Now: func() time.Time { return e.now }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return e
}

func (e *env) host(name string, tags ...string) store.IngestHost {
	e.st.AddHost(e.t.Context(), "test", "acme", "prod", name, tags)
	h, _ := e.st.HostByName(e.t.Context(), "acme", name)
	return h
}

type snap struct {
	pkgs   map[string]string
	kernel string
	uptime int64
	sha    string
}

// push stores a report a day (or e.gap) after the previous one and runs the rules.
func (e *env) push(h store.IngestHost, s snap) []string {
	e.t.Helper()
	e.now = e.now.Add(cmp.Or(e.gap, 24*time.Hour))
	e.seq++
	if s.kernel == "" {
		s.kernel = "6.1.0-26"
	}
	if s.uptime == 0 {
		s.uptime = int64(e.seq) * 86400 * 10 // steadily up
	}
	sn := &snapshot.Snapshot{Format: snapshot.FormatV1, CollectedAt: e.now, PackageManager: "dpkg",
		Collector: snapshot.Collector{Version: "0.2.0", SHA256: s.sha},
		OS:        snapshot.OS{ID: "debian", VersionID: "12"}, Kernel: snapshot.Kernel{Release: s.kernel, Arch: "x86_64"},
		UptimeSeconds: s.uptime}
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range s.pkgs {
			if !yield(k) {
				return
			}
		}
	}) {
		sn.Packages = append(sn.Packages, snapshot.Package{Name: name, Version: s.pkgs[name], Arch: "amd64"})
	}
	if _, err := e.st.SaveSnapshot(e.t.Context(), store.NewSnapshot{Host: h, Source: "push", ReceivedAt: e.now, Snapshot: sn,
		PayloadSHA256: sha256.Sum256([]byte(fmt.Sprint(h.ID, e.seq)))}, nil); err != nil {
		e.t.Fatal(err)
	}
	raised, err := e.eng.OnSnapshot(e.t.Context(), h)
	if err != nil {
		e.t.Fatal(err)
	}
	var rules []string
	for _, a := range raised {
		rules = append(rules, a.Rule)
	}
	return rules
}

var base = map[string]string{"openssl": "3.0.13-1", "curl": "7.88.1-10"}

func with(m map[string]string, kv ...string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(out, kv[i])
		} else {
			out[kv[i]] = kv[i+1]
		}
	}
	return out
}

func (e *env) learn(h store.IngestHost) {
	for range LearningSnapshots + 1 {
		if got := e.push(h, snap{pkgs: base}); len(got) != 0 {
			e.t.Fatalf("learning raised %v", got)
		}
	}
}

func TestLearningPeriodThenChanges(t *testing.T) {
	e := newEnv(t)
	h := e.host("web-01")
	// During learning even big changes are just the baseline.
	if got := e.push(h, snap{pkgs: with(base, "nmap", "7.93")}); len(got) != 0 {
		t.Fatalf("learning: %v", got)
	}
	e.learn(h)
	if got := e.push(h, snap{pkgs: with(base, "socat", "1.7")}); !slices.Equal(got, []string{"package_change"}) {
		t.Errorf("install: %v", got)
	}
	if got := e.push(h, snap{pkgs: with(base, "socat", "1.7", "curl", "7.88.1-9")}); !slices.Equal(got, []string{"package_downgrade"}) {
		t.Errorf("downgrade: %v", got)
	}
	// Upgrades are routine.
	if got := e.push(h, snap{pkgs: with(base, "socat", "1.7", "curl", "7.88.1-11")}); len(got) != 0 {
		t.Errorf("upgrade raised %v", got)
	}
}

func TestWindowsAndPlansMakeChangesExpected(t *testing.T) {
	e := newEnv(t)
	h := e.host("web-01")
	e.learn(h)
	// Every day 00:00–23:59 UTC is a window.
	if _, err := e.st.CreateWindow(t.Context(), "test", store.Window{OrgSlug: "acme", Weekdays: 127,
		StartTime: "00:00", Duration: 24 * time.Hour, Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	if got := e.push(h, snap{pkgs: with(base, "socat", "1.7"), uptime: 100}); len(got) != 0 {
		t.Errorf("in window: %v", got)
	}
}

func TestRebootAndKernel(t *testing.T) {
	e := newEnv(t)
	h := e.host("web-01")
	e.learn(h)
	if got := e.push(h, snap{pkgs: base, uptime: 600}); !slices.Equal(got, []string{"unexpected_reboot"}) {
		t.Errorf("reboot: %v", got)
	}
	if got := e.push(h, snap{pkgs: base, uptime: 600 + 86400, kernel: "6.1.0-27"}); !slices.Equal(got, []string{"kernel_no_reboot"}) {
		t.Errorf("kernel without reboot: %v", got)
	}
}

func TestPeerOutlierAndSuppression(t *testing.T) {
	e := newEnv(t)
	h := e.host("web-01", "web")
	p1, p2 := e.host("web-02", "web"), e.host("web-03", "web")
	e.push(p1, snap{pkgs: base})
	e.push(p2, snap{pkgs: base})
	e.learn(h)
	got := e.push(h, snap{pkgs: with(base, "xmrig", "6.0")})
	if !slices.Contains(got, "peer_outlier") || !slices.Contains(got, "package_change") {
		t.Errorf("outlier: %v", got)
	}
	if err := e.st.Suppress(t.Context(), "test", 0, h, "package_change", e.now.Add(48*time.Hour), "migrating", e.now); err != nil {
		t.Fatal(err)
	}
	if got := e.push(h, snap{pkgs: with(base, "xmrig", "6.0", "nano", "7.2")}); slices.Contains(got, "package_change") {
		t.Errorf("suppressed rule still raised: %v", got)
	}
}

func TestCollectorTrust(t *testing.T) {
	e := newEnv(t)
	h := e.host("web-01")
	good, bad := fmt.Sprintf("%064x", 1), fmt.Sprintf("%064x", 2)
	// No collectors trusted yet: nothing to compare against.
	if got := e.push(h, snap{pkgs: base, sha: bad}); len(got) != 0 {
		t.Errorf("no trust configured: %v", got)
	}
	e.st.TrustCollector(t.Context(), "test", good, "0.2.0", "")
	if got := e.push(h, snap{pkgs: base, sha: bad}); !slices.Equal(got, []string{"collector_changed"}) {
		t.Errorf("untrusted: %v", got)
	}
	if got := e.push(h, snap{pkgs: base, sha: bad}); len(got) != 0 {
		t.Errorf("same checksum raised twice: %v", got)
	}
	if got := e.push(h, snap{pkgs: base, sha: good}); len(got) != 0 {
		t.Errorf("trusted: %v", got)
	}
}

func TestSilence(t *testing.T) {
	e := newEnv(t)
	h := e.host("web-01")
	e.push(h, snap{pkgs: base})
	e.now = e.now.Add(4 * 24 * time.Hour)
	if n, err := e.eng.CheckSilence(t.Context(), 72*time.Hour); err != nil || n != 1 {
		t.Fatalf("silence: %d %v", n, err)
	}
	if n, _ := e.eng.CheckSilence(t.Context(), 72*time.Hour); n != 0 {
		t.Errorf("silence raised twice")
	}
}

func TestWindowOverlap(t *testing.T) {
	loc, _ := time.LoadLocation("America/Chicago")
	days, _ := store.ParseWeekdays("sat")
	w := store.Window{Weekdays: days, StartTime: "23:00", Duration: 3 * time.Hour, Timezone: "America/Chicago"}
	sat := time.Date(2026, 10, 24, 23, 30, 0, 0, loc) // inside
	if !w.Overlaps(sat, sat.Add(time.Minute)) {
		t.Error("inside window")
	}
	sunEarly := time.Date(2026, 10, 25, 1, 0, 0, 0, loc) // crosses midnight
	if !w.Overlaps(sunEarly, sunEarly.Add(time.Minute)) {
		t.Error("window crossing midnight")
	}
	tue := time.Date(2026, 10, 27, 12, 0, 0, 0, loc)
	if w.Overlaps(tue, tue.Add(time.Hour)) {
		t.Error("tuesday is outside")
	}
	if m, err := store.ParseWeekdays("mon-fri"); err != nil || m != 0b0111110 {
		t.Errorf("mon-fri = %b %v", m, err)
	}
}
