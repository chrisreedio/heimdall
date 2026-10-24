// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

func (e *env) count(table string) int {
	e.t.Helper()
	n, err := e.st.CountRows(e.t.Context(), table)
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

// Reboots show up in unchanged reports (heartbeats), which carry their
// own uptime, and a kernel change is a new snapshot compared with the
// last heartbeat.
func TestRebootRulesOnHeartbeats(t *testing.T) {
	e := newEnv(t)
	h := e.host("web-01")
	e.gap = time.Hour
	e.learn(h)
	if s := e.count("snapshots"); s != 1 {
		t.Fatalf("identical reports stored %d snapshots", s)
	}
	if got := e.push(h, snap{pkgs: base, uptime: 600}); !slices.Equal(got, []string{"unexpected_reboot"}) {
		t.Errorf("reboot in a heartbeat: %v", got)
	}
	if got := e.push(h, snap{pkgs: base, uptime: 600 + 3600}); len(got) != 0 {
		t.Errorf("steady heartbeat: %v", got)
	}
	if got := e.push(h, snap{pkgs: base, uptime: 600 + 7200, kernel: "6.1.0-27"}); !slices.Equal(got, []string{"kernel_no_reboot"}) {
		t.Errorf("kernel without reboot: %v", got)
	}
	if s, hb := e.count("snapshots"), e.count("heartbeats"); s != 2 || hb != LearningSnapshots+2 {
		t.Errorf("%d snapshots, %d heartbeats", s, hb)
	}
}

func names(hs []store.SilentHost) []string {
	var out []string
	for _, h := range hs {
		out = append(out, h.Name)
	}
	return out
}

func TestFastSilenceLifecycle(t *testing.T) {
	e := newEnv(t)
	h := e.host("web-01")
	daily := e.host("daily-01")
	e.push(daily, snap{pkgs: base}) // a day apart: still on a daily timer
	e.push(daily, snap{pkgs: base})
	e.gap = time.Hour
	e.push(h, snap{pkgs: base})
	e.push(h, snap{pkgs: base})
	ctx := t.Context()

	e.now = e.now.Add(2 * time.Hour)
	if got, err := e.eng.CheckFastSilence(ctx, 3*time.Hour); err != nil || len(got.Silent)+len(got.Back) != 0 {
		t.Fatalf("too soon: %+v %v", got, err)
	}
	e.now = e.now.Add(2 * time.Hour)
	got, err := e.eng.CheckFastSilence(ctx, 3*time.Hour)
	if err != nil || !slices.Equal(names(got.Silent), []string{"web-01"}) || len(got.Back) != 0 {
		t.Fatalf("silent: %+v %v", got, err)
	}
	if err := e.eng.MarkSilenceAlerts(ctx, got); err != nil {
		t.Fatal(err)
	}
	if as, _ := e.st.Anomalies(ctx, h.ID); len(as) != 1 || as[0].Rule != "silence" {
		t.Fatalf("anomalies: %+v", as)
	}
	// Once per episode: the next checks are quiet, and so is the stale check.
	e.now = e.now.Add(5 * time.Minute)
	if got, _ := e.eng.CheckFastSilence(ctx, 3*time.Hour); len(got.Silent)+len(got.Back) != 0 {
		t.Fatalf("alerted twice: %+v", got)
	}
	e.now = e.now.Add(72 * time.Hour)
	e.eng.CheckSilence(ctx, 72*time.Hour) // daily-01 goes stale; web-01's episode is already open
	if as, _ := e.st.Anomalies(ctx, h.ID); len(as) != 1 {
		t.Fatalf("stale check raised the same silence again: %+v", as)
	}

	// Back: one notice, the anomaly stays open with a note.
	e.push(h, snap{pkgs: base})
	got, _ = e.eng.CheckFastSilence(ctx, 3*time.Hour)
	if !slices.Equal(names(got.Back), []string{"web-01"}) || len(got.Silent) != 0 {
		t.Fatalf("back: %+v", got)
	}
	e.eng.MarkSilenceAlerts(ctx, got)
	if got, _ := e.eng.CheckFastSilence(ctx, 3*time.Hour); len(got.Back) != 0 {
		t.Fatalf("back twice: %+v", got)
	}
	as, _ := e.st.Anomalies(ctx, h.ID)
	if len(as) != 1 || !strings.Contains(as[0].Summary, "; reported again ") {
		t.Fatalf("anomalies after return: %+v", as)
	}
}

func TestFastSilenceRespectsWindows(t *testing.T) {
	e := newEnv(t)
	h := e.host("web-01")
	e.gap = time.Hour
	e.push(h, snap{pkgs: base})
	e.push(h, snap{pkgs: base})
	if _, err := e.st.CreateWindow(t.Context(), "test", store.Window{OrgSlug: "acme", Host: "web-01",
		Starts: e.now, Ends: e.now.Add(6 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(4 * time.Hour)
	if got, _ := e.eng.CheckFastSilence(t.Context(), 3*time.Hour); len(got.Silent) != 0 {
		t.Fatalf("alerted inside a window: %+v", got)
	}
	e.now = e.now.Add(3 * time.Hour) // window over, still quiet
	if got, _ := e.eng.CheckFastSilence(t.Context(), 3*time.Hour); len(got.Silent) != 1 {
		t.Fatalf("no alert after the window: %+v", got)
	}
}
