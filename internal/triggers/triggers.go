// SPDX-License-Identifier: AGPL-3.0-or-later

// Package triggers tracks what makes each host's collector run, and raises
// the "trigger_disabled" tripwire (see docs/anomaly-signals.md) when one
// is switched off while the host keeps reporting. It's apart from package
// anomaly so the ingest handler can use it without an import cycle.
package triggers

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// State is a collector's report on what makes it run, from the
// X-Heimdall-Triggers header: one state per trigger, e.g.
//
//	changes=enabled,active; timer=enabled,active
//	changes=enabled,ready; task=enabled,running      (Windows)
//
// Keys and what their states look like:
//
//	timer    heimdall-collect.timer (systemd): "<is-enabled>,<is-active>"
//	changes  heimdall-collect-changes.path (systemd): same; on Windows the
//	         "Heimdall collector (changes)" scheduled task, as for task
//	cron     /etc/cron.daily or /etc/periodic/daily job: "present" or "absent"
//	hook     apk commit hook or apt hook: "present" or "absent"
//	task     the "Heimdall collector" scheduled task (Windows):
//	         "<enabled|disabled|missing|unknown>,<state>", the state being
//	         the Task Scheduler's (ready, running, queued, disabled, unknown),
//	         "no-triggers" (enabled with every trigger off) or "none" (missing)
//
// A state containing "unknown" means the collector couldn't tell (e.g.
// systemctl couldn't reach D-Bus); it never raises an alert. A Windows
// collector sends a "task" entry, which is how its "changes" entry is
// told apart from a systemd one.
type State map[string]string

// MaxHeader caps the header the hub accepts.
const MaxHeader = 256

var (
	triggerKeyRe   = regexp.MustCompile(`^[a-z]{1,16}$`)
	triggerStateRe = regexp.MustCompile(`^[a-z-]{1,24}(,[a-z-]{1,24})?$`)
	// windowsStateRe is every state collect.ps1 can send for a task.
	windowsStateRe = regexp.MustCompile(`^(enabled|disabled|missing|unknown),(ready|running|queued|disabled|no-triggers|none|unknown)$`)
)

// Parse validates a header value. Anything malformed is rejected
// whole (the snapshot is still accepted; only the trigger state is dropped).
func Parse(v string) (State, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	if len(v) > MaxHeader {
		return nil, fmt.Errorf("triggers header longer than %d bytes", MaxHeader)
	}
	parts := strings.Split(v, ";")
	if len(parts) > 8 {
		return nil, fmt.Errorf("triggers header has more than 8 entries")
	}
	t := State{}
	for _, p := range parts {
		k, s, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok || !triggerKeyRe.MatchString(k) || !triggerStateRe.MatchString(s) {
			return nil, fmt.Errorf("invalid triggers entry %q", truncate(p, 40))
		}
		if _, dup := t[k]; dup {
			return nil, fmt.Errorf("repeated triggers entry %q", k)
		}
		t[k] = s
	}
	// The Windows collector's entries take only the values it can send.
	if _, win := t["task"]; win {
		for k, s := range t {
			if (k == "task" || k == "changes") && !windowsStateRe.MatchString(s) {
				return nil, fmt.Errorf("invalid Windows triggers entry %q", truncate(k+"="+s, 40))
			}
		}
	}
	return t, nil
}

// String is the canonical form: entries sorted by key.
func (t State) String() string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(t)) {
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		b.WriteString(k + "=" + t[k])
	}
	return b.String()
}

// On reports whether a state means the trigger will fire: a systemd
// unit that is enabled (or static) and active, a hook file that exists, or
// an enabled Windows scheduled task with a trigger (ready, running or
// queued).
func On(state string) bool {
	if state == "present" {
		return true
	}
	en, act, ok := strings.Cut(state, ",")
	if !ok {
		return false
	}
	if en == "enabled" && slices.Contains([]string{"ready", "running", "queued"}, act) {
		return true
	}
	return act == "active" && slices.Contains([]string{"enabled", "enabled-runtime", "static", "indirect", "generated", "alias", "linked"}, en)
}

// triggerKnown: the collector could tell the state (it isn't "unknown").
func triggerKnown(state string) bool { return state != "" && !strings.Contains(state, "unknown") }

// ChangeWatch summarizes whether the host reports changes as they happen:
// "on", "off", or "" if its collector doesn't say (older collectors, or
// the state is unknown).
func (t State) ChangeWatch() string {
	for _, k := range []string{"changes", "hook"} {
		if s, ok := t[k]; ok && triggerKnown(s) {
			if On(s) {
				return "on"
			}
			return "off"
		}
	}
	return ""
}

var triggerNames = map[string]struct{ what, unit string }{
	"timer":   {"Scheduled reporting", "heimdall-collect.timer"},
	"changes": {"Change reporting", "heimdall-collect-changes.path"},
	"cron":    {"Scheduled reporting", "the daily cron job"},
	"hook":    {"Change reporting", "the package manager hook"},
}

// windowsNames are the Windows collector's scheduled tasks.
var windowsNames = map[string]struct{ what, unit string }{
	"task":    {"Scheduled reporting", `the "Heimdall collector" scheduled task`},
	"changes": {"Change reporting", `the "Heimdall collector (changes)" scheduled task`},
}

// Check compares a report's trigger state with the host's own
// previous one and raises "trigger_disabled" when a trigger that was on is
// now definitely off, while the host is still reporting. Hosts whose
// collector never reported a trigger (older collectors, or never installed
// the path unit) don't alert. An empty header leaves the stored state
// alone; a state the collector couldn't determine keeps the previous one.
func Check(ctx context.Context, st *store.Store, hostID, snapshotID int64, header string, now time.Time) ([]store.Anomaly, error) {
	cur, err := Parse(header)
	if err != nil || cur == nil {
		return nil, err
	}
	raw, err := st.HostTriggers(ctx, hostID)
	if err != nil {
		return nil, err
	}
	prev, _ := Parse(raw) // stored values were validated on the way in

	var raised []store.Anomaly
	for _, k := range slices.Sorted(maps.Keys(cur)) {
		was, state := prev[k], cur[k]
		if !triggerKnown(state) {
			if was != "" {
				cur[k] = was // keep the last known state
			}
			continue
		}
		if !On(was) || On(state) {
			continue
		}
		names := triggerNames
		if _, win := cur["task"]; win {
			names = windowsNames
		}
		name, ok := names[k]
		if !ok {
			name.what, name.unit = "A collector trigger", k
		}
		a := store.Anomaly{Rule: "trigger_disabled", Severity: "high",
			Summary: fmt.Sprintf("%s disabled: %s is now %s (was %s)", name.what, name.unit, state, was),
			Detail: map[string]any{"key": "trigger:" + k + ":" + now.UTC().Format(time.RFC3339),
				"trigger": k, "was": was, "now": state}}
		ok, err := st.AddAnomaly(ctx, hostID, snapshotID, a, now)
		if err != nil {
			return raised, err
		}
		if ok {
			raised = append(raised, a)
		}
	}
	return raised, st.SetHostTriggers(ctx, hostID, cur.String(), now)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
