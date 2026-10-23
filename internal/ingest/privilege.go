// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/privilege"
	"github.com/chrisreedio/heimdall/internal/store"
)

// The opt-in privilege watch (install.sh --watch-privilege) reports in
// headers, not snapshot fields, so collectors and hubs of different
// versions still accept each other's requests. Bad values are dropped;
// they never fail the push.
const (
	// PrivilegeHeader: "v1 <unix-ts>:<kind>[:<user>],..." (the last 7 days).
	PrivilegeHeader = "X-Heimdall-Privilege"
	// PrivilegeWatchHeader: on, off or partial.
	PrivilegeWatchHeader = "X-Heimdall-Privilege-Watch"

	maxPrivilegeHeader = 12 << 10
	maxPrivilegeEvents = 200
	// Events older than this, or further in the future than MaxSkew, are dropped.
	maxPrivilegeAge = 8 * 24 * time.Hour
)

var privilegeUser = regexp.MustCompile(`^(?:[a-z_][a-z0-9_.-]{0,31}|\?)$`)

// parsePrivilege parses a PrivilegeHeader value. A malformed header gives
// nil; a malformed or out-of-range entry in a good header is skipped.
func parsePrivilege(v string, now time.Time) []store.PrivilegeEvent {
	list, ok := strings.CutPrefix(v, "v1 ")
	if !ok || len(v) > maxPrivilegeHeader {
		return nil
	}
	var out []store.PrivilegeEvent
	seen := map[store.PrivilegeEvent]bool{}
	for entry := range strings.SplitSeq(strings.TrimSpace(list), ",") {
		if len(out) == maxPrivilegeEvents {
			break
		}
		parts := strings.Split(entry, ":")
		if len(parts) < 2 || len(parts) > 3 || len(parts[0]) > 12 {
			continue
		}
		sec, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || sec <= 0 {
			continue
		}
		at := time.Unix(sec, 0).UTC()
		if at.Before(now.Add(-maxPrivilegeAge)) || at.After(now.Add(MaxSkew)) {
			continue
		}
		ev := store.PrivilegeEvent{At: at, Kind: parts[1]}
		switch ev.Kind {
		case "sudo", "su", "root-ssh":
		default:
			continue
		}
		if len(parts) == 3 {
			if !privilegeUser.MatchString(parts[2]) {
				continue
			}
			ev.User = parts[2]
		}
		if !seen[ev] {
			seen[ev] = true
			out = append(out, ev)
		}
	}
	return out
}

// parsePrivilegeWatch returns on, off or partial, or "" for anything else.
func parsePrivilegeWatch(v string) string {
	switch v = strings.TrimSpace(v); v {
	case "on", "off", "partial":
		return v
	}
	return ""
}

// onlyHeader returns a header's value if it was sent exactly once.
func onlyHeader(r *http.Request, name string) string {
	if vs := r.Header.Values(name); len(vs) == 1 {
		return vs[0]
	}
	return ""
}

// recordPrivilege stores what a push's privilege headers reported and runs
// the privilege watch rules. Failures are logged, never returned: the
// snapshot is already stored.
func (h *Handler) recordPrivilege(ctx context.Context, log *slog.Logger, host store.IngestHost, snapshotID int64, r *http.Request) {
	now := h.acc.Now()
	events := parsePrivilege(onlyHeader(r, PrivilegeHeader), now)
	state := parsePrivilegeWatch(onlyHeader(r, PrivilegeWatchHeader))
	if len(events) == 0 && state == "" {
		return
	}
	fresh, prev, err := h.store.RecordPrivilege(ctx, host.ID, events, state, now)
	if err != nil {
		log.Error("could not store privilege events", "err", err)
		return
	}
	e := &privilege.Rules{Store: h.store, Now: h.acc.Now}
	raised, err := e.OnReport(ctx, host, snapshotID, fresh, prev, state)
	if err != nil {
		log.Error("privilege watch rules failed", "err", err)
	}
	for _, a := range raised {
		log.Warn("anomaly", "rule", a.Rule, "severity", a.Severity, "summary", a.Summary)
	}
}
