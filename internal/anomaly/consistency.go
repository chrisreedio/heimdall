// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

// Reports that don't add up. A fake report has to agree with everything
// the hub has already seen from the host, so these rules compare a report
// with the host's own previous report. They use only what reports already
// contain. See docs/anomaly-signals.md#reports-that-dont-add-up.

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/history"
	"github.com/chrisreedio/heimdall/internal/store"
)

const (
	// UptimeTolerance is how much more uptime may grow than the time that
	// passed between two reports. It is generous, to absorb clock drift,
	// NTP steps and delivery delays.
	UptimeTolerance = 10 * time.Minute

	// A package drop is a fall in the package count between consecutive
	// snapshots of more than DropFraction of the packages, and at least
	// DropMin of them.
	DropFraction = 0.30
	DropMin      = 20
)

// uptimeInconsistent: uptime grew by more than the time that passed between
// two reports, i.e. the boot time (collected_at − uptime) moved earlier.
// Elapsed time is measured by the host's clock (collected_at) and by the
// hub's (received_at), and uptime has to outrun both: a stepped host clock
// or a delayed delivery can't set it off on its own. A smaller uptime is a
// reboot (unexpected_reboot) or a paused VM, never this rule. Unknown or
// zero uptimes (containers, some WSL setups) and imports, whose received
// time is when someone ran `heimdall import`, are skipped.
func uptimeInconsistent(prev, cur store.SnapshotFacts) (store.Anomaly, bool) {
	if prev.UptimeSeconds <= 0 || cur.UptimeSeconds <= 0 || prev.Source != "push" || cur.Source != "push" {
		return store.Anomaly{}, false
	}
	grew := time.Duration(cur.UptimeSeconds-prev.UptimeSeconds) * time.Second
	elapsed := max(cur.ReceivedAt.Sub(prev.ReceivedAt), cur.CollectedAt.Sub(prev.CollectedAt))
	if grew <= 0 || grew-elapsed <= UptimeTolerance {
		return store.Anomaly{}, false
	}
	prevBoot := prev.CollectedAt.Add(-time.Duration(prev.UptimeSeconds) * time.Second)
	curBoot := cur.CollectedAt.Add(-time.Duration(cur.UptimeSeconds) * time.Second)
	return store.Anomaly{Rule: "uptime_inconsistent", Severity: "medium",
		Summary: fmt.Sprintf("Uptime grew %s in %s: the host now claims it booted %s, but its previous report said %s",
			duration(grew), duration(max(elapsed, 0)), usTime(curBoot), usTime(prevBoot)),
		Detail: map[string]any{"key": cur.Key(), "previous_uptime_seconds": prev.UptimeSeconds,
			"uptime_seconds": cur.UptimeSeconds, "elapsed_seconds": int64(elapsed.Seconds()),
			"previous_boot": prevBoot.UTC().Format(time.RFC3339), "boot": curBoot.UTC().Format(time.RFC3339)}}, true
}

// osChanged: the os-release ID changed between two snapshots (e.g. debian
// to ubuntu). A reinstall or an in-place distro migration does that, so a
// maintenance window or patch plan makes it expected (the caller checks).
func osChanged(prev, cur store.SnapshotFacts) (store.Anomaly, bool) {
	if prev.OSID == "" || cur.OSID == "" || prev.OSID == cur.OSID {
		return store.Anomaly{}, false
	}
	return store.Anomaly{Rule: "os_changed", Severity: "medium",
		Summary: fmt.Sprintf("OS changed from %s to %s on the same host: a reinstall, or a report that isn't from this host", prev.OSID, cur.OSID),
		Detail:  map[string]any{"key": prev.OSID + "→" + cur.OSID, "from": prev.OSID, "to": cur.OSID}}, true
}

// collectorDowngrade: the collector's version went backwards and its
// checksum isn't a trusted release. When any release is trusted, an
// untrusted checksum is already collector_changed (high), so this only
// fires on hubs with no trusted collectors (`heimdall collector trust`),
// where nothing else notices. Pre-release suffixes (dev builds) are
// ignored: only the x.y.z core is compared.
func collectorDowngrade(prev, cur store.SnapshotFacts, anyTrusted, trusted bool) (store.Anomaly, bool) {
	if anyTrusted || trusted || !versionOlder(cur.CollectorVer, prev.CollectorVer) {
		return store.Anomaly{}, false
	}
	sum := "it reported no checksum"
	if cur.CollectorSHA256 != "" {
		sum = fmt.Sprintf("its checksum %s… isn't a trusted release", cur.CollectorSHA256[:min(12, len(cur.CollectorSHA256))])
	}
	return store.Anomaly{Rule: "collector_downgrade", Severity: "medium",
		Summary: fmt.Sprintf("Collector went back from %s to %s, and %s", prev.CollectorVer, cur.CollectorVer, sum),
		Detail: map[string]any{"key": prev.CollectorVer + "→" + cur.CollectorVer + ":" + cur.CollectorSHA256,
			"from": prev.CollectorVer, "to": cur.CollectorVer, "sha256": cur.CollectorSHA256}}, true
}

// versionOlder compares collector versions (x.y.z[-pre]) by their x.y.z
// core. Anything unparsable is never older.
func versionOlder(a, b string) bool {
	va, okA := versionCore(a)
	vb, okB := versionCore(b)
	if !okA || !okB {
		return false
	}
	for i := range va {
		if va[i] != vb[i] {
			return va[i] < vb[i]
		}
	}
	return false
}

func versionCore(v string) ([3]int, bool) {
	var out [3]int
	core, _, _ := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// packageDrop: the package count fell by more than DropFraction and at
// least DropMin between two snapshots, as if the inventory had been gutted
// to hide things. It summarises the removals in one anomaly and stands in
// for package_change on that report. An empty list means the package
// check was unavailable, which package_change already reports.
func packageDrop(before, after int, d history.Diff, snapshotID int64) (store.Anomaly, bool) {
	drop := before - after
	if after == 0 || drop < DropMin || float64(drop) <= DropFraction*float64(before) {
		return store.Anomaly{}, false
	}
	return store.Anomaly{Rule: "package_drop", Severity: "high",
		Summary: fmt.Sprintf("Package count fell from %d to %d (%d fewer, %.0f%%) in one report: %s",
			before, after, drop, 100*float64(drop)/float64(before), changeNames(d.Removed, 5)),
		Detail: map[string]any{"key": fmt.Sprint(snapshotID), "before": before, "after": after,
			"removed": changeList(d.Removed), "added": changeList(d.Added)}}, true
}

// inventoryReverted: a new snapshot's inventory is identical to an older
// snapshot's, not the previous one's, and packages changed since the
// previous one: as if an old report were being replayed with fresh
// timestamps. A deliberate rollback, or installing a package and removing
// it again, does the same, so it's low severity.
func inventoryReverted(matchID int64, matchedAt time.Time, d history.Diff, snapshotID int64) store.Anomaly {
	return store.Anomaly{Rule: "inventory_reverted", Severity: "low",
		Summary: fmt.Sprintf("Inventory went back to exactly what it was on %s (%d package change(s) undone). "+
			"Low severity: a rollback does this too, but so does an old report resent with fresh timestamps",
			usTime(matchedAt), len(d.Added)+len(d.Removed)+len(d.Upgraded)+len(d.Downgraded)),
		Detail: map[string]any{"key": fmt.Sprint(snapshotID), "matches_snapshot": matchID,
			"matches_received_at": matchedAt.UTC().Format(time.RFC3339)}}
}

func usTime(t time.Time) string { return t.UTC().Format("Jan 2, 2006 3:04 PM") + " UTC" }

// duration renders a duration as "3d 4h", "2h 5m", "45m" or "under a minute".
func duration(d time.Duration) string {
	if d < time.Minute {
		return "under a minute"
	}
	d = d.Round(time.Minute)
	days, hours, mins := int(d/(24*time.Hour)), int(d%(24*time.Hour)/time.Hour), int(d%time.Hour/time.Minute)
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}
