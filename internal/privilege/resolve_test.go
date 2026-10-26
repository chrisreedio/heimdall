// SPDX-License-Identifier: AGPL-3.0-or-later

package privilege

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/store"
)

func (e *ruleEnv) resolveKnown() int {
	e.t.Helper()
	n, err := ResolveKnown(e.t.Context(), e.st, e.rules.IPs, now)
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *ruleEnv) closed() []store.ClosedAnomaly {
	e.t.Helper()
	cs, err := e.st.ClosedAnomalies(e.t.Context(), store.AllScope, now.Add(-time.Hour), 100)
	if err != nil {
		e.t.Fatal(err)
	}
	return cs
}

func TestResolveKnownOnLabel(t *testing.T) {
	e := newRuleEnv(t)
	ctx := t.Context()
	if got := e.report(ev(-time.Hour, "sudo", "chris", "203.0.113.4"),
		ev(-time.Hour, "sudo", "deployer", "203.0.113.60")); len(got) != 2 { // a deploy account, from elsewhere
		t.Fatalf("raised %v", got)
	}
	if n := e.resolveKnown(); n != 0 {
		t.Fatalf("closed %d with nothing known", n)
	}
	if _, err := e.st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: e.host.OrgID, Prefix: netip.MustParsePrefix("203.0.113.4/32"),
		Kind: store.IPKindStaff, Name: "Alice home", Person: "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	if n := e.resolveKnown(); n != 1 {
		t.Fatalf("closed %d, want 1", n)
	}
	// Only the account is recognized at 203.0.113.60: still unknown.
	if open := e.open(ruleUnknownSource); len(open) != 1 || !strings.Contains(open[0].Summary, "203.0.113.60") {
		t.Fatalf("open = %+v", open)
	}
	cs := e.closed()
	if len(cs) != 1 || !cs[0].Auto || cs[0].By != "" ||
		cs[0].Note != "resolved: 203.0.113.4 is now known (staff: alice@example.com, label 'Alice home')" {
		t.Fatalf("closed = %+v", cs)
	}
	if at, err := e.st.LastAuditAt(ctx, "anomaly.resolve"); err != nil || at.IsZero() {
		t.Errorf("not audited: %v %v", at, err)
	}
	// Later sessions that day from it raise nothing new, and running again
	// changes nothing.
	if got := e.report(ev(-10*time.Minute, "root-ssh", "root", "203.0.113.4")); len(got) != 0 {
		t.Fatalf("raised %v after the address became known", got)
	}
	if n := e.resolveKnown(); n != 0 || len(e.open(ruleUnknownSource)) != 1 {
		t.Fatalf("second run closed %d", n)
	}
}

func TestResolveKnownLeavesOffTailnet(t *testing.T) {
	e := newRuleEnv(t)
	ctx := t.Context()
	if err := e.st.SetIPPolicy(ctx, "test", store.IPPolicy{OrgID: e.host.OrgID, TailnetOnly: true}, now); err != nil {
		t.Fatal(err)
	}
	if got := e.report(ev(-time.Hour, "sudo", "chris", "203.0.113.9")); strings.Join(got, ",") != "privilege_off_tailnet 203.0.113.9" {
		t.Fatalf("raised %v", got)
	}
	e.label("203.0.113.0/24", store.IPKindStaff)
	if n := e.resolveKnown(); n != 0 || len(e.open(ruleOffTailnet)) != 1 {
		t.Fatalf("closed %d: a label doesn't make an address allowed", n)
	}
}

// syncer is a synced source that labels an address when it runs.
type syncer struct {
	st    *store.Store
	label store.IPLabel
}

func (syncer) Name() string         { return "tailscale" }
func (syncer) Every() time.Duration { return time.Hour }
func (s syncer) Sync(ctx context.Context) error {
	return s.st.ReplaceIPLabels(ctx, 0, "tailscale", []store.IPLabel{s.label}, now)
}

func TestResolveKnownAfterSync(t *testing.T) {
	e := newRuleEnv(t)
	if got := e.report(ev(-time.Hour, "sudo", "chris", "198.51.100.20")); len(got) != 1 {
		t.Fatalf("raised %v", got)
	}
	sy := ipinfo.Then(syncer{e.st, store.IPLabel{Prefix: netip.MustParsePrefix("198.51.100.20/32"), Kind: store.IPKindStaff,
		Name: "laptop-01", Person: "alice@example.com"}}, func(ctx context.Context) {
		if _, err := ResolveKnown(ctx, e.st, e.rules.IPs, now); err != nil {
			t.Error(err)
		}
	})
	if sy.Name() != "tailscale" {
		t.Errorf("name %q", sy.Name())
	}
	if err := sy.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if cs := e.closed(); len(cs) != 1 || cs[0].Note != "resolved: 198.51.100.20 is now known (staff: alice@example.com, 'laptop-01' from tailscale)" {
		t.Fatalf("closed = %+v", cs)
	}
}

// An office address from a Cloudflare IP list counts as known, like staff:
// the alert closes, later sessions raise nothing, and the summary names
// the list and the item's comment.
func TestResolveKnownOfficeList(t *testing.T) {
	e := newRuleEnv(t)
	ctx := t.Context()
	if got := e.report(ev(-time.Hour, "sudo", "chris", "203.0.113.4")); len(got) != 1 {
		t.Fatalf("raised %v", got)
	}
	if err := e.st.ReplaceIPLabels(ctx, 0, store.IPListSource("offices01"), []store.IPLabel{{Prefix: netip.MustParsePrefix("203.0.113.0/24"),
		Kind: store.IPKindOffice, Name: "offices", Person: "Alice Example - Developer"}}, now); err != nil {
		t.Fatal(err)
	}
	if n := e.resolveKnown(); n != 1 {
		t.Fatalf("closed %d, want 1", n)
	}
	if cs := e.closed(); len(cs) != 1 || cs[0].Note != "resolved: 203.0.113.4 is now known (office: Alice Example - Developer, Cloudflare IP list 'offices')" {
		t.Fatalf("closed = %+v", cs)
	}
	if got := e.report(ev(-10*time.Minute, "root-ssh", "root", "203.0.113.9")); len(got) != 0 {
		t.Fatalf("raised %v from an office address", got)
	}
	v := e.rules.IPs.Resolve(ctx, e.host.OrgID, "203.0.113.9", "", now)
	if got := LabelText(v); got != "offices · Alice Example - Developer" {
		t.Errorf("label text %q", got)
	}
	// A manual office label without a list is known too.
	e.label("198.51.100.0/24", store.IPKindOffice)
	if got := e.report(ev(-5*time.Minute, "sudo", "chris", "198.51.100.7")); len(got) != 0 {
		t.Fatalf("raised %v from a manual office range", got)
	}
}
