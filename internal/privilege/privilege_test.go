// SPDX-License-Identifier: AGPL-3.0-or-later

package privilege

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// forgeRange stores a synced Forge range, as the daily deploy-service sync does.
func (e *ruleEnv) forgeRange() {
	e.t.Helper()
	if err := e.st.ReplaceIPLabels(e.t.Context(), 0, "service:forge", []store.IPLabel{{Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		Kind: store.IPKindAutomation, Name: "Laravel Forge"}}, now); err != nil {
		e.t.Fatal(err)
	}
}

// accessSummaries returns the open privileged_access anomalies' summaries.
func (e *ruleEnv) accessSummaries() []string {
	e.t.Helper()
	var out []string
	for _, a := range e.open("privileged_access") {
		out = append(out, a.Summary)
	}
	return out
}

func TestDeployServiceSessionsExempt(t *testing.T) {
	e := newRuleEnv(t)
	e.forgeRange()
	// Forge from its synced range, as root and as forge: not counted.
	e.report(ev(-time.Hour, "root-ssh", "root", "198.51.100.7"), ev(-time.Hour, "sudo", "forge", "198.51.100.8"))
	if got := e.accessSummaries(); len(got) != 0 {
		t.Fatalf("deploy-service sessions counted: %v", got)
	}
	// The forge account from an unknown address is only a name: it counts,
	// and the address is still unknown.
	if got := e.report(ev(-50*time.Minute, "root-ssh", "forge", "203.0.113.9")); strings.Join(got, ",") != "privilege_unknown_source 203.0.113.9" {
		t.Fatalf("raised %v", got)
	}
	if got := e.accessSummaries(); len(got) != 1 || !strings.Contains(got[0], "1 privileged access ") || !strings.Contains(got[0], "1 root SSH by forge from 203.0.113.9") {
		t.Fatalf("anomalies = %v", got)
	}
}

func TestDeployServiceSessionsCounted(t *testing.T) {
	e := newRuleEnv(t)
	e.forgeRange()
	if err := e.st.SetIPPolicy(t.Context(), "test", store.IPPolicy{OrgID: e.host.OrgID, AllowServices: true, CountServices: true}, now); err != nil {
		t.Fatal(err)
	}
	if got := e.report(ev(-time.Hour, "root-ssh", "root", "198.51.100.7")); len(got) != 0 {
		t.Fatalf("raised %v", got) // known address: no source alert either way
	}
	if got := e.accessSummaries(); len(got) != 1 || !strings.Contains(got[0], "1 root SSH by root from 198.51.100.7") {
		t.Fatalf("anomalies = %v", got)
	}
}

func TestMixedDayCountsNonExempt(t *testing.T) {
	e := newRuleEnv(t)
	e.forgeRange()
	e.label("192.0.2.0/24", store.IPKindStaff)
	if _, err := e.st.CreateWindow(t.Context(), "test", store.Window{OrgSlug: "acme", Host: "web-01",
		Starts: now.Add(-5 * time.Hour), Ends: now.Add(-4 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	e.report(ev(-3*time.Hour, "root-ssh", "root", "198.51.100.7"), ev(-2*time.Hour, "root-ssh", "root", "198.51.100.7"), // Forge
		ev(-time.Hour, "sudo", "chris", "192.0.2.7"),         // staff
		ev(-time.Hour, "sudo", "chris", ""),                  // local
		ev(-50*time.Minute, "su", "forge", "203.0.113.9"),    // the name only
		ev(-270*time.Minute, "sudo", "chris", "203.0.113.1")) // in a window
	got := e.accessSummaries()
	if len(got) != 1 || !strings.HasPrefix(got[0], "3 privileged accesses ") || !strings.Contains(got[0], "2 sudo, 1 su") ||
		strings.Contains(got[0], "198.51.100.7") {
		t.Fatalf("anomalies = %v", got)
	}
}
