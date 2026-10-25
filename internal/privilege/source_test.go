// SPDX-License-Identifier: AGPL-3.0-or-later

package privilege

import (
	"crypto/sha256"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/ipinfo"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/store/storetest"
)

var now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

type ruleEnv struct {
	t     *testing.T
	st    *store.Store
	host  store.IngestHost
	rules *Rules
}

func newRuleEnv(t *testing.T) *ruleEnv {
	t.Helper()
	st := storetest.New(t)
	ctx := t.Context()
	st.CreateOrg(ctx, "test", "acme", "")
	st.CreateEnv(ctx, "test", "acme", "prod", "")
	if _, _, err := st.AddHost(ctx, "test", "acme", "prod", "web-01", nil); err != nil {
		t.Fatal(err)
	}
	host, err := st.HostByName(ctx, "acme", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	ips := &ipinfo.Resolver{Store: st, Sources: []ipinfo.Source{ipinfo.SignIns{Store: st}},
		UserHints: []ipinfo.UserHint{func(u string) (ipinfo.Label, bool) {
			return ipinfo.Label{Kind: store.IPKindAutomation, Name: "Deploy bot", Source: "service:deploy"}, u == "deployer"
		}}}
	return &ruleEnv{t: t, st: st, host: host, rules: &Rules{Store: st, Now: func() time.Time { return now }, IPs: ips}}
}

// report runs the rules on fresh events and returns the rules raised.
func (e *ruleEnv) report(evs ...store.PrivilegeEvent) []string {
	e.t.Helper()
	raised, err := e.rules.OnReport(e.t.Context(), e.host, 0, evs, "on", "on")
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, a := range raised {
		if a.Rule != "privileged_access" {
			out = append(out, a.Rule+" "+a.Detail["source"].(string))
		}
	}
	return out
}

func (e *ruleEnv) open(rule string) []store.AnomalyRow {
	e.t.Helper()
	as, err := e.st.Anomalies(e.t.Context(), e.host.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []store.AnomalyRow
	for _, a := range as {
		if a.Rule == rule {
			out = append(out, a)
		}
	}
	return out
}

func (e *ruleEnv) label(prefix, kind string) {
	e.t.Helper()
	if _, err := e.st.AddIPLabel(e.t.Context(), "test", store.IPLabel{OrgID: e.host.OrgID,
		Prefix: netip.MustParsePrefix(prefix), Kind: kind, Name: "Office", Person: "alice"}); err != nil {
		e.t.Fatal(err)
	}
}

func ev(d time.Duration, kind, user, src string) store.PrivilegeEvent {
	return store.PrivilegeEvent{At: now.Add(d).Truncate(time.Second), Kind: kind, User: user, Source: src}
}

func TestUnknownSourceRule(t *testing.T) {
	e := newRuleEnv(t)
	got := e.report(ev(-time.Hour, "sudo", "chris", "203.0.113.9"), ev(-50*time.Minute, "root-ssh", "root", "203.0.113.9"),
		ev(-time.Hour, "sudo", "chris", "?"), ev(-time.Hour, "sudo", "chris", ""), // nothing to resolve
		ev(-time.Hour, "sudo", "chris", "100.101.102.103"), ev(-time.Hour, "sudo", "chris", "10.1.2.3"), // tailnet, private
		ev(-time.Hour, "sudo", "deployer", "198.51.100.20")) // a deploy service's account
	if strings.Join(got, ",") != "privilege_unknown_source 203.0.113.9" {
		t.Fatalf("raised %v", got)
	}
	as := e.open(ruleUnknownSource)
	if len(as) != 1 || as[0].Severity != "high" || !strings.Contains(as[0].Summary, "unknown address, 203.0.113.9") ||
		!strings.Contains(as[0].Summary, "1 sudo, 1 root SSH by chris, root") {
		t.Fatalf("anomalies = %+v", as)
	}
	// More from the same address that day add to it; another address is its own.
	if got := e.report(ev(-10*time.Minute, "sudo", "chris", "203.0.113.9"), ev(-10*time.Minute, "sudo", "chris", "2001:db8::9")); len(got) != 1 {
		t.Fatalf("raised %v", got)
	}
	if as := e.open(ruleUnknownSource); len(as) != 2 || !strings.Contains(as[1].Summary+as[0].Summary, "2 sudo, 1 root SSH") {
		t.Fatalf("anomalies = %+v", as)
	}

	// Labeled, in a synced deploy-service range, or in a window: no alert.
	e.label("192.0.2.0/24", store.IPKindStaff)
	if err := e.st.ReplaceIPLabels(t.Context(), 0, "service:deploy", []store.IPLabel{{Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		Kind: store.IPKindAutomation, Name: "Deploy service"}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CreateWindow(t.Context(), "test", store.Window{OrgSlug: "acme", Host: "web-01",
		Starts: now.Add(-3 * time.Hour), Ends: now.Add(-2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if got := e.report(ev(-time.Hour, "sudo", "chris", "192.0.2.7"), ev(-time.Hour, "sudo", "chris", "198.51.100.7"),
		ev(-150*time.Minute, "sudo", "chris", "203.0.113.50")); len(got) != 0 {
		t.Fatalf("raised %v", got)
	}

	// Someone who can see the org signed in to Heimdall from it: probably them.
	uid, err := e.st.CreateLocalUser(t.Context(), "test", "alice@example.com", "Alice", true, "x", []byte("0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.CreateSession(t.Context(), sha256.Sum256([]byte("tok")), uid, now.Add(-5*time.Hour), now.Add(time.Hour),
		"203.0.113.77", "test"); err != nil {
		t.Fatal(err)
	}
	if got := e.report(ev(-time.Hour, "sudo", "alice", "203.0.113.77")); len(got) != 0 {
		t.Fatalf("raised %v for an address alice signed in from", got)
	}
	v := e.rules.IPs.Resolve(t.Context(), e.host.OrgID, "203.0.113.77", "", now)
	if LabelText(v) != "probably Alice" || v.Best().Source != "signin" {
		t.Errorf("verdict %+v", v)
	}
	// Suppressed: nothing.
	if err := e.st.Suppress(t.Context(), "test", 0, e.host, ruleUnknownSource, now.Add(time.Hour), "travel", now); err != nil {
		t.Fatal(err)
	}
	if got := e.report(ev(-time.Minute, "sudo", "chris", "203.0.113.200")); len(got) != 0 {
		t.Fatalf("suppressed rule raised %v", got)
	}
}

func TestTailnetOnlyPolicy(t *testing.T) {
	e := newRuleEnv(t)
	ctx := t.Context()
	e.label("192.0.2.0/24", store.IPKindStaff)
	e.label("192.0.2.128/25", store.IPKindAutomation) // a manual automation label isn't a synced service
	if err := e.st.ReplaceIPLabels(ctx, 0, "service:deploy", []store.IPLabel{{Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		Kind: store.IPKindAutomation, Name: "Deploy service"}}, now); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetIPPolicy(ctx, "test", store.IPPolicy{OrgID: e.host.OrgID, TailnetOnly: true, AllowServices: true}, now); err != nil {
		t.Fatal(err)
	}
	// Inside a window still counts: the policy is the policy.
	if _, err := e.st.CreateWindow(ctx, "test", store.Window{OrgSlug: "acme", Host: "web-01",
		Starts: now.Add(-3 * time.Hour), Ends: now}); err != nil {
		t.Fatal(err)
	}
	got := e.report(ev(-time.Hour, "sudo", "chris", "192.0.2.7"), // labeled staff, still off the tailnet
		ev(-time.Hour, "sudo", "chris", "192.0.2.200"),    // manual automation
		ev(-time.Hour, "sudo", "deployer", "203.0.113.5"), // a user hint isn't an address range
		ev(-time.Hour, "sudo", "forge", "198.51.100.7"),   // synced deploy service: allowed
		ev(-time.Hour, "root-ssh", "root", "100.64.1.2"), ev(-time.Hour, "sudo", "chris", "fd7a:115c:a1e0::5"),
		ev(-time.Hour, "sudo", "chris", "127.0.0.1"), ev(-time.Hour, "sudo", "chris", "172.16.0.9"),
		ev(-time.Hour, "su", "chris", "bastion.example.com")) // a host name can't be shown to be on the tailnet
	want := "privilege_off_tailnet 192.0.2.200,privilege_off_tailnet 192.0.2.7,privilege_off_tailnet 203.0.113.5,privilege_off_tailnet bastion.example.com"
	if strings.Join(got, ",") != want {
		t.Fatalf("raised %v\nwant %s", got, want)
	}
	if n := len(e.open(ruleUnknownSource)); n != 0 {
		t.Errorf("the policy alert should stand in for the unknown-source one, got %d", n)
	}
	for _, a := range e.open(ruleOffTailnet) {
		if strings.Contains(a.Summary, "192.0.2.7") && !strings.Contains(a.Summary, "192.0.2.7 (alice)") {
			t.Errorf("summary should say who the address is: %s", a.Summary)
		}
	}

	// Without the deploy-service exemption, they alert too.
	if err := e.st.SetIPPolicy(ctx, "test", store.IPPolicy{OrgID: e.host.OrgID, TailnetOnly: true}, now); err != nil {
		t.Fatal(err)
	}
	if got := e.report(ev(-30*time.Minute, "sudo", "forge", "198.51.100.7")); strings.Join(got, ",") != "privilege_off_tailnet 198.51.100.7" {
		t.Fatalf("raised %v", got)
	}
	// Policy off: labeled addresses are fine again.
	if err := e.st.SetIPPolicy(ctx, "test", store.IPPolicy{OrgID: e.host.OrgID, AllowServices: true}, now); err != nil {
		t.Fatal(err)
	}
	if got := e.report(ev(-20*time.Minute, "sudo", "chris", "192.0.2.8")); len(got) != 0 {
		t.Fatalf("raised %v", got)
	}
}

func TestNilResolverUsesLabels(t *testing.T) {
	e := newRuleEnv(t)
	e.rules.IPs = nil
	e.label("192.0.2.0/24", store.IPKindStaff)
	if got := e.report(ev(-time.Hour, "sudo", "chris", "192.0.2.7"), ev(-time.Hour, "sudo", "chris", "203.0.113.1")); strings.Join(got, ",") != "privilege_unknown_source 203.0.113.1" {
		t.Fatalf("raised %v", got)
	}
}
