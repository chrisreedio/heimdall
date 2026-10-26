// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"net/netip"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

func banAlertFleet(t *testing.T) (*Engine, store.IngestHost, *time.Time) {
	t.Helper()
	st := storetest.New(t)
	ctx := t.Context()
	st.CreateOrg(ctx, "test", "acme", "")
	st.CreateEnv(ctx, "test", "acme", "prod", "")
	if _, _, err := st.AddHost(ctx, "test", "acme", "prod", "web-01", nil); err != nil {
		t.Fatal(err)
	}
	h, _ := st.HostByName(ctx, "acme", "web-01")
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	return &Engine{Store: st, Now: func() time.Time { return now }}, h, &now
}

func openRules(t *testing.T, e *Engine, rule string) []store.AnomalyView {
	t.Helper()
	all, err := e.Store.OpenAnomalies(t.Context(), store.AllScope)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AnomalyView
	for _, a := range all {
		if a.Rule == rule {
			out = append(out, a)
		}
	}
	return out
}

func TestLoginThenSucceeded(t *testing.T) {
	e, h, now := banAlertFleet(t)
	ctx := t.Context()
	at := now.Add(-time.Hour)
	row := func(ip string, ok bool) store.LoginFailure {
		return store.LoginFailure{IP: ip, Failures: 7, Usernames: 2, First: at.Add(-time.Minute), Last: at, Succeeded: ok}
	}
	if err := e.Store.RecordLogins(ctx, h.ID, store.LoginReport{Source: "journal", Days: []store.LoginDay{{
		Day: at.Format(time.DateOnly), Failures: 35, Addresses: 5,
		Rows: []store.LoginFailure{
			row("203.0.113.50", true),  // unknown: fires
			row("203.0.113.51", false), // never got in
			row("10.0.0.5", true),      // private
			row("198.51.100.7", true),  // labelled staff
			row("104.16.0.1", true),    // Cloudflare's edge
		}}}}, *now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Store.AddIPLabel(ctx, "test", store.IPLabel{OrgID: h.OrgID, Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		Kind: store.IPKindStaff, Name: "Office"}); err != nil {
		t.Fatal(err)
	}
	ips := &ipinfo.Resolver{Store: e.Store}
	n, err := e.CheckLoginSucceeded(ctx, ips, nil)
	if err != nil || n != 1 {
		t.Fatalf("raised %d, %v", n, err)
	}
	got := openRules(t, e, "login_then_succeeded")
	if len(got) != 1 || got[0].Severity != "high" || got[0].Host.ID != h.ID {
		t.Fatalf("%+v", got)
	}
	// Once, even after it's acknowledged.
	if err := e.Store.AckAnomaly(ctx, "test", 0, got[0].ID, "checked: an attacker", *now); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.CheckLoginSucceeded(ctx, ips, nil); n != 0 {
		t.Errorf("raised again: %d", n)
	}
}

func TestSurfaceAlerts(t *testing.T) {
	e, h, now := banAlertFleet(t)
	ctx := t.Context()
	zone := "cccccccccccccccccccccccccccccccc"
	e.Store.RecordReportIP(ctx, h.ID, "203.0.113.10")
	rec := func(name, typ, content string, proxied bool) store.CloudflareRecord {
		return store.CloudflareRecord{Name: name, Type: typ, Content: content, Proxied: proxied, TTL: 1}
	}
	if err := e.Store.ReplaceCloudflareZones(ctx, []store.CloudflareZone{{ID: zone, Name: "example.com", Status: "active"}},
		map[string][]store.CloudflareRecord{zone: {
			rec("www.example.com", "A", "203.0.113.10", false),
			rec("elsewhere.example.com", "A", "203.0.113.199", false),
			// A name that leads to web-01 and also CNAMEs to a target that's
			// gone, on a domain nobody holds now.
			rec("shop.example.com", "A", "203.0.113.10", true),
			rec("shop.example.com", "CNAME", "gone.example.org", true),
		}}, *now); err != nil {
		t.Fatal(err)
	}
	if err := e.Store.PutCNAMEChecks(ctx, []store.CNAMECheck{{Target: "gone.example.org", Status: store.CNAMEUnregistered, Note: "example.org isn't registered"}}, *now); err != nil {
		t.Fatal(err)
	}
	if err := e.Store.AddSurfaceChanges(ctx, []store.SurfaceChange{
		{At: now.Add(-time.Hour), ZoneID: zone, Zone: "example.com", Name: "www.example.com", Kind: store.SurfaceUnproxied},
		{At: now.Add(-time.Hour), ZoneID: zone, Zone: "example.com", Name: "elsewhere.example.com", Kind: store.SurfaceUnproxied},
		{At: now.Add(-time.Hour), ZoneID: zone, Zone: "example.com", Name: "www.example.com", Kind: store.SurfaceTarget},
	}, *now); err != nil {
		t.Fatal(err)
	}
	n, err := e.CheckSurface(ctx)
	if err != nil || n != 2 {
		t.Fatalf("raised %d, %v", n, err)
	}
	if got := openRules(t, e, "dns_unproxied"); len(got) != 1 || got[0].Severity != "medium" {
		t.Errorf("unproxied: %+v", got)
	}
	if got := openRules(t, e, "cname_takeover"); len(got) != 1 || got[0].Severity != "high" {
		t.Errorf("takeover: %+v", got)
	}
	if n, _ := e.CheckSurface(ctx); n != 0 {
		t.Errorf("raised again: %d", n)
	}
}
