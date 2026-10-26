// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

var webAlias = regexp.MustCompile(`(d\d+): (firewallEventsAdaptive(?:Groups)?)\(limit: \d+, filter: \{datetime_geq: "([^"]+)"`)

// web answers a web offender query. Zone A (aggregated) has an attacker,
// an allowed request from it, and friendly addresses: Cloudflare's edge,
// a private one, a labelled one and a host's. Zone B (Free) has only raw
// events, some of them not acted on.
func (f *fakeAPI) web(t *testing.T, w http.ResponseWriter, q, zone string, gqlErr func(string)) {
	if !strings.Contains(q, `action_in: [`) || strings.Contains(q, `"allow"`) || strings.Contains(q, `"log"`) {
		t.Errorf("web query doesn't filter actions: %s", q)
	}
	if zone == zoneB && strings.Contains(q, "firewallEventsAdaptiveGroups") {
		gqlErr("zone '" + zoneB + "' does not have access to the path")
		return
	}
	out := map[string]any{}
	var days []string
	for _, m := range webAlias.FindAllStringSubmatch(q, -1) {
		day := m[3][:10]
		days = append(days, day)
		hour := func(h string) string { return day + "T" + h + ":00:00Z" }
		if m[2] == "firewallEventsAdaptiveGroups" {
			g := func(n int, ip, action, h string) map[string]any {
				return map[string]any{"count": n, "dimensions": map[string]any{"clientIP": ip, "action": action, "datetimeHour": hour(h),
					"clientAsn": 64501, "clientASNDescription": "EXAMPLE-NET", "clientCountryName": "NL"}}
			}
			out[m[1]] = []map[string]any{
				g(40, "203.0.113.50", "block", "10"), g(2, "203.0.113.50", "managed_challenge", "14"),
				g(5, "203.0.113.50", "allow", "11"), g(9, "104.16.0.1", "block", "10"), g(3, "10.0.0.5", "block", "10"),
				g(4, "198.51.100.77", "block", "10"), g(2, "203.0.113.10", "block", "10"), g(1, "2001:db8::bad", "jschallenge", "09"),
			}
			continue
		}
		ev := func(ip, action, h string) map[string]any {
			return map[string]any{"clientIP": ip, "action": action, "datetime": hour(h), "clientAsn": "64502", "clientCountryName": "DE"}
		}
		out[m[1]] = []map[string]any{
			ev("203.0.113.60", "block", "12"), ev("203.0.113.60", "block", "08"), ev("203.0.113.60", "log", "09"),
			ev("203.0.113.61", "challengeSolved", "09"), ev("203.0.113.50", "managedChallenge", "13"),
		}
	}
	f.webDays = append(f.webDays, days)
	b, _ := json.Marshal(map[string]any{"data": map[string]any{"viewer": map[string]any{"zones": []any{out}}}})
	w.Write(b)
}

func TestWebOffenders(t *testing.T) {
	f, c := newFake(t)
	st := storetest.New(t)
	ctx := t.Context()
	org, _ := st.CreateOrg(ctx, "test", "acme", "")
	st.CreateEnv(ctx, "test", "acme", "prod", "")
	if _, _, err := st.AddHost(ctx, "test", "acme", "prod", "web-01", nil); err != nil {
		t.Fatal(err)
	}
	h, _ := st.HostByName(ctx, "acme", "web-01")
	st.RecordReportIP(ctx, h.ID, "203.0.113.10") // example.com's records lead here
	st.CreateOrg(ctx, "test", "other", "")
	st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: org.ID, Prefix: netip.MustParsePrefix("198.51.100.77/32"), Kind: store.IPKindStaff, Name: "Home"})

	clock := now
	s := &Syncer{Client: c, Store: st, Security: true, Interval: time.Hour, Now: func() time.Time { return clock }}
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	all, err := st.WebOffenders(ctx, "", now.Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]store.WebOffender{}
	for _, o := range all {
		got[o.IP] = o
	}
	// Friendly addresses and actions that don't count are never stored.
	for _, ip := range []string{"104.16.0.1", "10.0.0.5", "198.51.100.77", "203.0.113.10", "203.0.113.61"} {
		if _, ok := got[ip]; ok {
			t.Errorf("%s stored", ip)
		}
	}
	if len(all) != 3 || all[0].IP != "203.0.113.50" {
		t.Fatalf("offenders %+v", all)
	}
	a := got["203.0.113.50"]
	if a.Events != 86 || a.Actions["block"] != 80 || a.Actions["managed_challenge"] != 6 || a.Actions["allow"] != 0 || a.Days != 2 ||
		strings.Join(a.Zones, ",") != "example.com,example.net" || a.ASN == 0 || a.Country == "" {
		t.Errorf("203.0.113.50 %+v", a)
	}
	if a.First != time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC) || a.Last != time.Date(2026, 10, 24, 14, 59, 59, 0, time.UTC) {
		t.Errorf("first/last %v %v", a.First, a.Last)
	}
	// Zone B fell back to sampled raw events.
	if s := got["203.0.113.60"]; s.Events != 4 || s.Actions["block"] != 4 || s.ASN != 64502 || s.Country != "DE" || s.Zones[0] != "example.net" ||
		s.Last != time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC) {
		t.Errorf("sampled %+v", s)
	}
	if v := got["2001:db8::bad"]; v.Actions["js_challenge"] != 2 || v.ASName != "EXAMPLE-NET" {
		t.Errorf("v6 %+v", v)
	}

	// Org filter: only example.com leads to acme's host.
	acme, _ := st.WebOffenders(ctx, "acme", now.Add(-7*24*time.Hour))
	if len(acme) != 2 || acme[0].IP != "203.0.113.50" || acme[0].Events != 84 || len(acme[0].Zones) != 1 || acme[1].IP != "2001:db8::bad" {
		t.Errorf("acme %+v", acme)
	}
	if other, _ := st.WebOffenders(ctx, "other", now.Add(-7*24*time.Hour)); len(other) != 0 {
		t.Errorf("other org %+v", other)
	}

	// Incremental: yesterday was fetched final, so the next sync asks for
	// today only.
	f.mu.Lock()
	// Zone B's summary was sampled, so its web query went straight to raw
	// events: one query per zone.
	if len(f.webDays) != 2 || len(f.webDays[0]) != 2 || len(f.webDays[1]) != 2 {
		t.Errorf("first sync web queries %v", f.webDays)
	}
	f.webDays = nil
	f.mu.Unlock()
	st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: org.ID, Prefix: netip.MustParsePrefix("2001:db8::/64"), Kind: store.IPKindInfra, Name: "Lab"})
	clock = now.Add(time.Hour)
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if len(f.webDays) != 2 || len(f.webDays[0]) != 1 || f.webDays[0][0] != "2026-10-24" || len(f.webDays[1]) != 1 {
		t.Errorf("second sync web queries %v", f.webDays)
	}
	f.mu.Unlock()
	all, _ = st.WebOffenders(ctx, "", now.Add(-7*24*time.Hour))
	if len(all) != 2 || all[0].Events != 86 {
		t.Errorf("after refetch (and a newly known address dropped) %+v", all)
	}
}

func TestWebPruneAndDays(t *testing.T) {
	st := storetest.New(t)
	ctx := t.Context()
	if err := st.ReplaceCloudflareZones(ctx, []store.CloudflareZone{{ID: zoneA, Name: "example.com"}}, nil, now); err != nil {
		t.Fatal(err)
	}
	row := func(ip string, at time.Time) store.WebOffenderDay {
		return store.WebOffenderDay{IP: ip, Events: 3, Actions: map[string]int{"block": 3}, First: at, Last: at}
	}
	old := now.AddDate(0, 0, -40)
	if err := st.RecordWebOffenders(ctx, zoneA, []store.WebDay{{Day: old.Format(time.DateOnly), Final: true, Rows: []store.WebOffenderDay{row("203.0.113.70", old)}}}, old); err != nil {
		t.Fatal(err)
	}
	if o, _ := st.WebOffenders(ctx, "", time.Time{}); len(o) != 1 {
		t.Fatalf("before prune %+v", o)
	}
	day := now.Format(time.DateOnly)
	if err := st.RecordWebOffenders(ctx, zoneA, []store.WebDay{{Day: day, Rows: []store.WebOffenderDay{row("203.0.113.71", now)}}}, now); err != nil {
		t.Fatal(err)
	}
	// A refetched day replaces its rows instead of adding to them.
	if err := st.RecordWebOffenders(ctx, zoneA, []store.WebDay{{Day: day, Rows: []store.WebOffenderDay{row("203.0.113.71", now)}}}, now); err != nil {
		t.Fatal(err)
	}
	o, _ := st.WebOffenders(ctx, "", time.Time{})
	if len(o) != 1 || o[0].IP != "203.0.113.71" || o[0].Events != 3 {
		t.Errorf("after prune %+v", o)
	}
	if final, _ := st.WebFinalDays(ctx, zoneA, "2000-01-01"); len(final) != 0 {
		t.Errorf("old final day kept, or today final: %v", final)
	}
}

// A zone without the aggregated dataset falls back to sampled raw events
// even when its summary didn't say so.
func TestWebSampledFallback(t *testing.T) {
	f, c := newFake(t)
	state, days, err := c.webOffenders(t.Context(), zoneB, webDays(now, nil), false)
	if err != nil || state != store.CloudflareSecuritySampled || len(days) != 2 || !days[1].Sampled || len(days[1].Rows) != 2 {
		t.Fatalf("%s %+v %v", state, days, err)
	}
	if r := days[1].Rows[1]; r.IP != "203.0.113.60" || r.Events != 2 || r.Actions["block"] != 2 {
		t.Errorf("row %+v", r)
	}
	if len(f.webDays) != 1 { // the refused aggregated query isn't answered
		t.Errorf("queries %v", f.webDays)
	}
	if state, _, err := c.webOffenders(t.Context(), zoneC, webDays(now, nil), false); state != store.CloudflareSecurityPermission || !IsPermission(err) {
		t.Errorf("zone C: %s %v", state, err)
	}
}

func TestWebDaysAndActions(t *testing.T) {
	// Just after midnight yesterday isn't settled, so it isn't final yet.
	ds := webDays(time.Date(2026, 10, 24, 0, 30, 0, 0, time.UTC), nil)
	if len(ds) != 2 || ds[0].day != "2026-10-23" || ds[0].final || ds[1].final || !ds[1].to.Equal(time.Date(2026, 10, 24, 0, 30, 0, 0, time.UTC)) {
		t.Errorf("days %+v", ds)
	}
	ds = webDays(time.Date(2026, 10, 24, 1, 30, 0, 0, time.UTC), map[string]bool{})
	if !ds[0].final {
		t.Errorf("settled yesterday not final: %+v", ds)
	}
	if ds = webDays(now, map[string]bool{"2026-10-23": true}); len(ds) != 1 || ds[0].day != "2026-10-24" {
		t.Errorf("final day refetched: %+v", ds)
	}
	for in, want := range map[string]string{"block": "block", "managedChallenge": "managed_challenge", "jschallenge": "js_challenge",
		"connectionClose": "connection_close", "allow": "", "skip": "", "log": "", "bypass": "", "challengeSolved": "",
		"managedChallengeBypassed": "", "unknown": ""} {
		if got, _ := ActedAction(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}
