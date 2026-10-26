// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

const (
	zoneA     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // example.com, Pro: aggregated events
	zoneB     = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" // example.net, Free: raw events only
	zoneC     = "cccccccccccccccccccccccccccccccc" // example.org, no analytics permission
	testToken = "test-token-not-real-0123456789"
)

var now = time.Date(2026, 10, 24, 15, 30, 0, 0, time.UTC)

// fakeAPI is a stand-in for the Cloudflare API: two pages of zones, two
// pages of records for one zone, GraphQL answers that vary by plan, and
// Radar.
type fakeAPI struct {
	mu        sync.Mutex
	failZones bool
	failDNS   bool
	radarDeny bool
	radarHits int
	queries   []string
}

func (f *fakeAPI) handler(t *testing.T) http.Handler {
	alias := regexp.MustCompile(`(\w+): firewallEventsAdaptiveGroups\(`)
	env := func(w http.ResponseWriter, result any, page, pages int) {
		b, _ := json.Marshal(map[string]any{"success": true, "errors": []any{}, "result": result,
			"result_info": map[string]int{"page": page, "total_pages": pages}})
		w.Write(b)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)
			return
		}
		page := r.URL.Query().Get("page")
		switch {
		case r.URL.Path == "/user/tokens/verify":
			env(w, map[string]string{"id": "abc", "status": "active"}, 1, 1)
		case r.URL.Path == "/zones":
			if f.failZones {
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, `{"success":false,"errors":[{"code":1001,"message":"try later"}]}`)
				return
			}
			if page == "1" {
				env(w, []map[string]any{{"id": zoneA, "name": "example.com", "status": "active", "plan": map[string]string{"name": "Pro Website"}}}, 1, 2)
			} else {
				env(w, []map[string]any{
					{"id": zoneB, "name": "Example.net", "status": "active", "plan": map[string]string{"name": "Free Website"}},
					{"id": zoneC, "name": "example.org", "status": "pending", "plan": map[string]string{"name": "Free Website"}},
				}, 2, 2)
			}
		case r.URL.Path == "/zones/"+zoneA+"/dns_records":
			if f.failDNS {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			if page == "1" {
				env(w, []Record{
					{Name: "example.com", Type: "A", Content: "203.0.113.10", Proxied: true, TTL: 1},
					{Name: "origin.example.com", Type: "A", Content: "203.0.113.10", TTL: 300},
					{Name: "mail.example.com", Type: "MX", Content: "mx.example.com"},
				}, 1, 2)
			} else {
				env(w, []Record{
					{Name: "www.example.com", Type: "CNAME", Content: "origin.example.com", TTL: 1},
					{Name: "old.example.com", Type: "A", Content: "203.0.113.199", Proxied: true, TTL: 1},
					{Name: "office.example.com", Type: "A", Content: "198.51.100.5", TTL: 1},
				}, 2, 2)
			}
		case strings.HasPrefix(r.URL.Path, "/zones/") && strings.HasSuffix(r.URL.Path, "/dns_records"):
			env(w, []Record{{Name: "example.net", Type: "AAAA", Content: "2001:db8::1", Proxied: true, TTL: 1}}, 1, 1)
		case r.URL.Path == "/radar/entities/asns/ip":
			f.radarHits++
			if f.radarDeny {
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)
				return
			}
			env(w, map[string]any{"asn": map[string]any{"asn": 64500, "name": "EXAMPLE-AS", "orgName": "Example ISP", "country": "US"}}, 1, 1)
		case r.URL.Path == "/graphql" && r.Method == http.MethodPost:
			var req struct{ Query string }
			json.NewDecoder(r.Body).Decode(&req)
			q := req.Query
			f.queries = append(f.queries, q)
			gqlErr := func(msg string) { fmt.Fprintf(w, `{"data":null,"errors":[{"message":%q}]}`, msg) }
			zone := zoneA
			for _, z := range []string{zoneB, zoneC} {
				if strings.Contains(q, z) {
					zone = z
				}
			}
			switch {
			case zone == zoneC:
				gqlErr("not authorized for that account")
			case strings.Contains(q, "settings"):
				enabled := zone == zoneA || !strings.Contains(q, "firewallEventsAdaptiveGroups")
				fmt.Fprintf(w, `{"data":{"viewer":{"zones":[{"settings":{"%s":{"enabled":%v,"maxDuration":86400,"notOlderThan":2678400}}}]}},"errors":null}`,
					regexp.MustCompile(`settings \{ (\w+)`).FindStringSubmatch(q)[1], enabled)
			case strings.Contains(q, "httpRequests1hGroups"):
				io.WriteString(w, `{"data":{"viewer":{"zones":[{"req":[
					{"dimensions":{"datetime":"2026-10-24T14:00:00Z"},"sum":{"requests":1000}},
					{"dimensions":{"datetime":"2026-10-23T10:00:00Z"},"sum":{"requests":500}}]}]}}}`)
			case strings.Contains(q, "firewallEventsAdaptiveGroups") && zone == zoneB:
				gqlErr("zone '" + zoneB + "' does not have access to the path")
			case strings.Contains(q, "firewallEventsAdaptiveGroups"):
				out := map[string]any{}
				for _, m := range alias.FindAllStringSubmatch(q, -1) {
					a := m[1]
					switch {
					case strings.HasSuffix(a, "_total"):
						out[a] = []map[string]any{{"count": 7}}
					case strings.HasSuffix(a, "_action"):
						out[a] = []map[string]any{{"count": 5, "dimensions": map[string]any{"action": "block"}},
							{"count": 2, "dimensions": map[string]any{"action": "managed_challenge"}}}
					case strings.HasSuffix(a, "_country"):
						out[a] = []map[string]any{{"count": 7, "dimensions": map[string]any{"clientCountryName": "NL"}}}
					case strings.HasSuffix(a, "_asn"):
						out[a] = []map[string]any{{"count": 7, "dimensions": map[string]any{"clientAsn": 64501}}}
					case strings.HasSuffix(a, "_path"):
						out[a] = []map[string]any{{"count": 7, "dimensions": map[string]any{"clientRequestPath": "/wp-login.php"}}}
					}
				}
				b, _ := json.Marshal(map[string]any{"data": map[string]any{"viewer": map[string]any{"zones": []any{out}}}})
				w.Write(b)
			case strings.Contains(q, "firewallEventsAdaptive("):
				if strings.Contains(q, "clientIP") {
					t.Error("raw events query asks for client IPs")
				}
				io.WriteString(w, `{"data":{"viewer":{"zones":[{"ev":[
					{"action":"block","clientAsn":"64502","clientCountryName":"DE","clientRequestPath":"/.env"},
					{"action":"block","clientAsn":"64502","clientCountryName":"DE","clientRequestPath":"/.env"},
					{"action":"challenge","clientAsn":"64503","clientCountryName":"US","clientRequestPath":"/"}]}]}}}`)
			default:
				gqlErr("unknown field")
			}
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func newFake(t *testing.T) (*fakeAPI, *Client) {
	f := &fakeAPI{}
	srv := httptest.NewTLSServer(f.handler(t))
	t.Cleanup(srv.Close)
	return f, &Client{Base: srv.URL, Token: testToken, HTTP: srv.Client()}
}

func TestClientPaginationAndErrors(t *testing.T) {
	_, c := newFake(t)
	ctx := t.Context()
	tok, err := c.VerifyToken(ctx)
	if err != nil || tok.Status != "active" {
		t.Fatalf("verify: %+v %v", tok, err)
	}
	zs, err := c.Zones(ctx)
	if err != nil || len(zs) != 3 || zs[0].Plan.Name != "Pro Website" || zs[1].ID != zoneB {
		t.Fatalf("zones: %+v %v", zs, err)
	}
	rs, err := c.DNSRecords(ctx, zoneA)
	if err != nil || len(rs) != 5 { // MX dropped, both pages read
		t.Fatalf("records: %+v %v", rs, err)
	}
	if _, err := c.DNSRecords(ctx, "../etc"); err == nil {
		t.Error("bad zone ID accepted")
	}
	bad := *c
	bad.Token = "wrong-token-0123456789"
	_, err = bad.Zones(ctx)
	if !IsPermission(err) || strings.Contains(err.Error(), "wrong-token") {
		t.Errorf("bad token: %v", err)
	}
	if d, err := c.DatasetSettings(ctx, zoneB, "firewallEventsAdaptiveGroups"); err != nil || d.Enabled {
		t.Errorf("settings zone B: %+v %v", d, err)
	}
	if d, err := c.DatasetSettings(ctx, zoneA, "firewallEventsAdaptiveGroups"); err != nil || !d.Enabled || d.NotOlderThan != 2678400 {
		t.Errorf("settings zone A: %+v %v", d, err)
	}
	if _, err := c.DatasetSettings(ctx, zoneC, "firewallEventsAdaptive"); !IsPermission(err) {
		t.Errorf("settings zone C: %v", err)
	}
}

func TestSecurityByPlan(t *testing.T) {
	_, c := newFake(t)
	ctx := t.Context()
	state, note, sum, days, err := c.Security(ctx, zoneA, now)
	if err != nil || note != "" || state != store.CloudflareSecurityOK || sum.Total != 7 || len(sum.Actions) != 2 || sum.Actions[0].Key != "block" ||
		sum.ASNs[0].Key != "AS64501" || sum.Paths[0].Key != "/wp-login.php" || sum.Countries[0].Key != "NL" || sum.Requests != 1000 {
		t.Fatalf("zone A: %s %+v %v", state, sum, err)
	}
	byDay := map[string]int64{}
	for _, d := range days {
		if d.Dim == "total" || d.Dim == "requests" {
			byDay[d.Day+"/"+d.Dim] = d.Count
		}
	}
	if byDay["2026-10-24/total"] != 7 || byDay["2026-10-23/total"] != 7 || byDay["2026-10-23/requests"] != 500 || byDay["2026-10-24/requests"] != 1000 {
		t.Errorf("days: %v", byDay)
	}
	// Free plan: falls back to sampled raw events, counts only.
	state, note, sum, days, err = c.Security(ctx, zoneB, now)
	if err != nil || state != store.CloudflareSecuritySampled || !sum.Sampled || sum.Total != 3 || sum.Actions[0] != (Count{"block", 2}) ||
		sum.ASNs[0].Key != "AS64502" || len(days) != 0 || !strings.Contains(note, "sampled") {
		t.Fatalf("zone B: %s %+v %v", state, sum, err)
	}
	// No analytics permission: a calm state, and an error to log.
	state, note, _, _, err = c.Security(ctx, zoneC, now)
	if state != store.CloudflareSecurityPermission || err == nil || !strings.Contains(note, "Analytics") {
		t.Errorf("zone C: %s %q %v", state, note, err)
	}
}

func TestClassify(t *testing.T) {
	for msg, want := range map[string]string{
		"zone 'x' does not have access to the path": "plan",
		"not authorized for that account":           "permission",
		"cannot request data older than 2678400s":   "",
	} {
		if got := classify(msg); got != want {
			t.Errorf("%q: %q, want %q", msg, got, want)
		}
	}
}

func TestSyncerKeepsLastGood(t *testing.T) {
	f, c := newFake(t)
	st := storetest.New(t)
	ctx := t.Context()
	s := &Syncer{Client: c, Store: st, Security: true, Interval: time.Hour, Now: func() time.Time { return now }}
	// Zone C's missing analytics permission is a state, not a sync error.
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	zs, _ := st.CloudflareZones(ctx)
	if len(zs) != 3 || zs[0].Name != "example.com" || zs[1].Name != "example.net" {
		t.Fatalf("zones %+v", zs)
	}
	if zs[0].Security != store.CloudflareSecurityOK || zs[1].Security != store.CloudflareSecuritySampled || zs[2].Security != store.CloudflareSecurityPermission {
		t.Errorf("security states: %s %s %s", zs[0].Security, zs[1].Security, zs[2].Security)
	}
	if sum := ParseSummary(zs[0].Last24); sum.Total != 7 {
		t.Errorf("last24 %+v", sum)
	}
	recs, _ := st.CloudflareRecords(ctx)
	if len(recs) != 7 {
		t.Fatalf("records %d", len(recs))
	}
	days, _ := st.CloudflareDailyCounts(ctx, zoneA, "2026-10-01")
	if len(days) == 0 {
		t.Error("no daily counts")
	}

	// A failing DNS read keeps the zone's old records; a failing zone list
	// changes nothing.
	f.mu.Lock()
	f.failDNS = true
	f.mu.Unlock()
	if err := s.Sync(ctx); err == nil {
		t.Error("DNS failure not reported")
	}
	if recs, _ := st.CloudflareRecords(ctx); len(recs) != 7 {
		t.Errorf("records after DNS failure: %d", len(recs))
	}
	f.mu.Lock()
	f.failZones = true
	f.mu.Unlock()
	if err := s.Sync(ctx); err == nil {
		t.Error("zone list failure not reported")
	}
	if zs, _ := st.CloudflareZones(ctx); len(zs) != 3 {
		t.Errorf("zones after failure: %d", len(zs))
	}
	syncs, _ := st.CloudflareSyncs(ctx)
	if syncs["zones"].Error == "" || strings.Contains(syncs["zones"].Error, testToken) {
		t.Errorf("sync record %+v", syncs["zones"])
	}

	// Only the configured zones, and others go away.
	f.mu.Lock()
	f.failZones, f.failDNS = false, false
	f.mu.Unlock()
	s.Zones, s.Security = []string{"example.net"}, false
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if zs, _ := st.CloudflareZones(ctx); len(zs) != 1 || zs[0].ID != zoneB {
		t.Errorf("filtered zones %+v", zs)
	}
	if recs, _ := st.CloudflareRecords(ctx); len(recs) != 1 {
		t.Errorf("records of dropped zones kept: %d", len(recs))
	}
}

func TestEdge(t *testing.T) {
	v4, v6 := "173.245.48.0/20\n103.21.244.0/22\n104.16.0.0/13", "2400:cb00::/32\n2606:4700::/32\n2a06:98c0::/29\n"
	bad := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case bad:
			io.WriteString(w, "<html>oops</html>")
		case r.URL.Path == "/ips-v4":
			io.WriteString(w, v4)
		default:
			io.WriteString(w, v6)
		}
	}))
	defer srv.Close()
	st := storetest.New(t)
	ctx := t.Context()
	e := NewEdge()
	if !e.Contains(netip.MustParseAddr("104.16.1.1")) || e.Contains(netip.MustParseAddr("203.0.113.1")) || (*Edge)(nil).Contains(netip.MustParseAddr("104.16.1.1")) {
		t.Fatal("default edge")
	}
	es := &EdgeSyncer{Store: st, Edge: e, HTTP: srv.Client(), URLs: []string{srv.URL + "/ips-v4", srv.URL + "/ips-v6"}, Now: func() time.Time { return now }}
	// Before any sync the built-in ranges become labels.
	if err := es.Load(ctx); err != nil {
		t.Fatal(err)
	}
	r := &ipinfo.Resolver{Store: st}
	if v := r.Resolve(ctx, 0, "162.158.1.1", "", now); v.Kind() != store.IPKindInfra || v.Best().Name != "Cloudflare" {
		t.Errorf("default edge label: %+v", v.Labels)
	}
	if err := es.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.Prefixes()) != 6 || e.Contains(netip.MustParseAddr("162.158.1.1")) || !e.Contains(netip.MustParseAddr("::ffff:104.16.1.1")) {
		t.Errorf("synced edge %v", e.Prefixes())
	}
	if v := r.Resolve(ctx, 0, "2606:4700::1", "", now); v.Best().Name != "Cloudflare" || v.Best().Source != EdgeSource {
		t.Errorf("synced label %+v", v.Labels)
	}
	// A broken answer keeps the good ranges.
	bad = true
	if err := es.Sync(ctx); err == nil {
		t.Error("garbage accepted")
	}
	if len(e.Prefixes()) != 6 {
		t.Error("ranges replaced by a bad sync")
	}
	e2 := &Edge{}
	es2 := &EdgeSyncer{Store: st, Edge: e2, Now: func() time.Time { return now }}
	if err := es2.Load(ctx); err != nil || len(e2.Prefixes()) != 6 {
		t.Errorf("load from labels: %v %d", err, len(e2.Prefixes()))
	}
}

func TestRadar(t *testing.T) {
	f, c := newFake(t)
	st := storetest.New(t)
	ctx := t.Context()
	org, _ := st.CreateOrg(ctx, "test", "acme", "")
	office, _ := store.ParseIPPrefix("198.51.100.0/24")
	st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: org.ID, Prefix: office, Kind: store.IPKindStaff, Name: "Office"})
	clock := now
	rd := &Radar{Client: c, Store: st, Edge: NewEdge(), Now: func() time.Time { return clock }, Wait: time.Millisecond}
	r := &ipinfo.Resolver{Store: st, Sources: []ipinfo.Source{rd}}
	unknown := "192.0.2.50"
	// The first look is a miss and only queues the address (no request).
	if v := r.Resolve(ctx, org.ID, unknown, "", now); len(v.Labels) != 0 {
		t.Fatalf("first lookup: %+v", v.Labels)
	}
	for _, ip := range []string{"10.0.0.1", "100.70.0.1", "104.16.0.1", "2001:db8::1", "198.51.100.9"} {
		r.Resolve(ctx, org.ID, ip, "", now)
	}
	if rd.Queued() != 2 || f.radarHits != 0 { // the unknown one and the office one (filtered at lookup time)
		t.Fatalf("queued %d, hits %d", rd.Queued(), f.radarHits)
	}
	if err := rd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if f.radarHits != 1 { // the labelled office address was skipped
		t.Errorf("radar hits %d", f.radarHits)
	}
	v := r.Resolve(ctx, org.ID, unknown, "", now)
	if v.Kind() != store.IPKindUnknown || v.Best().Name != "AS64500 Example ISP (US)" || !v.Best().Guess || v.Best().Source != RadarSource {
		t.Errorf("radar label: %+v", v.Labels)
	}
	// A known label still wins over the guess.
	if v := r.Resolve(ctx, org.ID, "198.51.100.9", "", now); v.Best().Name != "Office" {
		t.Errorf("known label lost: %+v", v.Labels)
	}
	// The cache survives a restart; it's not asked again within 7 days.
	rd2 := &Radar{Client: c, Store: st, Edge: NewEdge(), Now: func() time.Time { return clock }}
	if err := rd2.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if ls, _ := rd2.Lookup(ctx, org.ID, netip.MustParseAddr(unknown), now); len(ls) != 1 || rd2.Queued() != 0 {
		t.Errorf("cached lookup: %+v queued %d", ls, rd2.Queued())
	}
	clock = now.Add(8 * 24 * time.Hour)
	if ls, _ := rd2.Lookup(ctx, org.ID, netip.MustParseAddr(unknown), now); len(ls) != 0 || rd2.Queued() != 1 {
		t.Errorf("stale entry: %+v queued %d", ls, rd2.Queued())
	}
	// No permission: paused, and the error says what to add.
	f.mu.Lock()
	f.radarDeny = true
	f.mu.Unlock()
	if err := rd2.Sync(ctx); err == nil || !strings.Contains(err.Error(), "Radar") {
		t.Errorf("denied: %v", err)
	}
	hits := f.radarHits
	rd2.Lookup(ctx, org.ID, netip.MustParseAddr("192.0.2.51"), now)
	rd2.Sync(ctx)
	if f.radarHits != hits {
		t.Error("lookups continued while paused")
	}
}
