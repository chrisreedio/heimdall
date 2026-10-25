// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/store/storetest"
)

// surfaceAPI fakes the endpoints a surface sync reads: zone A grants zone
// settings and certificates, zone B denies both (a token without Zone
// Settings Read or SSL and Certificates Read).
type surfaceAPI struct {
	mu      sync.Mutex
	records []Record // zone A's, changed between syncs
	ssl     string
	fail    bool // zone A's settings answer 500
}

func (f *surfaceAPI) handler(t *testing.T) http.Handler {
	ok := func(w http.ResponseWriter, result any) {
		b, _ := json.Marshal(map[string]any{"success": true, "errors": []any{}, "result": result,
			"result_info": map[string]int{"page": 1, "total_pages": 1}})
		w.Write(b)
	}
	deny := func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"success":false,"errors":[{"code":9109,"message":"Unauthorized to access requested resource"}]}`)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		p := r.URL.Path
		switch {
		case p == "/zones":
			ok(w, []map[string]any{
				{"id": zoneA, "name": "example.com", "status": "active", "plan": map[string]string{"name": "Pro Website"}},
				{"id": zoneB, "name": "example.net", "status": "active", "plan": map[string]string{"name": "Free Website"}},
			})
		case p == "/zones/"+zoneA+"/dns_records":
			ok(w, f.records)
		case p == "/zones/"+zoneB+"/dns_records":
			ok(w, []Record{{Name: "example.net", Type: "A", Content: "203.0.113.30", TTL: 1}})
		case strings.HasPrefix(p, "/zones/"+zoneA+"/settings/") && f.fail:
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, `{"success":false,"errors":[{"code":1001,"message":"try later"}]}`)
		case strings.HasPrefix(p, "/zones/"+zoneA+"/settings/"):
			v := map[string]string{"ssl": f.ssl, "always_use_https": "off", "min_tls_version": "1.2"}[strings.TrimPrefix(p, "/zones/"+zoneA+"/settings/")]
			ok(w, map[string]any{"id": "x", "value": v, "editable": true})
		case p == "/zones/"+zoneA+"/ssl/certificate_packs":
			ok(w, []map[string]any{
				{"status": "active", "certificates": []map[string]string{
					{"status": "active", "expires_on": "2027-01-20T00:00:00Z"}, {"status": "active", "expires_on": "2026-12-01T00:00:00Z"}}},
				{"status": "expired", "certificates": []map[string]string{{"status": "expired", "expires_on": "2025-01-01T00:00:00Z"}}},
			})
		case strings.HasPrefix(p, "/zones/"+zoneB+"/"):
			deny(w)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// fakeResolver answers from a map; a missing name is NXDOMAIN.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	asked   []string
}

func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, host)
	if host == "slow.example.org" {
		return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
	}
	if a, ok := f.answers[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestZoneSettingsPermissionFallback(t *testing.T) {
	f := &surfaceAPI{ssl: "flexible"}
	srv := httptest.NewTLSServer(f.handler(t))
	defer srv.Close()
	c := &Client{Base: srv.URL, Token: testToken, HTTP: srv.Client()}
	ctx := t.Context()
	state, _, zs, err := c.Settings(ctx, zoneA)
	if err != nil || state != store.SurfaceOK || zs != (ZoneSettings{SSL: "flexible", AlwaysHTTPS: "off", MinTLS: "1.2"}) {
		t.Errorf("zone A: %s %+v %v", state, zs, err)
	}
	state, note, _, err := c.Settings(ctx, zoneB)
	if err != nil || state != store.SurfacePermission || !strings.Contains(note, "Zone Settings") {
		t.Errorf("zone B: %s %q %v", state, note, err)
	}
	state, _, exp, err := c.CertExpiry(ctx, zoneA)
	if err != nil || state != store.SurfaceOK || !exp.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("certs A: %s %v %v", state, exp, err)
	}
	if state, note, _, err := c.CertExpiry(ctx, zoneB); err != nil || state != store.SurfacePermission || !strings.Contains(note, "SSL and Certificates") {
		t.Errorf("certs B: %s %q %v", state, note, err)
	}
}

func TestThirdParty(t *testing.T) {
	for target, want := range map[string]string{
		"acme.herokuapp.com.":                            "Heroku",
		"acme.azurewebsites.net":                         "Azure App Service",
		"acme-bucket.s3-website-us-east-1.amazonaws.com": "AWS S3 website",
		"acme-bucket.s3-website.eu-west-1.amazonaws.com": "AWS S3 website",
		"acme.github.io":                                 "GitHub Pages",
		"acme.pages.dev":                                 "Cloudflare Pages",
		"origin.example.com":                             "",
		"github.io.example.com":                          "",
		"ec2-198-51-100-1.compute-1.amazonaws.com":       "",
	} {
		if got := ThirdParty(target); got != want {
			t.Errorf("%s: %q, want %q", target, got, want)
		}
	}
}

func TestCheckCNAMEs(t *testing.T) {
	r := &fakeResolver{answers: map[string][]string{"live.herokuapp.com": {"198.51.100.7"}}}
	var targets []string
	for range 30 { // more targets than workers
		targets = append(targets, "live.herokuapp.com")
	}
	targets = append(targets, "gone.herokuapp.com", "slow.example.org")
	got := CheckCNAMEs(t.Context(), r, targets)
	if len(got) != len(targets) || len(r.asked) != len(targets) {
		t.Fatalf("%d checks, %d asked", len(got), len(r.asked))
	}
	if got[0].Status != store.CNAMEOK || got[30].Status != store.CNAMENXDomain || got[31].Status != store.CNAMEError {
		t.Errorf("statuses: %+v %+v %+v", got[0], got[30], got[31])
	}
	zones := []store.CloudflareZone{{ID: zoneA, Name: "example.com"}}
	ft := ForeignTargets(zones, []store.CloudflareRecord{
		{Type: "CNAME", Content: "origin.example.com"}, {Type: "CNAME", Content: "Acme.HerokuApp.com."},
		{Type: "CNAME", Content: "acme.herokuapp.com"}, {Type: "A", Content: "203.0.113.1"},
	})
	if len(ft) != 1 || ft[0] != "acme.herokuapp.com" {
		t.Errorf("foreign: %v", ft)
	}
}

func TestDiff(t *testing.T) {
	r := func(name, typ, content string, proxied bool) store.CloudflareRecord {
		return store.CloudflareRecord{Name: name, Type: typ, Content: content, Proxied: proxied}
	}
	before := []store.CloudflareRecord{
		r("www.example.com", "A", "203.0.113.10", true),
		r("api.example.com", "A", "203.0.113.11", false),
		r("old.example.com", "A", "203.0.113.12", true),
		r("same.example.com", "CNAME", "www.example.com", true),
	}
	after := []store.CloudflareRecord{
		r("WWW.example.com.", "A", "203.0.113.10", false),
		r("api.example.com", "A", "203.0.113.99", true),
		r("new.example.com", "CNAME", "acme.github.io", false),
		r("same.example.com", "CNAME", "www.example.com.", true),
	}
	got := map[string]store.SurfaceChange{}
	for _, c := range Diff(before, after) {
		got[c.Name+"/"+c.Kind] = c
	}
	if len(got) != 5 {
		t.Errorf("changes: %+v", got)
	}
	if _, ok := got["www.example.com/unproxied"]; !ok {
		t.Error("proxy off not recorded")
	}
	if c := got["api.example.com/target"]; c.Old != "A 203.0.113.11" || c.New != "A 203.0.113.99" {
		t.Errorf("target: %+v", c)
	}
	if _, ok := got["api.example.com/proxied"]; !ok {
		t.Error("proxy on not recorded")
	}
	if c := got["new.example.com/added"]; !strings.Contains(c.New, "acme.github.io") || !strings.Contains(c.New, "not proxied") {
		t.Errorf("added: %+v", c)
	}
	if _, ok := got["old.example.com/removed"]; !ok {
		t.Error("removal not recorded")
	}
}

func TestSurfaceSync(t *testing.T) {
	f := &surfaceAPI{ssl: "full", records: []Record{
		{Name: "www.example.com", Type: "A", Content: "203.0.113.10", Proxied: true, TTL: 1},
		{Name: "blog.example.com", Type: "CNAME", Content: "acme.herokuapp.com", Proxied: true, TTL: 1},
	}}
	srv := httptest.NewTLSServer(f.handler(t))
	defer srv.Close()
	st := storetest.New(t)
	ctx := t.Context()
	res := &fakeResolver{answers: map[string][]string{}}
	at := now
	s := &Syncer{Client: &Client{Base: srv.URL, Token: testToken, HTTP: srv.Client()}, Store: st, Interval: time.Hour,
		Now: func() time.Time { return at }, Surface: true, Resolver: res}
	// Zone B denies settings and certificates: a state, not a sync error.
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	settings := mustSettings(t, st)
	if a := settings[zoneA]; a.State != store.SurfaceOK || a.SSL != "full" || a.AlwaysHTTPS != "off" || a.CertExpires.IsZero() {
		t.Errorf("zone A settings: %+v", a)
	}
	if b := settings[zoneB]; b.State != store.SurfacePermission || b.CertState != store.SurfacePermission {
		t.Errorf("zone B settings: %+v", b)
	}
	checks, _ := st.CNAMEChecks(ctx)
	if checks["acme.herokuapp.com"].Status != store.CNAMENXDomain {
		t.Errorf("checks: %+v", checks)
	}
	// A first sync logs no changes: there's nothing to compare against.
	if cs, _ := st.SurfaceChanges(ctx, now.Add(-time.Hour), 100); len(cs) != 0 {
		t.Errorf("first sync logged %+v", cs)
	}

	// Second sync: www goes grey, blog is gone, api is new; settings
	// fail with a non-permission error keep the last good values.
	f.mu.Lock()
	f.records = []Record{
		{Name: "www.example.com", Type: "A", Content: "203.0.113.10", TTL: 1},
		{Name: "api.example.com", Type: "A", Content: "203.0.113.11", TTL: 1},
	}
	f.fail = true
	f.mu.Unlock()
	at = now.Add(time.Hour)
	if err := s.Sync(ctx); err == nil || !strings.Contains(err.Error(), "zone settings") {
		t.Fatalf("settings failure not reported: %v", err)
	}
	if a := mustSettings(t, st)[zoneA]; a.State != store.SurfaceError || a.SSL != "full" {
		t.Errorf("last good settings lost: %+v", a)
	}
	cs, err := st.SurfaceChanges(ctx, now, 100)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, c := range cs {
		kinds[c.Name] += c.Kind
		if c.Zone != "example.com" || !c.At.Equal(at) {
			t.Errorf("change: %+v", c)
		}
	}
	if kinds["www.example.com"] != "unproxied" || kinds["blog.example.com"] != "removed" || kinds["api.example.com"] != "added" || len(cs) != 3 {
		t.Errorf("changes: %+v", cs)
	}
	// blog's CNAME target is no longer used, so its check is dropped.
	if checks, _ := st.CNAMEChecks(ctx); len(checks) != 0 {
		t.Errorf("stale checks: %+v", checks)
	}
	// Changes older than 90 days are pruned.
	if err := st.AddSurfaceChanges(ctx, nil, now.AddDate(0, 0, 91)); err != nil {
		t.Fatal(err)
	}
	if cs, _ := st.SurfaceChanges(ctx, time.Time{}, 100); len(cs) != 0 {
		t.Errorf("not pruned: %d", len(cs))
	}
}

func mustSettings(t *testing.T, st *store.Store) map[string]store.SurfaceSettings {
	t.Helper()
	s, err := st.SurfaceSettingsAll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
