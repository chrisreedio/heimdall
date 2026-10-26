// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/netx"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func TestCatalog(t *testing.T) {
	var ids []string
	for _, s := range Catalog {
		ids = append(ids, s.ID)
		if s.Name == "" || s.Parse == nil || len(s.URLs) == 0 || !strings.HasPrefix(s.Docs, "https://") {
			t.Errorf("%s: incomplete", s.ID)
		}
		for _, u := range s.URLs {
			if !strings.HasPrefix(u, "https://") || config.HostOf(u) == "" {
				t.Errorf("%s: %q", s.ID, u)
			}
		}
		if len(s.Fallback) > 0 {
			if _, err := Prefixes(s.Fallback); err != nil || s.FallbackDate == "" {
				t.Errorf("%s fallback: %v", s.ID, err)
			}
		}
	}
	if !slices.Equal(ids, config.DeployServiceIDs) {
		t.Errorf("catalog %v, config knows %v", ids, config.DeployServiceIDs)
	}
	for _, id := range config.DefaultDeployServices().Services {
		if _, ok := Lookup(id); !ok {
			t.Errorf("default %q not in catalog", id)
		}
	}
}

func TestParsers(t *testing.T) {
	got, err := ParseLines([]byte("# Forge\n159.203.150.232\r\n\n  45.55.124.124  # old\n2001:db8::/32\n"))
	if err != nil || !slices.Equal(got, []string{"159.203.150.232", "45.55.124.124", "2001:db8::/32"}) {
		t.Errorf("lines = %q, %v", got, err)
	}
	if _, err := ParseLines([]byte("\n<!doctype html><title>Sign in</title>")); err == nil {
		t.Error("HTML accepted")
	}

	ploi := JSONPaths([]string{"data", "workers"})
	got, err = ploi([]byte(`{"data":{"workers":["198.51.100.1","2001:db8::1"],"site-monitors":{"london":"203.0.113.9"}}}`))
	if err != nil || !slices.Equal(got, []string{"198.51.100.1", "2001:db8::1"}) {
		t.Errorf("ploi = %q, %v", got, err)
	}
	deployhq := JSONPaths([]string{"all_ipv4"}, []string{"all_ipv6"})
	got, err = deployhq([]byte(`{"shared":{"ipv4":["x"]},"all_ipv4":["185.22.211.30"],"all_ipv6":["2a03:2800:300::/64"]}`))
	if err != nil || !slices.Equal(got, []string{"185.22.211.30", "2a03:2800:300::/64"}) {
		t.Errorf("deployhq = %q, %v", got, err)
	}
	buddy := JSONPaths([]string{"runners"})
	got, err = buddy([]byte(`{"lastUpdate":"January 22, 2026","runners":["66.96.88.128/25","18.191.41.36"]}`))
	if err != nil || len(got) != 2 {
		t.Errorf("buddy = %q, %v", got, err)
	}
	for _, bad := range []string{`{"data":{}}`, `{"data":{"workers":"198.51.100.1"}}`, `{"data":{"workers":[1]}}`, `[]`, `<html>`} {
		if _, err := ploi([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}

	got, err = ParseAny([]byte(` ["203.0.113.5", "198.51.100.0/24"]`))
	if err != nil || len(got) != 2 {
		t.Errorf("any json = %q, %v", got, err)
	}
	got, err = ParseAny([]byte("203.0.113.5\n"))
	if err != nil || len(got) != 1 {
		t.Errorf("any lines = %q, %v", got, err)
	}
}

func TestPrefixes(t *testing.T) {
	ps, err := Prefixes([]string{"203.0.113.5", "203.0.113.5/32", "198.51.100.7/24", "10.0.0.0/8", "::ffff:192.0.2.1", "2001:db8::/16"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"203.0.113.5/32", "198.51.100.0/24", "10.0.0.0/8", "192.0.2.1/32", "2001::/16"}
	if len(ps) != len(want) {
		t.Fatalf("got %v", ps)
	}
	for i, p := range ps {
		if p.String() != want[i] {
			t.Errorf("%d: %s, want %s", i, p, want[i])
		}
	}
	for _, bad := range [][]string{{"0.0.0.0/0"}, {"203.0.113.5", "128.0.0.0/7"}, {"::/0"}, {"2000::/15"}, {"forge.example.com"}, {}} {
		if _, err := Prefixes(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := Prefixes(make([]string, MaxPrefixes+1)); err == nil {
		t.Error("too many accepted")
	}
}

// listServer serves body (or fails with status) and counts requests.
type listServer struct {
	*httptest.Server
	body   atomic.Value // string
	status atomic.Int32
	auth   atomic.Value // last Authorization header
}

func newListServer(t *testing.T, body string) *listServer {
	ls := &listServer{}
	ls.body.Store(body)
	ls.status.Store(200)
	ls.auth.Store("")
	ls.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ls.auth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(int(ls.status.Load()))
		w.Write([]byte(ls.body.Load().(string)))
	}))
	t.Cleanup(ls.Close)
	return ls
}

func sourceLabels(t *testing.T, st *store.Store, source string) []store.IPLabel {
	t.Helper()
	ls, err := st.IPLabels(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.IPLabel
	for _, l := range ls {
		if l.Source == source {
			out = append(out, l)
		}
	}
	return out
}

func state(t *testing.T, st *store.Store, source string) store.IPSourceState {
	t.Helper()
	states, err := st.IPSourceStates(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range states {
		if s.Source == source {
			return s
		}
	}
	return store.IPSourceState{}
}

func TestSyncKeepsOldLabelsOnFailure(t *testing.T) {
	st := storetest.New(t)
	srv := newListServer(t, "198.51.100.10\n198.51.100.11\n")
	svc := Service{ID: "forge", Name: "Laravel Forge", URLs: []string{srv.URL + "/ips-v4.txt"}, Parse: ParseLines}
	sy := &Syncer{Service: svc, Store: st, Client: netx.NewForTest(srv.Client()), Now: func() time.Time { return now }}
	if sy.Name() != "service:forge" || sy.Every() != 24*time.Hour {
		t.Errorf("%s every %s", sy.Name(), sy.Every())
	}
	if err := sy.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	ls := sourceLabels(t, st, "service:forge")
	if len(ls) != 2 || ls[0].Kind != store.IPKindAutomation || ls[0].Name != "Laravel Forge" || ls[0].Prefix.String() != "198.51.100.10/32" {
		t.Fatalf("labels = %+v", ls)
	}
	if s := state(t, st, "service:forge"); !s.LastSuccess.Equal(now) || s.Labels != 2 || s.LastError != "" {
		t.Errorf("state = %+v", s)
	}

	// Each kind of failure keeps the two labels and records the error.
	for _, f := range []struct {
		status int
		body   string
	}{{500, "oops"}, {200, "<html>maintenance</html>"}, {200, ""}, {200, "198.51.100.10\n0.0.0.0/0\n"}, {200, "not-an-ip\n"}} {
		srv.status.Store(int32(f.status))
		srv.body.Store(f.body)
		if err := sy.Sync(t.Context()); err == nil {
			t.Errorf("%d %q: no error", f.status, f.body)
		}
		if got := sourceLabels(t, st, "service:forge"); len(got) != 2 {
			t.Errorf("%d %q: labels now %+v", f.status, f.body, got)
		}
		if s := state(t, st, "service:forge"); s.LastError == "" || s.Labels != 2 || !s.LastSuccess.Equal(now) {
			t.Errorf("%d %q: state %+v", f.status, f.body, s)
		}
	}
	// A changed list replaces the old one wholesale.
	srv.status.Store(200)
	srv.body.Store("203.0.113.0/28\n")
	if err := sy.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := sourceLabels(t, st, "service:forge"); len(got) != 1 || got[0].Prefix.String() != "203.0.113.0/28" {
		t.Errorf("labels = %+v", got)
	}
}

func TestSyncFallback(t *testing.T) {
	st := storetest.New(t)
	srv := newListServer(t, "")
	srv.status.Store(503)
	svc := Service{ID: "forge", Name: "Laravel Forge", URLs: []string{srv.URL}, Parse: ParseLines,
		Fallback: []string{"198.51.100.1", "198.51.100.2"}, FallbackDate: "2026-10-24"}
	sy := &Syncer{Service: svc, Store: st, Client: netx.NewForTest(srv.Client()), Now: func() time.Time { return now }}
	// Never synced: the built-in copy is stored, and the error still returned.
	if err := sy.Sync(t.Context()); err == nil {
		t.Fatal("no error")
	}
	ls := sourceLabels(t, st, "service:forge")
	if len(ls) != 2 || !strings.Contains(ls[0].Note, "built-in list from 2026-10-24") {
		t.Fatalf("fallback = %+v", ls)
	}
	// Once a live sync worked, a failure keeps the live list, not the copy.
	srv.status.Store(200)
	srv.body.Store("203.0.113.7\n")
	if err := sy.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	srv.status.Store(503)
	if err := sy.Sync(t.Context()); err == nil {
		t.Fatal("no error")
	}
	if ls := sourceLabels(t, st, "service:forge"); len(ls) != 1 || ls[0].Prefix.String() != "203.0.113.7/32" || ls[0].Note != "" {
		t.Errorf("labels = %+v", ls)
	}
}

func TestSyncToken(t *testing.T) {
	st := storetest.New(t)
	srv := newListServer(t, `{"data":{"workers":["198.51.100.20"],"site-monitors":{"us":"203.0.113.1"}}}`)
	svc, _ := Lookup("ploi")
	svc.URLs = []string{srv.URL + "/api/ips"}
	sy := &Syncer{Service: svc, Store: st, Client: netx.NewForTest(srv.Client()), Now: func() time.Time { return now }}
	if err := sy.Sync(t.Context()); !errors.Is(err, ErrNoToken) {
		t.Fatalf("no token: %v", err)
	}
	sy.Token = func() (string, error) { return "tok-123", nil }
	if err := sy.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := srv.auth.Load(); got != "Bearer tok-123" {
		t.Errorf("Authorization = %q", got)
	}
	if ls := sourceLabels(t, st, "service:ploi"); len(ls) != 1 || ls[0].Prefix.String() != "198.51.100.20/32" || ls[0].Name != "Ploi" {
		t.Errorf("labels = %+v", ls)
	}
}

func TestNewCustomAndHints(t *testing.T) {
	st := storetest.New(t)
	srv := newListServer(t, "198.51.100.40\n")
	cfg := config.DeployServices{
		Services: []string{"forge", "ploi"},
		Custom: []config.CustomService{
			{Name: "Acme Deploy", CIDRs: []string{"203.0.113.10", "203.0.113.16/28"}, Users: []string{"deploy"}},
			{Name: "Acme CI", CIDRs: []string{"203.0.113.50"}, URL: srv.URL + "/ips"},
		},
	}
	b := New(cfg, Setup{Store: st, Client: netx.NewForTest(srv.Client()), Now: func() time.Time { return now },
		Token: func(string) (string, error) { return "", errors.New("none stored") }})
	if !slices.Equal(b.NoToken, []string{"ploi"}) {
		t.Errorf("no token = %v", b.NoToken)
	}
	var names []string
	for _, sy := range b.Syncers {
		names = append(names, sy.Name())
	}
	if !slices.Equal(names, []string{"service:forge", "service:custom-acme-deploy", "service:custom-acme-ci"}) {
		t.Errorf("syncers = %v", names)
	}
	if !slices.Equal(b.Sources, []string{"service:forge", "service:ploi", "service:custom-acme-deploy", "service:custom-acme-ci"}) {
		t.Errorf("sources = %v", b.Sources)
	}
	// Custom: fixed ranges with no URL, and fixed plus fetched.
	for _, sy := range b.Syncers[1:] {
		if err := sy.Sync(t.Context()); err != nil {
			t.Fatal(sy.Name(), err)
		}
	}
	if ls := sourceLabels(t, st, "service:custom-acme-deploy"); len(ls) != 2 || ls[1].Prefix.String() != "203.0.113.16/28" || ls[0].Name != "Acme Deploy" {
		t.Errorf("deploy = %+v", ls)
	}
	if ls := sourceLabels(t, st, "service:custom-acme-ci"); len(ls) != 2 {
		t.Errorf("ci = %+v", ls)
	}

	// Hints: forge, ploi (even without a token) and the custom "deploy".
	r := &ipinfo.Resolver{Store: st, UserHints: b.Hints}
	for user, want := range map[string]string{"forge": "Laravel Forge", "ploi": "Ploi", "deploy": "Acme Deploy", "alice": "", "Forge": ""} {
		v := r.Resolve(t.Context(), 0, "192.0.2.99", user, now)
		got := ""
		if v.Kind() == store.IPKindAutomation {
			got = v.Best().Name
			if !v.Best().Guess {
				t.Errorf("%s: a user name alone must be a guess", user)
			}
		}
		if got != want {
			t.Errorf("user %q: %q, want %q", user, got, want)
		}
	}
	// An address match is known, and ranks above a user guess.
	v := r.Resolve(t.Context(), 0, "203.0.113.20", "forge", now)
	if b := v.Best(); b.Name != "Acme Deploy" || b.Guess || b.Prefix != netip.MustParsePrefix("203.0.113.16/28") {
		t.Errorf("best = %+v", b)
	}
}

func TestPruner(t *testing.T) {
	st := storetest.New(t)
	ctx := t.Context()
	p := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	for src, pre := range map[string]string{"service:forge": "198.51.100.1/32", "service:buddy": "198.51.100.2/32", "tailscale": "100.64.0.1/32"} {
		if err := st.ReplaceIPLabels(ctx, 0, src, []store.IPLabel{{Prefix: p(pre), Kind: store.IPKindAutomation, Name: "x"}}, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.AddIPLabel(ctx, "test", store.IPLabel{Prefix: p("203.0.113.0/24"), Kind: store.IPKindStaff, Name: "Office"}); err != nil {
		t.Fatal(err)
	}
	if err := (&Pruner{Store: st, Keep: []string{"service:forge"}}).Sync(ctx); err != nil {
		t.Fatal(err)
	}
	ls, _ := st.IPLabels(ctx, 0)
	var left []string
	for _, l := range ls {
		left = append(left, l.Source)
	}
	slices.Sort(left)
	if !slices.Equal(left, []string{"manual", "service:forge", "tailscale"}) {
		t.Errorf("left = %v", left)
	}
}
