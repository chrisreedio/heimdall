// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

// A real connect: an open port answers, a closed one is refused.
func TestProbeLocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	open := ln.Addr().(*net.TCPAddr).Port
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	shut := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	lo := netip.MustParseAddr("127.0.0.1")

	p := &Prober{Now: func() time.Time { return now }, Ports: []int{shut, open}, Timeout: time.Second}
	if r := p.Probe(t.Context(), lo); r.State != store.ProbeAnswers || r.Port != open || !r.CheckedAt.Equal(now) {
		t.Errorf("open: %+v", r)
	}
	p.Ports = []int{shut}
	if r := p.Probe(t.Context(), lo); r.State != store.ProbeRefused {
		t.Errorf("closed: %+v", r)
	}
}

func TestProbeable(t *testing.T) {
	ok := Probeable(nil)
	for a, want := range map[string]bool{
		"198.51.100.5": true, "2001:db8::5": true, "::ffff:198.51.100.5": true,
		"127.0.0.1": false, "::1": false, "10.0.0.5": false, "192.168.1.1": false, "169.254.1.1": false, "fe80::1": false,
		"100.100.1.1": false, "192.0.2.1": false, "104.16.0.1": false, "0.0.0.0": false, "224.0.0.1": false,
	} {
		if got := ok(netip.MustParseAddr(a)); got != want {
			t.Errorf("Probeable(%s) = %v", a, got)
		}
	}
}

// fakeDial answers per address: "open" on 443, "refused" or (anything
// else) a timeout. It records every dial.
type fakeDial struct {
	mu    sync.Mutex
	how   map[string]string
	dials []string
}

func (f *fakeDial) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, _ := net.SplitHostPort(addr)
	f.mu.Lock()
	f.dials = append(f.dials, addr)
	how := f.how[host]
	f.mu.Unlock()
	switch {
	case how == "open" && port == "443":
		c, s := net.Pipe()
		s.Close()
		return c, nil
	case how == "refused":
		return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	}
	return nil, &net.OpError{Op: "dial", Err: context.DeadlineExceeded}
}

func TestProberSync(t *testing.T) {
	ctx := t.Context()
	st := storetest.New(t)
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	zone := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	recs := []store.CloudflareRecord{
		{Name: "live.example.com", Type: "A", Content: "198.51.100.5"},
		{Name: "closed.example.com", Type: "A", Content: "198.51.100.6"},
		{Name: "dead.example.com", Type: "A", Content: "198.51.100.7"},
		{Name: "also.example.com", Type: "A", Content: "198.51.100.7"}, // same address: probed once
		{Name: "lan.example.com", Type: "A", Content: "10.0.0.5"},      // private: never dangling, never dialled
		{Name: "edge.example.com", Type: "A", Content: "104.16.0.1"},   // Cloudflare's
	}
	set := func(rs []store.CloudflareRecord) {
		if err := st.ReplaceCloudflareZones(ctx, []store.CloudflareZone{{ID: zone, Name: "example.com", Status: "active"}},
			map[string][]store.CloudflareRecord{zone: rs}, now); err != nil {
			t.Fatal(err)
		}
	}
	set(recs)
	f := &fakeDial{how: map[string]string{"198.51.100.5": "open", "198.51.100.6": "refused"}}
	p := &Prober{Store: st, Now: func() time.Time { return now }, Dial: f.dial}
	if err := p.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := st.DanglingProbes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]store.DanglingProbe{
		"198.51.100.5": {State: store.ProbeAnswers, Port: 443},
		"198.51.100.6": {State: store.ProbeRefused},
		"198.51.100.7": {State: store.ProbeSilent},
	}
	if len(got) != len(want) {
		t.Fatalf("stored %d: %+v", len(got), got)
	}
	for a, w := range want {
		g := got[netip.MustParseAddr(a)]
		if g.State != w.State || g.Port != w.Port || !g.CheckedAt.Equal(now) {
			t.Errorf("%s: %+v", a, g)
		}
	}
	for _, d := range f.dials {
		if h, _, _ := net.SplitHostPort(d); h == "10.0.0.5" || h == "104.16.0.1" {
			t.Errorf("dialled %s", d)
		}
	}
	// 443 answered for .5, so 80 wasn't tried; the others tried both.
	if n := len(f.dials); n != 5 {
		t.Errorf("%d dials: %v", n, f.dials)
	}

	// Fresh results aren't probed again; stale ones are.
	f.dials = nil
	now = now.Add(time.Hour)
	p.Sync(ctx)
	if len(f.dials) != 0 {
		t.Errorf("re-probed fresh results: %v", f.dials)
	}
	now = now.Add(6 * time.Hour)
	p.Sync(ctx)
	if len(f.dials) != 5 {
		t.Errorf("stale results not re-probed: %v", f.dials)
	}

	// A new record is probed on the next run; a gone one's result goes.
	f.dials = nil
	now = now.Add(time.Minute)
	set(append(recs[1:], store.CloudflareRecord{Name: "new.example.com", Type: "AAAA", Content: "2001:db8::9"}))
	p.Sync(ctx)
	if !slices.Equal(f.dials, []string{"[2001:db8::9]:443", "[2001:db8::9]:80"}) {
		t.Errorf("new record: %v", f.dials)
	}
	got, _ = st.DanglingProbes(ctx)
	if _, ok := got[netip.MustParseAddr("198.51.100.5")]; ok || len(got) != 3 {
		t.Errorf("after the record went: %+v", got)
	}

	// Max caps a run, never-checked first.
	st2 := storetest.New(t)
	st = st2
	var many []store.CloudflareRecord
	for i := range 10 {
		many = append(many, store.CloudflareRecord{Name: "h" + strconv.Itoa(i) + ".example.com", Type: "A", Content: "198.51.100." + strconv.Itoa(20+i)})
	}
	set(many)
	f.dials = nil
	p = &Prober{Store: st2, Now: func() time.Time { return now }, Dial: f.dial, Max: 4, Workers: 2}
	p.Sync(ctx)
	if got, _ := st2.DanglingProbes(ctx); len(got) != 4 {
		t.Errorf("Max 4: stored %d", len(got))
	}
	// Turning it off clears what's stored.
	if err := st2.PruneDanglingProbes(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := st2.DanglingProbes(ctx); len(got) != 0 {
		t.Errorf("after clearing: %d", len(got))
	}
}

// A cancelled run stores nothing half-done.
func TestProberCancelled(t *testing.T) {
	st := storetest.New(t)
	zone := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	st.ReplaceCloudflareZones(t.Context(), []store.CloudflareZone{{ID: zone, Name: "example.com", Status: "active"}},
		map[string][]store.CloudflareRecord{zone: {{Name: "x.example.com", Type: "A", Content: "198.51.100.5"}}}, time.Now())
	ctx, cancel := context.WithCancel(t.Context())
	p := &Prober{Store: st, Now: time.Now, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		cancel()
		return nil, errors.New("cancelled")
	}}
	if err := p.Sync(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
	if got, _ := st.DanglingProbes(t.Context()); len(got) != 0 {
		t.Errorf("stored %+v", got)
	}
}
