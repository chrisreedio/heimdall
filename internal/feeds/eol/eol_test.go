// SPDX-License-Identifier: AGPL-3.0-or-later

package eol

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/netx"
)

// newServer serves testdata/<product>.json at the v1 path, plus any
// extra bodies given.
func newServer(t *testing.T, extra map[string]string) (*Client, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		product, ok := strings.CutPrefix(r.URL.Path, "/api/v1/products/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		if body, ok := extra[product]; ok {
			w.Write([]byte(body))
			return
		}
		b, err := os.ReadFile("testdata/" + product + ".json")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return &Client{HTTP: netx.NewForTest(srv.Client()), BaseURL: srv.URL}, &hits
}

func day(s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return t
}

func find(t *testing.T, cycles []Cycle, name string) Cycle {
	t.Helper()
	for _, c := range cycles {
		if c.Cycle == name {
			return c
		}
	}
	t.Fatalf("cycle %q not found", name)
	return Cycle{}
}

func TestProductFixtures(t *testing.T) {
	c, _ := newServer(t, nil)
	cycles, err := c.Product(t.Context(), ProductUbuntu)
	if err != nil {
		t.Fatal(err)
	}
	jammy := find(t, cycles, "22.04")
	if jammy.Product != "ubuntu" || jammy.EOL == nil || !jammy.EOL.Equal(day("2027-06-01")) || jammy.EOLReached {
		t.Errorf("22.04 = %+v", jammy)
	}
	if jammy.ReleaseDate == nil || jammy.Latest == "" {
		t.Errorf("22.04 missing release date or latest: %+v", jammy)
	}

	for _, p := range []string{ProductAlpine, ProductPHP, ProductLaravel} {
		cycles, err := c.Product(t.Context(), p)
		if err != nil || len(cycles) == 0 {
			t.Fatalf("%s: %v", p, err)
		}
	}
	laravel, _ := c.Product(t.Context(), ProductLaravel)
	if l11 := find(t, laravel, "11"); l11.EOL == nil || !l11.EOL.Equal(day("2026-03-12")) {
		t.Errorf("laravel 11 = %+v", l11)
	}
}

func TestProductParsing(t *testing.T) {
	body := `{"schema_version":"1.2.1","result":{"name":"nodejs","releases":[
		{"name":"3","isEol":true,"eolFrom":null,"latest":{"name":"3.3.1"}},
		{"name":"20","releaseDate":"2023-04-18","isEoas":true,"eoasFrom":"2024-10-22","isEol":false,"eolFrom":"2026-04-30","latest":{"name":"20.18.0"}},
		{"name":"21","isEol":false,"eolFrom":null},
		{"name":"bad cycle!","isEol":false,"eolFrom":"2030-01-01"},
		{"name":"22","isEol":false,"eolFrom":"not-a-date"},
		{"name":"23","isEol":false,"eolFrom":"2025-06-01","latest":{"name":"<script>"}}
	]}}`
	c, _ := newServer(t, map[string]string{"nodejs": body})
	cycles, err := c.Product(t.Context(), ProductNodeJS)
	if err != nil {
		t.Fatal(err)
	}
	if len(cycles) != 4 { // 3, 20, 21, 23; the malformed ones are skipped
		t.Fatalf("got %d cycles: %+v", len(cycles), cycles)
	}
	if n3 := find(t, cycles, "3"); !n3.EOLReached || n3.EOL != nil {
		t.Errorf("eol=true without date: %+v", n3)
	}
	n20 := find(t, cycles, "20")
	if n20.SupportUntil == nil || !n20.SupportUntil.Equal(day("2024-10-22")) || n20.Latest != "20.18.0" {
		t.Errorf("20 = %+v", n20)
	}
	if n21 := find(t, cycles, "21"); n21.EOL != nil || n21.EOLReached {
		t.Errorf("no EOL announced: %+v", n21)
	}
	if n23 := find(t, cycles, "23"); n23.Latest != "" {
		t.Errorf("hostile latest kept: %q", n23.Latest)
	}
}

func TestProductErrors(t *testing.T) {
	c, hits := newServer(t, map[string]string{
		"empty":   `{"result":{"name":"empty","releases":[]}}`,
		"garbage": `{"result":{"releases":[{"name":"!!"}]}}`,
		"notjson": `<html>`,
	})
	for _, p := range []string{"", "Ubuntu", "../etc/passwd", "a/b", "ubuntu?x=1", strings.Repeat("a", 41)} {
		if _, err := c.Product(t.Context(), p); err == nil {
			t.Errorf("product %q should be rejected", p)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("invalid slugs made %d requests", n)
	}
	for _, p := range []string{"empty", "garbage", "notjson", "missing"} {
		if _, err := c.Product(t.Context(), p); err == nil {
			t.Errorf("%s: expected error", p)
		}
	}
}

func TestOSCycle(t *testing.T) {
	tests := []struct {
		id, version, like string
		product, cycle    string
		ok                bool
	}{
		{"ubuntu", "22.04", "debian", "ubuntu", "22.04", true},
		{"ubuntu", "24.04", "", "ubuntu", "24.04", true},
		{"debian", "12", "", "debian", "12", true},
		{"rocky", "9.3", "rhel centos fedora", "rocky-linux", "9", true},
		{"almalinux", "9.8", "rhel centos fedora", "almalinux", "9", true},
		{"alpine", "3.20.10", "", "alpine-linux", "3.20", true},
		{"rhel", "9.4", "fedora", "rhel", "9", true},
		{"ol", "9.4", "fedora", "", "", false},                     // no ID_LIKE match
		{"pop", "22.04", "ubuntu debian", "ubuntu", "22.04", true}, // derivative via ID_LIKE
		{"debian", "", "", "", "", false},                          // sid/testing has no VERSION_ID
		{"ubuntu", "22", "", "", "", false},
		{"alpine", "edge", "", "", "", false},
		{"arch", "", "", "", "", false},
	}
	for _, tt := range tests {
		p, c, ok := OSCycle(tt.id, tt.version, tt.like)
		if p != tt.product || c != tt.cycle || ok != tt.ok {
			t.Errorf("OSCycle(%q, %q, %q) = %q, %q, %v; want %q, %q, %v",
				tt.id, tt.version, tt.like, p, c, ok, tt.product, tt.cycle, tt.ok)
		}
	}
}

func TestRuntimeCycle(t *testing.T) {
	tests := []struct {
		product, version, cycle string
		ok                      bool
	}{
		{"php", "8.3.12", "8.3", true},
		{"php", "8.3", "8.3", true},
		{"nodejs", "20.11.1", "20", true},
		{"nodejs", "v18.19.0", "18", true},
		{"python", "3.12.7", "3.12", true},
		{"laravel", "11.31.0", "11", true},
		{"laravel", "v12.0.1", "12", true},
		{"php", "8", "", false},
		{"php", "8.x", "", false},
		{"php", "", "", false},
		{"ruby", "3.3.0", "", false},
		{"python", "3.12rc1", "", false},
	}
	for _, tt := range tests {
		c, ok := RuntimeCycle(tt.product, tt.version)
		if c != tt.cycle || ok != tt.ok {
			t.Errorf("RuntimeCycle(%q, %q) = %q, %v; want %q, %v", tt.product, tt.version, c, ok, tt.cycle, tt.ok)
		}
	}
}

func TestEvaluate(t *testing.T) {
	eol := day("2027-06-01")
	cycles := []Cycle{
		{Cycle: "22.04", EOL: &eol},
		{Cycle: "8.1", EOLReached: true},
		{Cycle: "26.04"},
	}
	now := day("2026-10-22")

	s := Evaluate(cycles, "22.04", now)
	if !s.Known || s.EOL || s.EOLDate == nil || s.DaysLeft != 222 {
		t.Errorf("future EOL: %+v", s)
	}
	s = Evaluate(cycles, "22.04", day("2027-06-11").Add(12*time.Hour))
	if !s.EOL || s.DaysLeft != -11 {
		t.Errorf("past EOL: %+v", s)
	}
	if s = Evaluate(cycles, "22.04", eol); !s.EOL || s.DaysLeft != 0 {
		t.Errorf("on the EOL day: %+v", s)
	}
	if s = Evaluate(cycles, "8.1", now); !s.Known || !s.EOL || s.EOLDate != nil || s.DaysLeft != 0 {
		t.Errorf("eol=true without date: %+v", s)
	}
	if s = Evaluate(cycles, "26.04", now); !s.Known || s.EOL {
		t.Errorf("no EOL announced: %+v", s)
	}
	if s = Evaluate(cycles, "18.04", now); s.Known || s.EOL {
		t.Errorf("unknown cycle: %+v", s)
	}
}

func TestWindowsServerCycle(t *testing.T) {
	for v, want := range map[string]string{"10.0.20348": "2022", "10.0.17763": "2019", "10.0.26100": "2025", "6.3.9600": "2012-r2"} {
		if p, c, ok := OSCycle("windows", v, "windows-server"); !ok || p != "windows-server" || c != want {
			t.Errorf("%s: %s %s %v", v, p, c, ok)
		}
	}
	if _, _, ok := OSCycle("windows", "10.0.22631", ""); ok {
		t.Error("desktop Windows should be unmapped")
	}
	if _, _, ok := OSCycle("windows", "10.0.99999", "windows-server"); ok {
		t.Error("unknown build should be unmapped")
	}
}
