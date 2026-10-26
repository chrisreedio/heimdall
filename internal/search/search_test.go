// SPDX-License-Identifier: AGPL-3.0-or-later

package search

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/ingest"
	"github.com/realmwatch/heimdall/internal/snapshot"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in   string
		want Query
	}{
		{"openssl", Query{Kind: KindPackage, Name: "openssl"}},
		{"openssl < 3.0.13", Query{Kind: KindPackage, Name: "openssl", Op: "<", Version: "3.0.13"}},
		{"openssl<3.0.13", Query{Kind: KindPackage, Name: "openssl", Op: "<", Version: "3.0.13"}},
		{"openssh-server >= 1:9.2p1-2+deb12u3", Query{Kind: KindPackage, Name: "openssh-server", Op: ">=", Version: "1:9.2p1-2+deb12u3"}},
		{"libc6 == 2.36-9", Query{Kind: KindPackage, Name: "libc6", Op: "=", Version: "2.36-9"}},
		{"pkg:php", Query{Kind: KindPackage, Name: "php"}},
		{"PKG:nodejs > 18", Query{Kind: KindPackage, Name: "nodejs", Op: ">", Version: "18"}},
		{"php = 8.1", Query{Kind: KindRuntime, Name: "php", Op: "=", Version: "8.1"}},
		{"node < 20", Query{Kind: KindRuntime, Name: "nodejs", Op: "<", Version: "20"}},
		{"runtime:python >= 3.12", Query{Kind: KindRuntime, Name: "python", Op: ">=", Version: "3.12"}},
		{"Python", Query{Kind: KindRuntime, Name: "python"}},
		{"cve-2024-6387", Query{Kind: KindCVE, Name: "CVE-2024-6387"}},
		{"DEBIAN-CVE-2023-5678", Query{Kind: KindCVE, Name: "DEBIAN-CVE-2023-5678"}},
		{"rlsa-2024:6783", Query{Kind: KindCVE, Name: "RLSA-2024:6783"}},
		{"USN-6000-1", Query{Kind: KindCVE, Name: "USN-6000-1"}},
		{"GHSA-78FX-H6XR-VCH4", Query{Kind: KindCVE, Name: "GHSA-78fx-h6xr-vch4"}},
		{"host:web", Query{Kind: KindHost, Name: "web"}},
		{"  laravel/framework < 11.31  ", Query{Kind: KindComposer, Name: "laravel/framework", Op: "<", Version: "11.31"}},
	}
	for _, tt := range tests {
		got, err := Parse(tt.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tt.in, err)
			continue
		}
		tt.want.Raw = strings.TrimSpace(tt.in)
		if got != tt.want {
			t.Errorf("Parse(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}

	for _, bad := range []string{
		"", "   ", strings.Repeat("a", 201), "openssl 3.0", "open ssl < 1", "<script> < 1",
		"openssl < ", "openssl < 1 2", "openssl < 'x'", "host:", "host:a b", "runtime:ruby", "php = 8.x",
		"pkg:", "-rf < 1",
	} {
		if q, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) = %+v, want error", bad, q)
		}
	}
}

type fleet struct {
	t  *testing.T
	st *store.Store
}

func newFleet(t *testing.T) *fleet {
	t.Helper()
	st := storetest.New(t)
	ctx := t.Context()
	st.CreateOrg(ctx, "test", "acme", "")
	st.CreateEnv(ctx, "test", "acme", "prod", "")
	st.CreateOrg(ctx, "test", "globex", "")
	st.CreateEnv(ctx, "test", "globex", "prod", "")
	return &fleet{t: t, st: st}
}

// push registers org/host and stores the fixture after mutate.
func (f *fleet) push(org, host, fixture string, mutate func(*snapshot.Snapshot)) store.IngestHost {
	f.t.Helper()
	ctx := f.t.Context()
	if _, _, err := f.st.AddHost(ctx, "test", org, "prod", host, nil); err != nil {
		f.t.Fatal(err)
	}
	h, err := f.st.HostByName(ctx, org, host)
	if err != nil {
		f.t.Fatal(err)
	}
	if fixture == "" {
		return h
	}
	b, err := os.ReadFile("../snapshot/testdata/" + fixture)
	if err != nil {
		f.t.Fatal(err)
	}
	var s snapshot.Snapshot
	json.Unmarshal(b, &s)
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	s.CollectedAt = now
	if mutate != nil {
		mutate(&s)
	}
	raw, _ := json.Marshal(s)
	acc := ingest.Accepter{Store: f.st, Now: func() time.Time { return now }}
	res, err := acc.Accept(ctx, h, "push", raw)
	if err != nil || res.Status != http.StatusCreated {
		f.t.Fatalf("push %s: %+v %v", host, res, err)
	}
	return h
}

func (f *fleet) run(query string) *Result {
	f.t.Helper()
	q, err := Parse(query)
	if err != nil {
		f.t.Fatalf("Parse(%q): %v", query, err)
	}
	res, err := Run(f.t.Context(), f.st, q, store.AllScope)
	if err != nil {
		f.t.Fatalf("Run(%q): %v", query, err)
	}
	return res
}

func hosts(r *Result) string {
	var out []string
	for _, m := range r.Matches {
		out = append(out, m.Org+"/"+m.Host+":"+m.Name)
	}
	return strings.Join(out, " ")
}

func setup(t *testing.T) (*fleet, store.IngestHost) {
	f := newFleet(t)
	web := f.push("acme", "web-01", "debian12.json", func(s *snapshot.Snapshot) {
		s.Packages = append(s.Packages,
			snapshot.Package{Name: "php8.2-cli", Version: "8.2.20-1~deb12u1", Arch: "amd64", SourceName: "php8.2", SourceVersion: "8.2.20-1~deb12u1"},
			snapshot.Package{Name: "php8.2-fpm", Version: "8.2.20-1~deb12u1", Arch: "amd64", SourceName: "php8.2", SourceVersion: "8.2.20-1~deb12u1"},
		)
	})
	f.push("globex", "edge-01", "alpine320.json", nil)
	f.push("globex", "odd-01", "debian12.json", func(s *snapshot.Snapshot) { s.OS.ID, s.OS.VersionID = "plan9", "4" })
	f.push("acme", "web-02", "", nil) // never reported
	return f, web
}

func TestPackageSearch(t *testing.T) {
	f, _ := setup(t)

	// Source-name match: "openssl" finds libssl3 too. The unsupported OS is
	// skipped only when a version comparison is needed.
	r := f.run("openssl < 3.0.15")
	if got := hosts(r); got != "acme/web-01:libssl3 acme/web-01:openssl" {
		t.Errorf("openssl < 3.0.15: %s", got)
	}
	if !strings.Contains(r.Note, "1 host skipped") {
		t.Errorf("note = %q", r.Note)
	}
	for _, m := range r.Matches {
		if m.Name == "libssl3" && !strings.Contains(m.Detail, "source package openssl") {
			t.Errorf("libssl3 detail = %q", m.Detail)
		}
		if m.OS != "Debian GNU/Linux 12 (bookworm)" {
			t.Errorf("OS = %q", m.OS)
		}
	}
	if got := hosts(f.run("pkg:openssl")); got != "acme/web-01:libssl3 acme/web-01:openssl globex/odd-01:libssl3 globex/odd-01:openssl" {
		t.Errorf("any version: %s", got)
	}

	// dpkg: tilde sorts before the release, epochs dominate.
	if got := hosts(f.run("openssl < 3.0.14-1")); got != "acme/web-01:libssl3 acme/web-01:openssl" {
		t.Errorf("tilde <: %s", got)
	}
	if got := hosts(f.run("openssl >= 3.0.14-1")); got != "" {
		t.Errorf("tilde >=: %s", got)
	}
	r = f.run("openssh-server < 1:9.2p1-2+deb12u5")
	if got := hosts(r); got != "acme/web-01:openssh-server" {
		t.Errorf("epoch <: %s", got)
	}
	if !strings.Contains(r.Matches[0].Detail, "update pending: 1:9.2p1-2+deb12u5") {
		t.Errorf("pending detail = %q", r.Matches[0].Detail)
	}
	if got := hosts(f.run("openssh-server < 9.9")); got != "" {
		t.Errorf("epoch beats bigger upstream: %s", got)
	}
	if got := hosts(f.run("openssh-server = 1:9.2p1-2+deb12u3")); got != "acme/web-01:openssh-server" {
		t.Errorf("=: %s", got)
	}

	// apk scheme.
	if got := hosts(f.run("musl < 1.2.5-r4")); got != "globex/edge-01:musl" {
		t.Errorf("apk: %s", got)
	}
	if got := hosts(f.run("busybox > 1.36.1-r29")); got != "" {
		t.Errorf("apk equal not greater: %s", got)
	}
	if got := hosts(f.run("nonexistent-pkg")); got != "" {
		t.Errorf("missing package: %s", got)
	}
}

func TestRuntimeSearch(t *testing.T) {
	f, _ := setup(t)
	for q, want := range map[string]string{
		"php":        "acme/web-01:php",
		"php = 8.2":  "acme/web-01:php",
		"php = 8":    "acme/web-01:php",
		"php = 8.1":  "",
		"php < 8.3":  "acme/web-01:php",
		"php >= 8.3": "",
		"node":       "",
	} {
		if got := hosts(f.run(q)); got != want {
			t.Errorf("%s: %q, want %q", q, got, want)
		}
	}
	r := f.run("php")
	if r.Matches[0].Version != "8.2.20" || !strings.Contains(r.Matches[0].Detail, "php8.2-cli") {
		t.Errorf("runtime match = %+v", r.Matches[0])
	}
}

func TestCVESearch(t *testing.T) {
	f, web := setup(t)
	ctx := t.Context()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	if err := f.st.PutAdvisory(ctx, store.Advisory{ID: "DEBIAN-CVE-2023-5678", Modified: now,
		Aliases: []string{"CVE-2023-5678"}, Raw: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.st.SetFindings(ctx, web.ID, []store.Finding{{AdvisoryID: "DEBIAN-CVE-2023-5678",
		Ecosystem: "Debian:12", Package: "openssl", Version: "3.0.11-1~deb12u2", FixedVersion: "3.0.13-1~deb12u1"}}, now); err != nil {
		t.Fatal(err)
	}

	r := f.run("cve-2023-5678")
	if got := hosts(r); got != "acme/web-01:openssl" {
		t.Fatalf("by alias: %s", got)
	}
	if d := r.Matches[0].Detail; d != "openssl: fixed in 3.0.13-1~deb12u1 (DEBIAN-CVE-2023-5678)" {
		t.Errorf("detail = %q", d)
	}
	if got := hosts(f.run("DEBIAN-CVE-2023-5678")); got != "acme/web-01:openssl" {
		t.Errorf("by id: %s", got)
	}
	if got := hosts(f.run("CVE-2099-0001")); got != "" {
		t.Errorf("unknown CVE: %s", got)
	}

	// Resolved findings don't match.
	if _, _, err := f.st.SetFindings(ctx, web.ID, nil, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := hosts(f.run("CVE-2023-5678")); got != "" {
		t.Errorf("resolved finding still matches: %s", got)
	}
}

func TestHostSearch(t *testing.T) {
	f, _ := setup(t)
	r := f.run("host:WEB")
	if got := hosts(r); got != "acme/web-01:web-01 acme/web-02:web-02" {
		t.Errorf("host:WEB: %s", got)
	}
	if r.Matches[1].Detail != "never reported" || r.Matches[0].OS == "" {
		t.Errorf("details: %+v", r.Matches)
	}
	if got := hosts(f.run("host:zzz")); got != "" {
		t.Errorf("no match: %s", got)
	}
}

func TestRuntimeSatisfies(t *testing.T) {
	for _, tt := range []struct {
		have, op, want string
		ok             bool
	}{
		{"8.1.27", "=", "8.1", true},
		{"8.10.0", "=", "8.1", false},
		{"8.1", "=", "8.1.27", false},
		{"8.10.0", ">", "8.9", true},
		{"20.11.1", "<", "20.12", true},
		{"3.12.7", ">=", "3.12", true},
		{"x", "<", "1", false},
	} {
		if got := runtimeSatisfies(tt.have, tt.op, tt.want); got != tt.ok {
			t.Errorf("%s %s %s = %v", tt.have, tt.op, tt.want, got)
		}
	}
}
