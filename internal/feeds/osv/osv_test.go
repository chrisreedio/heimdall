// SPDX-License-Identifier: AGPL-3.0-or-later

package osv

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/realmwatch/heimdall/internal/netx"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Client{HTTP: netx.NewForTest(srv.Client()), BaseURL: srv.URL}
}

type wireReq struct {
	Queries []batchQuery `json:"queries"`
}

func TestQueryBatchChunksAndPreservesOrder(t *testing.T) {
	var requests atomic.Int32
	c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/querybatch" {
			http.Error(w, "bad route", 400)
			return
		}
		requests.Add(1)
		var req wireReq
		json.NewDecoder(r.Body).Decode(&req)
		if len(req.Queries) > maxBatch {
			http.Error(w, "too many", 400)
			return
		}
		// One vuln per query, named after the package so order is checkable.
		var resp batchResponse
		resp.Results = make([]struct {
			Vulns []struct {
				ID       string `json:"id"`
				Modified string `json:"modified"`
			} `json:"vulns"`
			NextPageToken string `json:"next_page_token"`
		}, len(req.Queries))
		for i, q := range req.Queries {
			resp.Results[i].Vulns = append(resp.Results[i].Vulns, struct {
				ID       string `json:"id"`
				Modified string `json:"modified"`
			}{ID: "TEST-" + q.Package.Name, Modified: "2026-10-15T09:47:31.215895355Z"})
		}
		json.NewEncoder(w).Encode(resp)
	})

	qs := make([]Query, 2500)
	for i := range qs {
		qs[i] = Query{Ecosystem: "Debian:12", Name: fmt.Sprintf("pkg%d", i), Version: "1.0"}
	}
	res, err := c.QueryBatch(t.Context(), qs)
	if err != nil {
		t.Fatal(err)
	}
	if n := requests.Load(); n != 3 {
		t.Errorf("requests = %d, want 3", n)
	}
	for i, refs := range res {
		if len(refs) != 1 || refs[0].ID != fmt.Sprintf("TEST-pkg%d", i) {
			t.Fatalf("result %d = %+v", i, refs)
		}
		if refs[0].Modified.IsZero() || refs[0].Modified.Nanosecond() == 0 {
			t.Fatalf("result %d: fractional modified time not parsed: %v", i, refs[0].Modified)
		}
	}
}

func TestQueryBatchPagination(t *testing.T) {
	c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		var req wireReq
		json.NewDecoder(r.Body).Decode(&req)
		var results []map[string]any
		for _, q := range req.Queries {
			switch {
			case q.Package.Name == "paged" && q.PageToken == "":
				results = append(results, map[string]any{"vulns": []map[string]string{{"id": "A-1"}}, "next_page_token": "tok1"})
			case q.Package.Name == "paged" && q.PageToken == "tok1":
				if q.Version != "1.0" || q.Package.Ecosystem != "Debian:12" {
					http.Error(w, "page request must repeat the query", 400)
					return
				}
				results = append(results, map[string]any{"vulns": []map[string]string{{"id": "A-2"}}})
			default:
				results = append(results, map[string]any{})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	res, err := c.QueryBatch(t.Context(), []Query{
		{"Debian:12", "clean", "1.0"},
		{"Debian:12", "paged", "1.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res[0]) != 0 {
		t.Errorf("clean: %+v", res[0])
	}
	var ids []string
	for _, r := range res[1] {
		ids = append(ids, r.ID)
	}
	if strings.Join(ids, ",") != "A-1,A-2" {
		t.Errorf("paged: %v", ids)
	}
}

func TestQueryBatchRealFixtureAndLoopGuard(t *testing.T) {
	body := fixture(t, "querybatch.json")
	c := newClient(t, func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
	res, err := c.QueryBatch(t.Context(), []Query{{"Debian:12", "openssl", "3.0.11-1~deb12u2"}, {"Debian:12", "libssl3", "3.0.11-1~deb12u2"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res[0]) != 3 || res[0][0].ID != "DEBIAN-CVE-2023-5678" || len(res[1]) != 0 {
		t.Fatalf("got %+v", res)
	}

	// A server that always returns a page token must not loop forever.
	loop := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"results":[{"next_page_token":"again"}]}`)
	})
	if _, err := loop.QueryBatch(t.Context(), []Query{{"Debian:12", "x", "1"}}); err == nil || !strings.Contains(err.Error(), "pages") {
		t.Fatalf("loop guard: %v", err)
	}

	// Result count must match the query count.
	short := newClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"results":[]}`) })
	if _, err := short.QueryBatch(t.Context(), []Query{{"Debian:12", "x", "1"}}); err == nil {
		t.Fatal("short results accepted")
	}

	// Hostile IDs are rejected.
	bad := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"results":[{"vulns":[{"id":"../../etc/passwd"}]}]}`)
	})
	if _, err := bad.QueryBatch(t.Context(), []Query{{"Debian:12", "x", "1"}}); err == nil {
		t.Fatal("bad id accepted")
	}
}

func TestVuln(t *testing.T) {
	ubuntu := fixture(t, "UBUNTU-CVE-2023-2975.json")
	var gotPath string
	c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		switch r.URL.Path {
		case "/v1/vulns/UBUNTU-CVE-2023-2975":
			w.Write(ubuntu)
		case "/v1/vulns/RLSA-2024:6783":
			w.Write(ubuntu) // wrong record for the requested ID
		case "/v1/vulns/BIG-1":
			w.Write([]byte(`{"id":"BIG-1","details":"` + strings.Repeat("x", maxVulnBytes) + `"}`))
		default:
			http.NotFound(w, r)
		}
	})

	v, raw, err := c.Vuln(t.Context(), "UBUNTU-CVE-2023-2975")
	if err != nil {
		t.Fatal(err)
	}
	if v.ID != "UBUNTU-CVE-2023-2975" || len(raw) != len(ubuntu) || v.Modified.IsZero() || v.Published.IsZero() {
		t.Fatalf("parsed %+v", v)
	}

	if _, _, err := c.Vuln(t.Context(), "RLSA-2024:6783"); err == nil || !strings.Contains(err.Error(), "response is for") {
		t.Fatalf("id mismatch: %v", err)
	}
	if !strings.Contains(gotPath, "RLSA-2024:6783") {
		t.Errorf("unexpected escaped path %q", gotPath)
	}
	if _, _, err := c.Vuln(t.Context(), "BIG-1"); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("oversized: %v", err)
	}
	for _, id := range []string{"", "../x", "a/b", "x y", "a?b=c", strings.Repeat("A", 200)} {
		if _, _, err := c.Vuln(t.Context(), id); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("id %q: %v", id, err)
		}
	}
}

func parseFixture(t *testing.T, name string) *Vuln {
	t.Helper()
	v, err := Parse(fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDistroRating(t *testing.T) {
	for file, want := range map[string]string{
		"UBUNTU-CVE-2023-2975.json":  "low",    // severity entry of type "Ubuntu"
		"DEBIAN-CVE-2023-5678.json":  "",       // urgency "not yet assigned"
		"ALPINE-CVE-2024-12797.json": "",       // CVSS only
		"RLSA-2024_6783.json":        "medium", // "Moderate: openssl security update"
		"ALSA-2024_0310.json":        "medium",
		"GHSA-78fx-h6xr-vch4.json":   "medium", // database_specific.severity MODERATE
	} {
		if got := parseFixture(t, file).DistroRating(); got != want {
			t.Errorf("%s: DistroRating() = %q, want %q", file, got, want)
		}
	}

	// Debian urgency: highest across releases wins; unimportant counts as low.
	deb := &Vuln{Affected: []Affected{
		{EcosystemSpecific: json.RawMessage(`{"urgency":"unimportant"}`)},
		{EcosystemSpecific: json.RawMessage(`{"urgency":"high"}`)},
		{EcosystemSpecific: json.RawMessage(`"not an object"`)},
	}}
	if got := deb.DistroRating(); got != "high" {
		t.Errorf("debian urgency: %q", got)
	}
	if got := (&Vuln{Summary: "Important: kernel security update"}).DistroRating(); got != "high" {
		t.Errorf("Important: %q", got)
	}
	if got := (&Vuln{Summary: "Issue summary: something"}).DistroRating(); got != "" {
		t.Errorf("non-rating prefix: %q", got)
	}
	if got := (&Vuln{Severity: []Severity{{"Ubuntu", "negligible"}}}).DistroRating(); got != "low" {
		t.Errorf("negligible: %q", got)
	}
}

func TestFixedVersions(t *testing.T) {
	u := parseFixture(t, "UBUNTU-CVE-2023-2975.json")
	if got := u.FixedVersions("Ubuntu:22.04", "openssl"); !slices.Equal(got, []string{"3.0.2-0ubuntu1.12"}) {
		t.Errorf("Ubuntu:22.04 → %v", got)
	}
	// "Ubuntu:Pro:22.04:LTS" must not match a plain "Ubuntu:22.04" query.
	if got := u.FixedVersions("Ubuntu:22.04", "nodejs"); len(got) != 0 {
		t.Errorf("nodejs (Pro only) → %v", got)
	}
	d := parseFixture(t, "DEBIAN-CVE-2023-5678.json")
	if got := d.FixedVersions("Debian:12", "openssl"); !slices.Equal(got, []string{"3.0.13-1~deb12u1"}) {
		t.Errorf("Debian:12 → %v", got)
	}
	if got := d.FixedVersions("Debian:1", "openssl"); len(got) != 0 {
		t.Errorf("Debian:1 prefix must not match Debian:12: %v", got)
	}
	a := parseFixture(t, "ALSA-2024_0310.json")
	if got := a.FixedVersions("AlmaLinux:9", "openssl-libs"); !slices.Equal(got, []string{"1:3.0.7-25.el9_3"}) {
		t.Errorf("Alma → %v", got)
	}
}

func TestEcosystemMatches(t *testing.T) {
	for _, c := range []struct {
		record, query string
		want          bool
	}{
		{"Debian:12", "Debian:12", true},
		{"Ubuntu:22.04:LTS", "Ubuntu:22.04", true},
		{"Ubuntu:Pro:22.04:LTS", "Ubuntu:22.04", false},
		{"Debian:12", "Debian:1", false},
		{"Debian:12", "", false},
	} {
		if got := EcosystemMatches(c.record, c.query); got != c.want {
			t.Errorf("EcosystemMatches(%q, %q) = %v", c.record, c.query, got)
		}
	}
}

func TestCVEs(t *testing.T) {
	for file, want := range map[string][]string{
		"DEBIAN-CVE-2023-5678.json":  {"CVE-2023-5678"}, // upstream
		"UBUNTU-CVE-2023-2975.json":  {"CVE-2023-2975"}, // upstream
		"RLSA-2024_6783.json":        {"CVE-2024-6119"}, // upstream
		"ALSA-2024_0310.json":        {"CVE-2023-5363"}, // related
		"ALPINE-CVE-2024-12797.json": {"CVE-2024-12797"},
	} {
		if got := parseFixture(t, file).CVEs(); !slices.Equal(got, want) {
			t.Errorf("%s: CVEs() = %v, want %v", file, got, want)
		}
	}
	v := &Vuln{ID: "CVE-2024-0001", Aliases: []string{"GHSA-x", "CVE-2024-0001", "CVE-2024-0002", "CVE-24-1"}}
	if got := v.CVEs(); !slices.Equal(got, []string{"CVE-2024-0001", "CVE-2024-0002"}) {
		t.Errorf("dedupe: %v", got)
	}
}

func TestParseLimits(t *testing.T) {
	var aff []string
	for range maxAffected + 1 {
		aff = append(aff, `{}`)
	}
	if _, err := Parse([]byte(`{"id":"X-1","affected":[` + strings.Join(aff, ",") + `]}`)); err == nil {
		t.Error("too many affected entries accepted")
	}
	if _, err := Parse([]byte(`{"id":"bad id"}`)); err == nil {
		t.Error("bad id accepted")
	}
	v, err := Parse([]byte(`{"id":"X-1","modified":"not a time","withdrawn":"2024-01-01T00:00:00Z"}`))
	if err != nil || !v.Modified.IsZero() || v.Withdrawn == nil || v.Withdrawn.Year() != 2024 {
		t.Errorf("lenient times: %+v %v", v, err)
	}
}
