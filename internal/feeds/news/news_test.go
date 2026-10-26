// SPDX-License-Identifier: AGPL-3.0-or-later

package news

import (
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/netx"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/incidents.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseFixture(t *testing.T) {
	f, err := Parse(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	var slugs []string
	for _, it := range f.Items {
		slugs = append(slugs, it.Slug)
	}
	want := []string{"examplessl-heap-overflow", "widgetco-customer-data-breach", "leftpad-ng-hijacked", "old-closed-thing"}
	if !slices.Equal(slugs, want) {
		t.Fatalf("items %v, want %v", slugs, want)
	}
	// http and javascript: links, unknown category, wrong types, blank
	// title, bad date, bad slug, duplicate slug, a non-object.
	if f.Dropped != 9 {
		t.Errorf("dropped %d, want 9", f.Dropped)
	}
	if f.IgnoredIDs != 2 {
		t.Errorf("ignored IDs %d, want 2 (GHSA and MAL)", f.IgnoredIDs)
	}

	ssl := f.Items[0]
	if !slices.Equal(ssl.CVEs, []string{"CVE-2099-0001", "CVE-2099-0002"}) {
		t.Errorf("CVEs %v", ssl.CVEs)
	}
	if ssl.Category != "patch" || ssl.Status != "live" || ssl.Severity != "critical" || ssl.PatchStatus != "patched" ||
		ssl.URL != "https://news.example.test/i/examplessl-heap-overflow" || ssl.ClosedAt != nil {
		t.Errorf("fields: %+v", ssl)
	}
	// Text is kept verbatim; escaping is the renderer's job.
	if !strings.Contains(ssl.Title, "<script>") {
		t.Errorf("title altered: %q", ssl.Title)
	}
	if !ssl.StartedAt.Equal(time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)) ||
		!ssl.UpdatedAt.Equal(time.Date(2026, 10, 22, 9, 30, 0, 0, time.UTC)) {
		t.Errorf("dates %v %v", ssl.StartedAt, ssl.UpdatedAt)
	}
	breach := f.Items[1]
	if breach.ClosedAt == nil || !breach.ClosedAt.Equal(time.Date(2026, 10, 15, 6, 0, 0, 0, time.UTC)) {
		t.Errorf("closedAt with offset: %v", breach.ClosedAt)
	}
	if len(f.Items[2].CVEs) != 0 {
		t.Errorf("MAL ID kept as a CVE: %v", f.Items[2].CVEs)
	}
}

func TestParseRejectsBrokenFeeds(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":       `<html>maintenance</html>`,
		"no incidents":   `{"site": "x"}`,
		"wrong type":     `{"incidents": {"slug": "x"}}`,
		"empty":          `{"incidents": []}`,
		"all malformed":  `{"incidents": [{"slug": "x", "url": "http://x"}, 3]}`,
		"top-level list": `[]`,
	} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestValidateLimits(t *testing.T) {
	base := rawItem{Slug: "a", Title: "t", URL: "https://x.test/a", Category: "patch", Status: "live",
		Severity: "high", StartedAt: "2026-10-01", UpdatedAt: "2026-10-01"}
	if _, _, ok := validate(base); !ok {
		t.Fatal("base item rejected")
	}
	for name, mutate := range map[string]func(*rawItem){
		"long title":       func(r *rawItem) { r.Title = strings.Repeat("x", maxTitle+1) },
		"control char":     func(r *rawItem) { r.Title = "a\x1bb" },
		"long summary":     func(r *rawItem) { r.Summary = strings.Repeat("x", maxSummary+1) },
		"bad severity":     func(r *rawItem) { r.Severity = "apocalyptic" },
		"bad status":       func(r *rawItem) { r.Status = "rumoured" },
		"bad patch status": func(r *rawItem) { r.PatchStatus = "maybe" },
		"credentials":      func(r *rawItem) { r.URL = "https://u:p@x.test/" },
		"too many tags":    func(r *rawItem) { r.Tags = make([]string, maxList+1) },
		"tag with space":   func(r *rawItem) { r.Tags = []string{"two words"} },
		"too many cves":    func(r *rawItem) { r.CVEIDs = make([]string, maxCVEs+1) },
		"year out of range": func(r *rawItem) {
			r.StartedAt = "1970-01-01"
		},
	} {
		r := base
		mutate(&r)
		if _, _, ok := validate(r); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	r := base
	r.CVEIDs = []string{"CVE-2099-12345", "cve-2099-1234", "CVE-99-1", "<b>"}
	it, ignored, ok := validate(r)
	if !ok || !slices.Equal(it.CVEs, []string{"CVE-2099-12345"}) || ignored != 3 {
		t.Errorf("cve filtering: %v %d %v", it.CVEs, ignored, ok)
	}
}

func TestFetch(t *testing.T) {
	raw := fixture(t)
	var gotUA, gotINM string
	big := false
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotINM = r.Header.Get("User-Agent"), r.Header.Get("If-None-Match")
		if big {
			w.Write([]byte(`{"incidents": [`))
			w.Write([]byte(strings.Repeat(" ", MaxBytes)))
			w.Write([]byte(`]}`))
			return
		}
		if gotINM == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Thu, 22 Oct 2026 10:00:00 GMT")
		w.Write(raw)
	}))
	defer ts.Close()
	c := netx.NewForTest(ts.Client())

	f, v, err := Fetch(t.Context(), c, ts.URL, Validators{})
	if err != nil || f == nil || len(f.Items) != 4 {
		t.Fatalf("first fetch: %v %v", f, err)
	}
	if v.ETag != `"v1"` || v.LastModified == "" || gotUA != "heimdall-test" {
		t.Errorf("validators %+v, UA %q", v, gotUA)
	}
	f, v2, err := Fetch(t.Context(), c, ts.URL, v)
	if err != nil || f != nil || v2 != v || gotINM != `"v1"` {
		t.Errorf("conditional fetch: %v %+v %v (If-None-Match %q)", f, v2, err, gotINM)
	}
	big = true
	if _, _, err := Fetch(t.Context(), c, ts.URL, Validators{}); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("size cap: %v", err)
	}

	// The real client refuses anything but https to allowlisted hosts.
	real := netx.New([]string{"news.example.test"}, "heimdall/test")
	if _, _, err := Fetch(t.Context(), real, "http://news.example.test/incidents.json", Validators{}); err == nil {
		t.Error("plain http allowed")
	}
	if _, _, err := Fetch(t.Context(), real, "https://elsewhere.example/incidents.json", Validators{}); err == nil {
		t.Error("host outside the allowlist allowed")
	}
}
