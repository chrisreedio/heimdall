// SPDX-License-Identifier: AGPL-3.0-or-later

package kev

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/netx"
)

func serve(t *testing.T, body []byte) (*netx.Client, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return netx.NewForTest(srv.Client()), srv.URL
}

func TestFetchFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/kev-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	c, url := serve(t, raw)
	cat, err := Fetch(t.Context(), c, url)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Entries) != 10 || cat.Skipped != 0 {
		t.Fatalf("entries=%d skipped=%d", len(cat.Entries), cat.Skipped)
	}
	if cat.Version == "" || cat.Released.IsZero() {
		t.Errorf("catalog metadata missing: %+v", cat)
	}
	known, unknown := 0, 0
	for _, e := range cat.Entries {
		if !cveRe.MatchString(e.CVE) || e.DateAdded.IsZero() || e.Vendor == "" || e.Name == "" {
			t.Errorf("bad entry %+v", e)
		}
		if e.KnownRansomware {
			known++
		} else {
			unknown++
		}
	}
	if known == 0 || unknown == 0 {
		t.Errorf("fixture should have both ransomware states: known=%d unknown=%d", known, unknown)
	}
}

func TestParseSkipsInvalidAndDuplicates(t *testing.T) {
	cat, err := Parse([]byte(`{
		"catalogVersion": "2026.01.01",
		"dateReleased": "2026-01-01T00:00:00.000Z",
		"vulnerabilities": [
			{"cveID": "CVE-2024-1234", "vendorProject": "Acme\u001b[31m", "product": "Widget",
			 "vulnerabilityName": "` + strings.Repeat("A", 500) + `", "dateAdded": "2024-05-01",
			 "dueDate": "2024-05-22", "knownRansomwareCampaignUse": "Known"},
			{"cveID": "CVE-2024-1234", "vendorProject": "Dup", "dateAdded": "2024-05-02"},
			{"cveID": "cve-2024-9999", "dateAdded": "2024-05-01"},
			{"cveID": "CVE-2024-12; DROP", "dateAdded": "2024-05-01"},
			{"cveID": "CVE-2024-5678", "dateAdded": "05/01/2024"},
			{"cveID": "CVE-2024-1111111", "dateAdded": "2024-06-01", "dueDate": "", "knownRansomwareCampaignUse": "Unknown"},
			"not an object"
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Entries) != 2 || cat.Skipped != 5 {
		t.Fatalf("entries=%d skipped=%d: %+v", len(cat.Entries), cat.Skipped, cat.Entries)
	}
	e := cat.Entries[0]
	if e.Vendor != "Acme[31m" {
		t.Errorf("control characters not dropped: %q", e.Vendor)
	}
	if len([]rune(e.Name)) != maxText {
		t.Errorf("name not capped: %d", len(e.Name))
	}
	if !e.KnownRansomware || e.DueDate == nil || !e.DueDate.Equal(time.Date(2024, 5, 22, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("entry fields: %+v", e)
	}
	if cat.Entries[1].DueDate != nil || cat.Entries[1].KnownRansomware {
		t.Errorf("second entry: %+v", cat.Entries[1])
	}
}

func TestParseErrors(t *testing.T) {
	for name, in := range map[string]string{
		"not json":      `<html>`,
		"no list":       `{"catalogVersion": "x"}`,
		"empty list":    `{"vulnerabilities": []}`,
		"all invalid":   `{"vulnerabilities": [{"cveID": "nope", "dateAdded": "2024-01-01"}]}`,
		"list is wrong": `{"vulnerabilities": {}}`,
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestFetchOversized(t *testing.T) {
	big := make([]byte, maxBytes+10)
	c, url := serve(t, big)
	if _, err := Fetch(t.Context(), c, url); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("want size error, got %v", err)
	}
}
