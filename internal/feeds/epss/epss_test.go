// SPDX-License-Identifier: AGPL-3.0-or-later

package epss

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chrisreedio/heimdall/internal/netx"
)

type row struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

// fakeAPI answers every requested CVE except those in skip, using rows for overrides.
func fakeAPI(t *testing.T, override map[string]row, skip map[string]bool, status int) (*Client, *atomic.Int32) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/data/v1/epss" {
			http.NotFound(w, r)
			return
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		ids := strings.Split(r.URL.Query().Get("cve"), ",")
		if len(ids) > BatchSize {
			t.Errorf("batch of %d exceeds %d", len(ids), BatchSize)
		}
		var data []row
		for _, id := range ids {
			if skip[id] {
				continue
			}
			if o, ok := override[id]; ok {
				data = append(data, o)
				continue
			}
			data = append(data, row{CVE: id, EPSS: "0.5", Percentile: "0.9", Date: "2026-10-22"})
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "OK", "total": len(data), "offset": 0, "limit": 100, "data": data})
	}))
	t.Cleanup(srv.Close)
	return &Client{HTTP: netx.NewForTest(srv.Client()), BaseURL: srv.URL}, &calls
}

func TestFixtureParses(t *testing.T) {
	b, err := os.ReadFile("testdata/sample.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(b) }))
	defer srv.Close()
	c := &Client{HTTP: netx.NewForTest(srv.Client()), BaseURL: srv.URL}
	got, err := c.Scores(t.Context(), []string{"CVE-2021-44228", "CVE-2024-6387", "CVE-1999-0001"})
	if err != nil {
		t.Fatal(err)
	}
	if s := got["CVE-2021-44228"]; s.EPSS < 0.99 || s.Percentile != 1 || s.Date.IsZero() {
		t.Errorf("log4shell = %+v", s)
	}
	if len(got) != 3 {
		t.Errorf("got %d scores", len(got))
	}
}

func TestBatching(t *testing.T) {
	c, calls := fakeAPI(t, nil, nil, 0)
	var ids []string
	for i := range 250 {
		ids = append(ids, fmt.Sprintf("CVE-2024-%05d", i+1))
	}
	ids = append(ids, ids[0], "not-a-cve", "cve-2024-00002") // duplicate, invalid, lowercase duplicate
	got, err := c.Scores(t.Context(), ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 250 {
		t.Errorf("got %d scores, want 250", len(got))
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("%d requests, want 3", n)
	}
}

func TestUntrustedRows(t *testing.T) {
	c, _ := fakeAPI(t, map[string]row{
		"CVE-2024-0002": {CVE: "CVE-2024-0002", EPSS: "1.5", Percentile: "0.9", Date: "2026-10-22"},
		"CVE-2024-0003": {CVE: "CVE-2024-0003", EPSS: "0.1", Percentile: "-0.1", Date: "2026-10-22"},
		"CVE-2024-0004": {CVE: "CVE-2024-0004", EPSS: "NaN", Percentile: "0.5", Date: "2026-10-22"},
		"CVE-2024-0005": {CVE: "CVE-2024-0005", EPSS: "0.1", Percentile: "0.5", Date: "yesterday"},
		"CVE-2024-0006": {CVE: "CVE-2024-9999", EPSS: "0.1", Percentile: "0.5", Date: "2026-10-22"}, // not asked for
	}, map[string]bool{"CVE-2024-0007": true}, 0)
	got, err := c.Scores(t.Context(), []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003",
		"CVE-2024-0004", "CVE-2024-0005", "CVE-2024-0006", "CVE-2024-0007"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["CVE-2024-0001"].EPSS != 0.5 {
		t.Errorf("got %+v, want only CVE-2024-0001", got)
	}
}

func TestServerError(t *testing.T) {
	c, _ := fakeAPI(t, nil, nil, http.StatusBadGateway)
	if _, err := c.Scores(t.Context(), []string{"CVE-2024-0001"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestEmptyInputMakesNoRequest(t *testing.T) {
	c, calls := fakeAPI(t, nil, nil, 0)
	got, err := c.Scores(t.Context(), []string{"", "nope"})
	if err != nil || len(got) != 0 || calls.Load() != 0 {
		t.Errorf("got %v, %v, %d calls", got, err, calls.Load())
	}
}

func TestTooManyBatches(t *testing.T) {
	c, calls := fakeAPI(t, nil, nil, 0)
	var ids []string
	for i := range BatchSize*maxBatches + 1 {
		ids = append(ids, fmt.Sprintf("CVE-2024-%06d", i+1))
	}
	if _, err := c.Scores(t.Context(), ids); err == nil || calls.Load() != 0 {
		t.Errorf("err %v, %d calls", err, calls.Load())
	}
}
