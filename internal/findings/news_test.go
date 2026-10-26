// SPDX-License-Identifier: AGPL-3.0-or-later

package findings

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/netx"
	"github.com/realmwatch/heimdall/internal/store"
)

// TestNewsKeepsLastGoodCopy: a fetch that fails or returns garbage never
// deletes stored incidents, and the failure shows in feed status.
func TestNewsKeepsLastGoodCopy(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if err := e.st.PutAdvisory(ctx, store.Advisory{ID: "DEBIAN-CVE-2099-0001", Modified: e.now, Severity: "critical",
		Raw: []byte(`{}`), Aliases: []string{"CVE-2099-0001"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.st.SetFindings(ctx, e.host.ID, []store.Finding{{AdvisoryID: "DEBIAN-CVE-2099-0001",
		Ecosystem: "Debian:12", Package: "openssl", Version: "3.0.11-1"}}, e.now); err != nil {
		t.Fatal(err)
	}

	fixture, err := os.ReadFile("../feeds/news/testdata/incidents.json")
	if err != nil {
		t.Fatal(err)
	}
	var body string
	status := http.StatusOK
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	defer ts.Close()
	n := &NewsSyncer{Store: e.st, HTTP: netx.NewForTest(ts.Client()), Sources: []string{ts.URL + "/incidents.json"},
		Now: func() time.Time { return e.now }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	body = string(fixture)
	if err := n.Run(ctx); err != nil {
		t.Fatal(err)
	}
	stored := func() []store.NewsEntry {
		t.Helper()
		all, err := e.st.News(ctx, store.AllScope)
		if err != nil {
			t.Fatal(err)
		}
		return all
	}
	// Four valid items; the one closed in March is past retention.
	if got := stored(); len(got) != 3 || got[0].Slug != "examplessl-heap-overflow" || len(got[0].Hosts) != 1 {
		t.Fatalf("after first sync: %+v", got)
	}

	for name, resp := range map[string]struct {
		status int
		body   string
	}{
		"server error": {http.StatusBadGateway, "oops"},
		"html":         {http.StatusOK, "<html>maintenance</html>"},
		"empty list":   {http.StatusOK, `{"incidents": []}`},
		"all garbage":  {http.StatusOK, `{"incidents": [{"slug": 1}, {"title": "x", "url": "javascript:alert(1)"}]}`},
	} {
		status, body = resp.status, resp.body
		err := n.Run(ctx)
		if err == nil {
			t.Errorf("%s: no error", name)
		}
		if got := stored(); len(got) != 3 || len(got[0].Hosts) != 1 {
			t.Errorf("%s: stored copy changed: %d items", name, len(got))
		}
		states, _ := e.st.FeedStates(ctx)
		var news store.FeedState
		for _, f := range states {
			if f.Feed == "news" {
				news = f
			}
		}
		if news.LastError == "" || news.LastSuccess.IsZero() {
			t.Errorf("%s: feed status %+v", name, news)
		}
	}

	// Recovering clears the error.
	status, body = http.StatusOK, string(fixture)
	if err := n.Run(ctx); err != nil {
		t.Fatal(err)
	}
	states, _ := e.st.FeedStates(ctx)
	for _, f := range states {
		if f.Feed == "news" && f.LastError != "" {
			t.Errorf("error not cleared: %q", f.LastError)
		}
	}
	if !strings.Contains(stored()[0].Title, "<script>") {
		t.Error("title should be stored verbatim (escaping happens when rendering)")
	}
}

func TestNilNewsSyncerIsOff(t *testing.T) {
	var n *NewsSyncer
	if n.MatchHost(t.Context(), 1) != nil || n.MatchAll(t.Context()) != nil {
		t.Error("nil syncer should do nothing")
	}
}
