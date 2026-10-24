// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAlertWebhook(t *testing.T) {
	var got []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	a := Alert{Kind: "silent", GeneratedAt: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC),
		Hosts: []string{"acme/web-01", "acme/db-01\r\nBcc: x"}, Count: 2, AlertAfter: "3h0m0s", URL: "https://heimdall.internal/anomalies"}

	w := &Webhook{URL: srv.URL, Format: "json", Client: srv.Client()}
	if err := w.SendAlert(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	var back Alert
	if err := json.Unmarshal(got, &back); err != nil || back.Kind != "silent" || back.Count != 2 ||
		back.Hosts[0] != "acme/web-01" || strings.ContainsAny(back.Hosts[1], "\r\n") {
		t.Errorf("json payload = %s (%v)", got, err)
	}
	if a.Hosts[1] != "acme/db-01\r\nBcc: x" {
		t.Error("SendAlert modified the caller's slice")
	}

	w.Format = "slack"
	if err := w.SendAlert(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	var slack map[string]string
	json.Unmarshal(got, &slack)
	if !strings.HasPrefix(slack["text"], "Heimdall: 2 hosts stopped reporting") || !strings.Contains(slack["text"], "  acme/web-01\n") ||
		!strings.Contains(slack["text"], "more than 3h0m0s") {
		t.Errorf("slack payload = %s", got)
	}

	a.Kind, a.Hosts, a.Count = "back", a.Hosts[:1], 1
	if s := a.Subject(); s != "Heimdall: 1 host is reporting again" {
		t.Errorf("subject = %q", s)
	}
}
