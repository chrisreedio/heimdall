// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

func TestAnomalyTriage(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	host := e.seed()
	e.st.CreateLocalUser(t.Context(), "test", "admin@example.com", "", true, "$argon2id$x", []byte("secretsecretsecret12"))
	if _, err := e.st.AddAnomaly(t.Context(), host.ID, 0, store.Anomaly{Rule: "package_change", Severity: "medium",
		Summary: "<script>x</script> installed"}, testNow); err != nil {
		t.Fatal(err)
	}
	body := e.get("/anomalies", signedIn(e)).Body.String()
	if !strings.Contains(body, "package_change") || strings.Contains(body, "<script>x") {
		t.Fatalf("list (escaped?):\n%s", body)
	}
	f := url.Values{"csrf": {auth.CSRFToken(goodToken)}, "note": {"our deploy"}}
	if w := e.post("/anomalies/1/ack", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("ack: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(e.get("/anomalies", signedIn(e)).Body.String(), "package_change") {
		t.Error("acknowledged anomaly still listed")
	}
	if w := e.post("/anomalies/999/ack", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("unknown anomaly: %d", w.Code)
	}
}
