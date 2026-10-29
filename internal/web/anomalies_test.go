// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

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
	body = e.get("/anomalies", signedIn(e)).Body.String()
	open, closed, _ := strings.Cut(body, "Closed in the last 30 days")
	if strings.Contains(open, "package_change") {
		t.Error("acknowledged anomaly still listed")
	}
	if !strings.Contains(closed, "package_change") || !strings.Contains(closed, "our deploy") || strings.Contains(closed, "Closed by Heimdall itself") {
		t.Error("acknowledged anomaly missing from the closed list, or marked auto-resolved")
	}
	if w := e.post("/anomalies/999/ack", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("unknown anomaly: %d", w.Code)
	}
}

func TestAnomalyBulkTriage(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	host := e.seed()
	e.seedOrg("other", "web-02")
	e.st.CreateLocalUser(t.Context(), "test", "admin@example.com", "", true, "$argon2id$x", []byte("secretsecretsecret12"))
	other, _ := e.st.HostByName(t.Context(), "other", "web-02")
	add := func(h store.IngestHost, rule, key string) {
		t.Helper()
		if _, err := e.st.AddAnomaly(t.Context(), h.ID, 0, store.Anomaly{Rule: rule, Severity: "medium", Summary: rule + " " + key,
			Detail: map[string]any{"key": key}}, testNow); err != nil {
			t.Fatal(err)
		}
	}
	add(host, "package_change", "a")  // 1
	add(host, "package_change", "b")  // 2
	add(host, "silence", "c")         // 3
	add(other, "package_change", "d") // 4, another org's
	openIDs := func() (ids []int64) {
		list, _ := e.st.OpenAnomalies(t.Context(), store.AllScope)
		for _, a := range list {
			ids = append(ids, a.ID)
		}
		return ids
	}
	form := func(action string, ids ...string) url.Values {
		return url.Values{"csrf": {auth.CSRFToken(goodToken)}, "note": {"checked, our deploy"}, "action": {action}, "days": {"3"}, "id": ids}
	}
	post := func(f url.Values) *httptest.ResponseRecorder {
		return e.post("/anomalies/bulk", f, signedIn(e), origin(e.baseURL))
	}

	// The page offers the form, a box per row, and select-all for JS.
	body := e.get("/anomalies", signedIn(e)).Body.String()
	if !strings.Contains(body, `action="/anomalies/bulk"`) || strings.Count(body, `form="bulk" data-bulk-row`) != 4 || !strings.Contains(body, "data-bulk-all") {
		t.Fatalf("bulk form missing:\n%s", body)
	}

	// An operator in acme only: posting the other org's id changes nothing.
	e.auth.viewer = &auth.Viewer{UserID: 1, Email: "admin@example.com", SessionToken: goodToken,
		Scope: store.Scope{Orgs: map[int64]store.Role{host.OrgID: store.RoleOperator}}}
	if w := post(form("ack", "1", "4")); w.Code != http.StatusNotFound {
		t.Fatalf("other org's anomaly: %d", w.Code)
	}
	if got := openIDs(); len(got) != 4 {
		t.Fatalf("open after a refused bulk ack: %v", got)
	}
	// A viewer in the other org: can see 4, can't triage it.
	e.auth.viewer.Scope.Orgs[other.OrgID] = store.RoleViewer
	if w := post(form("ack", "1", "4")); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "operator role") {
		t.Fatalf("viewer org: %d", w.Code)
	}
	if body := e.get("/anomalies", signedIn(e)).Body.String(); strings.Count(body, `form="bulk" data-bulk-row`) != 3 {
		t.Error("a box offered for an anomaly the viewer can't triage")
	}
	e.auth.viewer = nil // admin again

	for name, f := range map[string]url.Values{
		"none":     form("ack"),
		"bad id":   form("ack", "1", "x"),
		"no note":  {"csrf": {auth.CSRFToken(goodToken)}, "action": {"ack"}, "id": {"1"}},
		"too many": form("ack"),
	} {
		if name == "too many" {
			for i := range maxBulkAnomalies + 1 {
				f.Add("id", strconv.Itoa(i+1))
			}
		}
		if w := post(f); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if got := openIDs(); len(got) != 4 {
		t.Fatalf("open after refused requests: %v", got)
	}
	if w := post(form("ack", "1")); w.Code != http.StatusSeeOther {
		t.Fatalf("bulk ack of one: %d %s", w.Code, w.Body.String())
	}
	if w := e.post("/anomalies/bulk", url.Values{"note": {"x"}, "action": {"ack"}, "id": {"2"}}, signedIn(e), origin(e.baseURL)); w.Code == http.StatusSeeOther {
		t.Error("bulk ack without a CSRF token was accepted")
	}

	// Acknowledge 1 (already closed now) and 2: one closed, one skipped.
	w := post(form("ack", "1", "2", "2"))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/anomalies?done=ack&n=1&skipped=1" {
		t.Fatalf("bulk ack: %d %s", w.Code, w.Header().Get("Location"))
	}
	if body := e.get(w.Header().Get("Location"), signedIn(e)).Body.String(); !strings.Contains(body, "Acknowledged 1 anomaly. 1 was already closed.") {
		t.Errorf("notice missing:\n%s", body)
	}
	// Mute 3 and 4: each (host, signal) muted, both acknowledged.
	w = post(form("suppress", "3", "4"))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/anomalies?done=suppress&n=2" {
		t.Fatalf("bulk mute: %d %s", w.Code, w.Header().Get("Location"))
	}
	if got := openIDs(); len(got) != 0 {
		t.Errorf("still open: %v", got)
	}
	for _, h := range []store.IngestHost{host, other} {
		rule := map[int64]string{host.ID: "silence", other.ID: "package_change"}[h.ID]
		if ok, _ := e.st.Suppressed(t.Context(), h.ID, rule, testNow.Add(48*time.Hour)); !ok {
			t.Errorf("%s not muted on %s", rule, h.Name)
		}
	}
	if !auditHas(t, e, "anomaly.ack") || !auditHas(t, e, "anomaly.suppress") {
		t.Error("bulk triage not audited")
	}
	// Notices only take numbers from the query string.
	if got := bulkNotice(url.Values{"done": {"<b>"}, "n": {"1"}}); got != "" {
		t.Errorf("notice from an unknown action: %q", got)
	}
}
