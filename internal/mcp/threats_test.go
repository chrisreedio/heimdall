// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// seedFailures: one offender on each org's host, and one on both.
func (e *env) seedFailures() {
	e.t.Helper()
	ctx := e.t.Context()
	now := time.Now().UTC()
	at := now.Add(-time.Hour)
	for org, ips := range map[string][]string{"acme": {"198.51.100.9", "198.51.100.10"}, "globex": {"198.51.100.9", "203.0.113.50"}} {
		h, err := e.st.HostByName(ctx, org, "web-"+org)
		if err != nil {
			e.t.Fatal(err)
		}
		day := store.LoginDay{Day: at.Format(time.DateOnly), Failures: 40, Addresses: len(ips)}
		for _, ip := range ips {
			day.Rows = append(day.Rows, store.LoginFailure{IP: ip, Failures: 20, Usernames: 3, First: at.Add(-time.Minute), Last: at})
		}
		if err := e.st.RecordLogins(ctx, h.ID, store.LoginReport{Source: "journal", Days: []store.LoginDay{day}}, now); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) threatsToken() string {
	e.t.Helper()
	tok, _, err := e.st.CreateToken(e.t.Context(), "test", e.uid, "firewall", store.PurposeThreats)
	if err != nil {
		e.t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "hmd_threats_") {
		e.t.Fatalf("token %q", tok)
	}
	return tok
}

func (e *env) get(path, token string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, r)
	return w
}

func TestThreatTokenPurposes(t *testing.T) {
	e := newEnv(t)
	mcpTok := e.token
	thr := e.threatsToken()
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`

	// A threat-list token reads the list, and nothing else.
	if w := e.get(ThreatsPath, thr); w.Code != http.StatusOK {
		t.Errorf("threats token on the list: %d %s", w.Code, w.Body.String())
	}
	e.token = thr
	if w := e.do("POST", ping); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "MCP token") {
		t.Errorf("threats token on /mcp: %d %s", w.Code, w.Body.String())
	}
	// An MCP token can't pull the list.
	e.token = mcpTok
	for _, p := range []string{ThreatsPath, ThreatNetworksPath} {
		if w := e.get(p, mcpTok); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "threat-list token") {
			t.Errorf("mcp token on %s: %d %s", p, w.Code, w.Body.String())
		}
	}
	if w := e.do("POST", ping); w.Code != http.StatusOK {
		t.Errorf("mcp token on /mcp: %d", w.Code)
	}
	// The purpose is the database's, not the prefix's: an MCP token's
	// secret behind a threats prefix is no token at all.
	forged := "hmd_threats_" + strings.TrimPrefix(mcpTok, "hmd_mcp_")
	if w := e.get(ThreatsPath, forged); w.Code != http.StatusUnauthorized {
		t.Errorf("forged prefix: %d", w.Code)
	}
	if w := e.get(ThreatsPath, ""); w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("no token: %d", w.Code)
	}
	tokens, _ := e.st.ListMCPTokens(t.Context(), e.uid)
	for _, tk := range tokens {
		if tk.Purpose == store.PurposeThreats {
			e.st.RevokeMCPToken(t.Context(), "test", e.uid, tk.ID)
		}
	}
	if w := e.get(ThreatsPath, thr); w.Code != http.StatusUnauthorized {
		t.Errorf("revoked: %d", w.Code)
	}
}

func TestThreatsREST(t *testing.T) {
	e := newEnv(t) // the user views acme only
	e.seedFailures()
	thr := e.threatsToken()

	w := e.get(ThreatsPath, thr)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" ||
		w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("json: %d %v", w.Code, w.Header())
	}
	var res struct {
		Total     int
		Addresses []struct {
			IP  string
			SSH struct{ Hosts, Failures int }
		}
	}
	json.Unmarshal(w.Body.Bytes(), &res)
	var got []string
	for _, a := range res.Addresses {
		got = append(got, a.IP)
		if a.SSH.Hosts != 1 || a.SSH.Failures != 20 {
			t.Errorf("%s counts another org's host: %+v", a.IP, a.SSH)
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"198.51.100.10", "198.51.100.9"}) || res.Total != 2 {
		t.Errorf("acme viewer sees %v (total %d)", got, res.Total)
	}

	w = e.get(ThreatsPath+"?format=plain", thr)
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("plain: %d %v", w.Code, w.Header())
	}
	lines := strings.Split(strings.TrimSuffix(w.Body.String(), "\n"), "\n")
	slices.Sort(lines)
	if !slices.Equal(lines, []string{"198.51.100.10", "198.51.100.9"}) {
		t.Errorf("plain: %q", w.Body.String())
	}
	w = e.get(ThreatsPath+"?format=csv&limit=1", thr)
	rows, err := csv.NewReader(w.Body).ReadAll()
	if w.Header().Get("Content-Type") != "text/csv; charset=utf-8" || err != nil || len(rows) != 2 || rows[0][0] != "ip" {
		t.Errorf("csv: %v %v", rows, err)
	}
	w = e.get(ThreatNetworksPath+"?format=plain", thr)
	if w.Code != 200 || w.Body.String() != "198.51.100.0/24\n" {
		t.Errorf("networks plain: %d %q", w.Code, w.Body.String())
	}
	w = e.get(ThreatNetworksPath+"?format=json", thr)
	if !strings.Contains(w.Body.String(), `"network":"198.51.100.0/24"`) || !strings.Contains(w.Body.String(), `"addresses":2`) {
		t.Errorf("networks json: %s", w.Body.String())
	}

	// Another org: refused.
	if w := e.get(ThreatsPath+"?org=globex", thr); w.Code != http.StatusForbidden {
		t.Errorf("other org: %d %s", w.Code, w.Body.String())
	}
	if w := e.get(ThreatsPath+"?org=acme", thr); w.Code != 200 {
		t.Errorf("own org: %d", w.Code)
	}
	// Bad input, methods, origin and size.
	for _, q := range []string{"?format=xml", "?since=90d", "?source=smtp", "?limit=0", "?min_score=x"} {
		if w := e.get(ThreatsPath+q, thr); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, w.Code)
		}
	}
	r := httptest.NewRequest("POST", ThreatsPath, strings.NewReader("x"))
	r.Header.Set("Authorization", "Bearer "+thr)
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, r)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
	if w := e.get(ThreatsPath, thr, "Origin", "https://evil.example"); w.Code != http.StatusForbidden {
		t.Errorf("foreign origin: %d", w.Code)
	}
	if w := e.get(ThreatsPath+"?org="+strings.Repeat("a", maxQuery), thr); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("long query: %d", w.Code)
	}
	if w := e.get("/api/v1/other", thr); w.Code != http.StatusNotFound {
		t.Errorf("unknown path: %d", w.Code)
	}
}

func TestThreatsWebREST(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	now := time.Now().UTC()
	const zone = "0123456789abcdef0123456789abcdef"
	if err := e.st.ReplaceCloudflareZones(ctx, []store.CloudflareZone{{ID: zone, Name: "acme.example.com", Plan: "Pro", Status: "active"}}, nil, now); err != nil {
		t.Fatal(err)
	}
	acme, _ := e.st.HostByName(ctx, "acme", "web-acme")
	e.st.SetCloudflareZoneOrgs(ctx, map[string][]int64{zone: {acme.OrgID}})
	at := now.Add(-time.Hour)
	if err := e.st.RecordWebOffenders(ctx, zone, []store.WebDay{{Day: at.Format(time.DateOnly), Rows: []store.WebOffenderDay{
		{IP: "203.0.113.70", Events: 4, Actions: map[string]int{"block": 4}, First: at, Last: at}}}}, now); err != nil {
		t.Fatal(err)
	}
	w := e.get(ThreatsPath+"?source=web&format=csv", e.threatsToken())
	rows, _ := csv.NewReader(w.Body).ReadAll()
	if w.Code != 200 || len(rows) != 2 || rows[1][0] != "203.0.113.70" || rows[1][1] != "web" ||
		rows[1][slices.Index(rows[0], "web_zones")] != "acme.example.com" || rows[1][slices.Index(rows[0], "web_actions")] != "block:4" {
		t.Errorf("web rows: %d %v", w.Code, rows)
	}
}

func TestThreatTools(t *testing.T) {
	e := newEnv(t)
	e.seedFailures()
	res := e.tool("threats", map[string]any{"limit": 1, "min_hosts": 1})
	d := res["data"].(map[string]any)
	if d["total"] != float64(2) || d["truncated"] != true || len(d["addresses"].([]any)) != 1 {
		t.Errorf("threats: %v", d)
	}
	b, _ := json.Marshal(d)
	if strings.Contains(string(b), "203.0.113.50") {
		t.Errorf("another org's offender: %s", b)
	}
	res = e.tool("threats", map[string]any{"org": "globex"})
	if msg, _ := res["data"].(map[string]any)["error"].(string); !strings.Contains(msg, "scope") {
		t.Errorf("other org: %v", res)
	}
	res = e.tool("threats", map[string]any{"limit": 101})
	if msg, _ := res["data"].(map[string]any)["error"].(string); !strings.Contains(msg, "limit") {
		t.Errorf("limit over 100: %v", res)
	}
	res = e.tool("threat_networks", map[string]any{"kind": "prefix"})
	nets := res["data"].(map[string]any)["networks"].([]any)
	if len(nets) != 1 || nets[0].(map[string]any)["network"] != "198.51.100.0/24" {
		t.Errorf("threat_networks: %v", nets)
	}
}
