// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/store/storetest"
)

type env struct {
	t     *testing.T
	st    *store.Store
	now   time.Time
	h     *Handler
	token string
	host  store.IngestHost
	body  []byte
}

// collected_at in the Debian fixture.
var fixtureTime = time.Date(2026, 10, 22, 4, 17, 3, 0, time.UTC)

func newEnv(t *testing.T, mutate func(*config.Ingest)) *env {
	t.Helper()
	st := storetest.New(t)
	ctx := t.Context()
	st.CreateOrg(ctx, "test", "acme", "")
	st.CreateEnv(ctx, "test", "acme", "prod", "")
	_, token, err := st.AddHost(ctx, "test", "acme", "prod", "web-01", nil)
	if err != nil {
		t.Fatal(err)
	}
	host, err := st.HostByName(ctx, "acme", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("../snapshot/testdata/debian12.json")
	if err != nil {
		t.Fatal(err)
	}

	e := &env{t: t, st: st, now: fixtureTime.Add(time.Minute), token: token, host: host, body: body}
	cfg := config.Default().Ingest
	if mutate != nil {
		mutate(&cfg)
	}
	e.h, err = NewHandler(st, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return e.now })
	if err != nil {
		t.Fatal(err)
	}
	return e
}

type req struct {
	method, path, token, contentType, encoding, remote, xff, hostname, triggers string
	body                                                                        []byte
}

func (e *env) do(r req) *httptest.ResponseRecorder {
	e.t.Helper()
	if r.method == "" {
		r.method = http.MethodPost
	}
	if r.path == "" {
		r.path = Path
	}
	if r.token == "" {
		r.token = e.token
	}
	if r.contentType == "" {
		r.contentType = "application/json"
	}
	if r.body == nil {
		r.body = e.body
	}
	hr := httptest.NewRequest(r.method, r.path, bytes.NewReader(r.body))
	hr.Header.Set("Authorization", "Bearer "+r.token)
	hr.Header.Set("Content-Type", r.contentType)
	if r.encoding != "" {
		hr.Header.Set("Content-Encoding", r.encoding)
	}
	if r.remote != "" {
		hr.RemoteAddr = r.remote
	}
	if r.xff != "" {
		hr.Header.Set("X-Forwarded-For", r.xff)
	}
	if r.hostname != "" {
		hr.Header.Set(HostnameHeader, r.hostname)
	}
	if r.triggers != "" {
		hr.Header.Set(TriggersHeader, r.triggers)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, hr)
	return w
}

func (e *env) expect(r req, status int) *httptest.ResponseRecorder {
	e.t.Helper()
	w := e.do(r)
	if w.Code != status {
		e.t.Fatalf("status = %d, want %d (body %q)", w.Code, status, w.Body.String())
	}
	return w
}

func (e *env) anomalies() []string {
	e.t.Helper()
	as, err := e.st.Anomalies(e.t.Context(), e.host.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	var rules []string
	for _, a := range as {
		rules = append(rules, a.Rule)
	}
	return rules
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

func TestStoresSnapshot(t *testing.T) {
	e := newEnv(t, nil)
	w := e.expect(req{}, http.StatusCreated)
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Cache-Control") != "no-store" {
		t.Error("missing security headers")
	}

	sum, err := e.st.LatestSnapshot(t.Context(), e.host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Packages != 4 || sum.PendingUpdates != 2 || sum.PendingSecurity != 1 || sum.Source != "push" {
		t.Errorf("summary = %+v", sum)
	}
	if sum.RebootRequired == nil || !*sum.RebootRequired {
		t.Error("reboot_required not stored")
	}
	hosts, _ := e.st.ListHosts(t.Context(), "acme")
	if !hosts[0].LastSeenAt.Equal(e.now) {
		t.Errorf("last_seen = %v, want %v", hosts[0].LastSeenAt, e.now)
	}
	if a := e.anomalies(); len(a) != 0 {
		t.Errorf("unexpected anomalies %v", a)
	}
}

func TestGzip(t *testing.T) {
	e := newEnv(t, nil)
	e.expect(req{body: gz(e.body), encoding: "gzip"}, http.StatusCreated)
	e.expect(req{body: []byte("not gzip"), encoding: "gzip"}, http.StatusBadRequest)
	e.expect(req{encoding: "br"}, http.StatusUnsupportedMediaType)
}

func TestSizeLimits(t *testing.T) {
	e := newEnv(t, func(c *config.Ingest) { c.MaxBody = 64 << 10 })
	big := bytes.Repeat([]byte(" "), 65<<10)
	e.expect(req{body: append(bytes.Clone(e.body), big...)}, http.StatusRequestEntityTooLarge)

	// A gzip bomb: tiny on the wire, huge when decompressed.
	bomb := gz(append(bytes.Clone(e.body), bytes.Repeat([]byte(" "), 20<<20)...))
	if len(bomb) > 64<<10 {
		t.Fatalf("bomb is %d bytes on the wire; test needs it under the cap", len(bomb))
	}
	e.expect(req{body: bomb, encoding: "gzip"}, http.StatusRequestEntityTooLarge)
}

func TestRetryAndReplay(t *testing.T) {
	e := newEnv(t, nil)
	e.expect(req{}, http.StatusCreated)

	e.now = e.now.Add(2 * time.Minute) // network retry
	e.expect(req{}, http.StatusOK)
	if a := e.anomalies(); len(a) != 0 {
		t.Fatalf("retry raised anomalies %v", a)
	}

	e.now = e.now.Add(time.Hour) // the same payload, much later
	e.expect(req{}, http.StatusConflict)
	if a := e.anomalies(); len(a) != 1 || a[0] != "replay" {
		t.Fatalf("anomalies = %v, want [replay]", a)
	}
}

func TestClockSkew(t *testing.T) {
	e := newEnv(t, nil)
	e.now = fixtureTime.Add(-time.Hour) // host claims a time an hour in the future
	e.expect(req{}, http.StatusCreated)
	if a := e.anomalies(); len(a) != 1 || a[0] != "clock_skew" {
		t.Fatalf("anomalies = %v, want [clock_skew]", a)
	}
}

func TestImportSkewOnlyFlagsFuture(t *testing.T) {
	e := newEnv(t, nil)
	e.now = fixtureTime.Add(30 * 24 * time.Hour) // a month-old import is fine
	res, err := e.h.acc.Accept(t.Context(), e.host, "import", e.body)
	if err != nil || res.Status != http.StatusCreated || len(res.Anomalies) != 0 {
		t.Fatalf("import: %+v, %v", res, err)
	}
}

func TestAuth(t *testing.T) {
	e := newEnv(t, nil)
	e.expect(req{token: "nope"}, http.StatusUnauthorized)
	e.expect(req{token: "hmd_ingest_" + strings.Repeat("A", 43)}, http.StatusUnauthorized)

	hr := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(e.body))
	hr.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, hr)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no Authorization header: %d", w.Code)
	}

	newToken, err := e.st.RotateToken(t.Context(), "test", "acme", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	e.expect(req{}, http.StatusUnauthorized) // old token revoked
	e.expect(req{token: newToken}, http.StatusCreated)
}

func TestAuthFailureLockout(t *testing.T) {
	e := newEnv(t, nil)
	for range authFailuresPerMinute {
		e.expect(req{token: "bad", remote: "198.51.100.7:1234"}, http.StatusUnauthorized)
	}
	// Even a valid token is refused from that IP until the bucket refills.
	e.expect(req{remote: "198.51.100.7:1234"}, http.StatusTooManyRequests)
	e.expect(req{remote: "198.51.100.8:1234"}, http.StatusCreated)
	e.now = e.now.Add(time.Minute)
	// Same inventory a minute later: recorded as an unchanged report.
	e.expect(req{remote: "198.51.100.7:1234", body: []byte(strings.Replace(string(e.body), "04:17:03", "04:18:03", 1))}, http.StatusOK)
}

func TestHostRateLimit(t *testing.T) {
	e := newEnv(t, func(c *config.Ingest) { c.RatePerHost = config.Rate{N: 2, Per: time.Hour} })
	e.expect(req{}, http.StatusCreated)
	e.expect(req{}, http.StatusOK)
	e.expect(req{}, http.StatusTooManyRequests)
}

func TestRouting(t *testing.T) {
	e := newEnv(t, nil)
	e.expect(req{path: "/"}, http.StatusNotFound)
	e.expect(req{path: "/api/v1/ingest/"}, http.StatusNotFound)
	e.expect(req{path: "/metrics"}, http.StatusNotFound)
	w := e.expect(req{method: http.MethodPut}, http.StatusMethodNotAllowed)
	if w.Header().Get("Allow") != "GET, POST" {
		t.Error("missing Allow header")
	}
	e.expect(req{contentType: "text/plain"}, http.StatusUnsupportedMediaType)
}

func TestInvalidSnapshot(t *testing.T) {
	e := newEnv(t, nil)
	w := e.expect(req{body: []byte(`{"format":"heimdall.snapshot/v1","evil":true}`)}, http.StatusUnprocessableEntity)
	if !strings.Contains(w.Body.String(), "evil") {
		t.Errorf("body should explain the problem: %q", w.Body.String())
	}
	if _, err := e.st.LatestSnapshot(t.Context(), e.host.ID); err == nil {
		t.Error("invalid snapshot was stored")
	}
}

func TestAllowCIDRs(t *testing.T) {
	e := newEnv(t, func(c *config.Ingest) { c.AllowCIDRs = []string{"203.0.113.0/24"} })
	e.expect(req{remote: "198.51.100.7:1234"}, http.StatusForbidden)
	e.expect(req{remote: "203.0.113.9:1234"}, http.StatusCreated)
}

func TestBehindProxy(t *testing.T) {
	e := newEnv(t, func(c *config.Ingest) {
		c.BehindProxy = true
		c.AllowCIDRs = []string{"203.0.113.0/24"}
	})
	// Client-supplied entries before the proxy's last hop are ignored.
	e.expect(req{remote: "127.0.0.1:5000", xff: "203.0.113.9, 198.51.100.7"}, http.StatusForbidden)
	e.expect(req{remote: "127.0.0.1:5000", xff: "198.51.100.7, 203.0.113.9"}, http.StatusCreated)

	// X-Forwarded-For from a non-loopback peer is never trusted.
	e2 := newEnv(t, func(c *config.Ingest) {
		c.BehindProxy = true
		c.AllowCIDRs = []string{"203.0.113.0/24"}
	})
	e2.expect(req{remote: "198.51.100.7:1234", xff: "203.0.113.9"}, http.StatusForbidden)
}

func TestReportedHostnameNamesAutoHosts(t *testing.T) {
	e := newEnv(t, nil)
	ctx := t.Context()
	// A named host ignores the header.
	e.expect(req{hostname: "attacker-chosen"}, http.StatusCreated)
	if _, err := e.st.HostByName(ctx, "acme", "web-01"); err != nil {
		t.Fatalf("named host was renamed: %v", err)
	}
	// A host added without a name takes it from its first stored report.
	auto, token, err := e.st.AddHost(ctx, "test", "acme", "prod", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	e.expect(req{token: token, hostname: "Web-01"}, http.StatusCreated)
	h, err := e.st.HostByName(ctx, "acme", "web-01-2")
	if err != nil || h.ID != auto.ID || h.AutoName {
		t.Fatalf("auto host after first report: %+v %v", h, err)
	}
}

func TestHubVersionForCollectors(t *testing.T) {
	e := newEnv(t, nil)
	e.h.Version = "v9.8.7"
	w := e.expect(req{}, http.StatusCreated)
	if got := w.Header().Get(VersionHeader); got != "v9.8.7" {
		t.Errorf("push response version header = %q", got)
	}
	w = e.expect(req{method: http.MethodGet, body: []byte{}}, http.StatusOK)
	if body := w.Body.String(); body != "{\"version\":\"v9.8.7\"}\n" {
		t.Errorf("GET body = %q", body)
	}
	// Without a valid token: nothing, not even the version.
	w = e.expect(req{method: http.MethodGet, token: "hmd_ingest_" + strings.Repeat("x", 43), body: []byte{}}, http.StatusUnauthorized)
	if w.Header().Get(VersionHeader) != "" || strings.Contains(w.Body.String(), "9.8.7") {
		t.Error("the version leaked to an unauthenticated request")
	}
	e.expect(req{method: http.MethodPut}, http.StatusMethodNotAllowed)
}
