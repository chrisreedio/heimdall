// SPDX-License-Identifier: AGPL-3.0-or-later

package tailscale

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/netx"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

// Test credentials: obviously fake, never real.
const (
	testClientID = "kTESTCLIENT"
	testSecret   = "tskey-client-kTESTCLIENT-notarealsecret"
	testAPIKey   = "tskey-api-kTESTKEY-notarealsecret"
)

const devicesJSON = `{"devices":[
 {"id":"1001","nodeId":"nLAPTOP","addresses":["100.101.102.103","fd7a:115c:a1e0::1"],"user":"alice@example.com",
  "name":"laptop-01.tail1234.ts.net","hostname":"laptop-01","clientVersion":"1.90.1","os":"macOS",
  "connectedToControl":true,"lastSeen":"2026-10-24T11:59:00Z","keyExpiryDisabled":false,"expires":"2026-11-01T00:00:00Z"},
 {"id":"1002","nodeId":"nWEB01","addresses":["100.64.0.5","fd7a:115c:a1e0::5"],"user":"bob@example.com",
  "name":"web-01.tail1234.ts.net","hostname":"web-01","clientVersion":"1.88.0","os":"linux","tags":["tag:server"],
  "connectedToControl":false,"lastSeen":"2026-10-21T08:00:00Z","keyExpiryDisabled":true,"expires":"0001-01-01T00:00:00Z"}
]}`

type fakeAPI struct {
	srv                   *httptest.Server
	tokens, lists, keyGet atomic.Int32
	fail                  atomic.Bool
	lastAuth              atomic.Value
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/oauth/token":
			r.ParseForm()
			if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != testClientID || r.PostForm.Get("client_secret") != testSecret {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			f.tokens.Add(1)
			io.WriteString(w, `{"access_token":"tskey-test-access","token_type":"Bearer","expires_in":3600,"scope":"devices:core:read"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/tailnet/-/devices":
			f.lastAuth.Store(r.Header.Get("Authorization"))
			if a := r.Header.Get("Authorization"); a != "Bearer tskey-test-access" && a != "Bearer "+testAPIKey {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if f.fail.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			f.lists.Add(1)
			io.WriteString(w, devicesJSON)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/tailnet/-/keys/kTESTKEY":
			f.keyGet.Add(1)
			io.WriteString(w, `{"id":"kTESTKEY","keyType":"api","expires":"2026-11-02T00:00:00Z"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) client(cred Credential, now time.Time) *Client {
	return &Client{Cred: cred, Tailnet: "-", HTTP: netx.NewForTest(f.srv.Client()), BaseURL: f.srv.URL + "/api/v2",
		Now: func() time.Time { return now }}
}

var testNow = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func TestOAuthDevices(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(Credential{ClientID: testClientID, ClientSecret: testSecret}, testNow)
	for range 2 {
		devs, err := c.Devices(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(devs) != 2 {
			t.Fatalf("devices: %+v", devs)
		}
		l, w := devs[0], devs[1]
		if l.ID != "nLAPTOP" || l.User != "alice@example.com" || !l.Online || l.KeyExpiry.IsZero() || l.Name != "laptop-01.tail1234.ts.net" {
			t.Errorf("laptop: %+v", l)
		}
		if w.User != "" || !w.KeyExpiryDisabled || !w.KeyExpiry.IsZero() || w.Online || len(w.Tags) != 1 {
			t.Errorf("tagged server: %+v", w)
		}
	}
	if f.tokens.Load() != 1 {
		t.Errorf("token exchanged %d times, want 1 (cached for its hour)", f.tokens.Load())
	}
	if exp, err := c.KeyExpiry(t.Context()); err != nil || !exp.IsZero() {
		t.Errorf("OAuth key expiry = %v, %v", exp, err)
	}

	bad := f.client(Credential{ClientID: testClientID, ClientSecret: "tskey-client-wrong"}, testNow)
	_, err := bad.Devices(t.Context())
	if err == nil || !strings.Contains(err.Error(), "set-key") || strings.Contains(err.Error(), "tskey-client-wrong") {
		t.Errorf("refused client: %v", err)
	}
}

func TestAPIKeyDevicesAndExpiry(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(Credential{APIKey: testAPIKey}, testNow)
	if _, err := c.Devices(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.tokens.Load() != 0 || f.lastAuth.Load() != "Bearer "+testAPIKey {
		t.Errorf("tokens %d, auth %v", f.tokens.Load(), f.lastAuth.Load())
	}
	exp, err := c.KeyExpiry(t.Context())
	if err != nil || !exp.Equal(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("expiry %v %v", exp, err)
	}
}

func TestCredentialFile(t *testing.T) {
	for _, c := range []Credential{{APIKey: testAPIKey}, {ClientID: testClientID, ClientSecret: testSecret}} {
		got, err := ParseCredential("# comment\n" + c.Encode())
		if err != nil || got != c {
			t.Errorf("round trip %+v: %+v %v", c, got, err)
		}
	}
	for _, bad := range []string{"", "api_key = two words", "oauth_client_id = x", "nonsense", "api_key = a\noauth_client_id = b\noauth_client_secret = c", "token = x"} {
		if _, err := ParseCredential(bad); err == nil {
			t.Errorf("%q accepted", bad)
		} else if strings.Contains(err.Error(), "two words") {
			t.Errorf("error echoes the secret: %v", err)
		}
	}
	if APIKeyID(testAPIKey) != "kTESTKEY" || APIKeyID("tskey-client-x-y") != "" {
		t.Error("APIKeyID")
	}
}

func TestLabels(t *testing.T) {
	f := newFakeAPI(t)
	devs, err := f.client(Credential{APIKey: testAPIKey}, testNow).Devices(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	labels := Labels(devs, nil, testNow)
	want := map[string]string{
		"100.101.102.103/32":    "staff laptop-01 alice@example.com",
		"fd7a:115c:a1e0::1/128": "staff laptop-01 alice@example.com",
		"100.64.0.5/32":         "infra web-01 ",
		"fd7a:115c:a1e0::5/128": "infra web-01 ",
	}
	if len(labels) != len(want) {
		t.Fatalf("labels: %+v", labels)
	}
	for _, l := range labels {
		if got := l.Kind + " " + l.Name + " " + l.Person; got != want[l.Prefix.String()] {
			t.Errorf("%s: %q, want %q", l.Prefix, got, want[l.Prefix.String()])
		}
		if l.Source != Source {
			t.Errorf("source %q", l.Source)
		}
	}
	if n := labels[2].Note; n != "Tailscale · tag:server · linux · last seen 3 days ago" {
		t.Errorf("note %q", n)
	}
	if n := labels[0].Note; n != "Tailscale · macOS · online" {
		t.Errorf("note %q", n)
	}
	// A person's device that is one of your hosts is infra.
	if l := Labels(devs, map[string]bool{"nLAPTOP": true}, testNow); l[0].Kind != store.IPKindInfra {
		t.Errorf("server-matched device: %+v", l[0])
	}
}

func TestMatch(t *testing.T) {
	devs := []store.TailnetDevice{
		{ID: "a", Name: "web-01.tail1234.ts.net", Hostname: "ip-10-0-0-5", Addresses: []string{"100.64.0.5"}},
		{ID: "b", Name: "db-01.tail1234.ts.net", Hostname: "WEB-02", Addresses: []string{"100.64.0.6", "fd7a:115c:a1e0::6"}},
		{ID: "c", Name: "web-03.tail1234.ts.net", Hostname: "web-03", LastSeen: testNow.Add(-time.Hour)},
		{ID: "d", Name: "web-03-1.tail1234.ts.net", Hostname: "web-03", LastSeen: testNow},
	}
	for _, c := range []struct{ name, ip, want string }{
		{"web-01", "", "a"},
		{"Web-01.example.com", "", "a"}, // ignores case and domain
		{"web-02", "", "b"},             // by hostname
		{"renamed", "100.64.0.6", "b"},  // by report address
		{"renamed", "::ffff:100.64.0.6", "b"},
		{"web-03", "", "c"},           // MagicDNS name before hostname
		{"web-04", "203.0.113.9", ""}, // not on the tailnet
		{"", "", ""},
	} {
		d, ok := Match(devs, c.name, c.ip)
		if c.want == "" && ok || c.want != "" && d.ID != c.want {
			t.Errorf("%s/%s: %q %v, want %q", c.name, c.ip, d.ID, ok, c.want)
		}
	}
	// Two devices with the same hostname: the most recently seen.
	if d, _ := Match(devs[3:], "web-03", ""); d.ID != "d" {
		t.Errorf("got %s", d.ID)
	}
	if d, _ := Match(append([]store.TailnetDevice{devs[2]}, devs[3]), "web-03", ""); d.ID != "c" {
		t.Errorf("MagicDNS exact: %s", d.ID)
	}
}

func TestSyncKeepsLastGood(t *testing.T) {
	st := storetest.New(t)
	ctx := t.Context()
	org, err := st.CreateOrg(ctx, "test", "acme", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateEnv(ctx, "test", org.Slug, "prod", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.AddHost(ctx, "test", "acme", "prod", "web-01", nil); err != nil {
		t.Fatal(err)
	}
	f := newFakeAPI(t)
	s := &Syncer{Store: st, Client: f.client(Credential{APIKey: testAPIKey}, testNow), Period: time.Minute, Now: func() time.Time { return testNow }}
	res, err := s.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Devices != 2 || res.Labels != 4 || res.Hosts != 1 || res.KeyExpires.IsZero() {
		t.Errorf("result %+v", res)
	}
	check := func() {
		t.Helper()
		labels, _ := st.IPLabels(ctx, org.ID)
		devs, _ := st.TailnetDevices(ctx)
		if len(labels) != 4 || len(devs) != 2 {
			t.Fatalf("labels %d, devices %d", len(labels), len(devs))
		}
		if devs[0].ID != "nLAPTOP" || devs[0].Addresses[1] != "fd7a:115c:a1e0::1" || !devs[0].LastSeen.Equal(time.Date(2026, 10, 24, 11, 59, 0, 0, time.UTC)) {
			t.Errorf("stored device %+v", devs[0])
		}
	}
	check()
	f.fail.Store(true)
	if err := s.Sync(ctx); err == nil {
		t.Fatal("sync should fail")
	}
	check()
	state, err := st.TailnetSyncState(ctx)
	if err != nil || state.Error == "" || !state.SyncedAt.Equal(testNow) || state.Devices != 2 || state.Credential != KindAPIKey || state.KeyExpires.IsZero() {
		t.Errorf("state %+v %v", state, err)
	}
	if strings.Contains(state.Error, testAPIKey) {
		t.Error("error stores the key")
	}
}
