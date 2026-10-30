// SPDX-License-Identifier: AGPL-3.0-or-later

package push

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

// hub is a store with two orgs and four users, each with one device:
//
//   - admin (all orgs), bob (viewer of acme), carol (operator of globex),
//     dave (viewer of acme, disabled).
//   - acme has web-01 and web-02, globex db-01.
type hub struct {
	t     *testing.T
	st    *store.Store
	n     *Notifier
	now   time.Time
	users map[string]int64
	hosts map[string]int64
	mu    sync.Mutex
	sent  []sent
	fail  func(endpoint string) error // a delivery's result; nil = success
}

type sent struct {
	user string // the endpoint's owner
	p    payload
	m    Message
}

var start = time.Date(2026, 10, 30, 17, 0, 0, 0, time.UTC) // noon in Chicago

func newHub(t *testing.T) *hub {
	t.Helper()
	ctx := t.Context()
	st := storetest.New(t)
	h := &hub{t: t, st: st, now: start, users: map[string]int64{}, hosts: map[string]int64{}}
	for _, o := range []string{"acme", "globex"} {
		if _, err := st.CreateOrg(ctx, "test", o, o); err != nil {
			t.Fatal(err)
		}
		st.CreateEnv(ctx, "test", o, "prod", "")
	}
	for _, x := range [][2]string{{"acme", "web-01"}, {"acme", "web-02"}, {"globex", "db-01"}} {
		if _, _, err := st.AddHost(ctx, "test", x[0], "prod", x[1], nil); err != nil {
			t.Fatal(err)
		}
		host, _ := st.HostByName(ctx, x[0], x[1])
		h.hosts[x[1]] = host.ID
	}
	for _, u := range []struct {
		name, org string
		role      store.Role
		admin     bool
	}{{"admin", "", "", true}, {"bob", "acme", store.RoleViewer, false}, {"carol", "globex", store.RoleOperator, false},
		{"dave", "acme", store.RoleViewer, false}} {
		email := u.name + "@example.com"
		id, err := st.CreateLocalUser(ctx, "test", email, u.name, u.admin, "$argon2id$x", []byte("0123456789abcdefghij"))
		if err != nil {
			t.Fatal(err)
		}
		h.users[u.name] = id
		if u.org != "" {
			if err := st.Grant(ctx, "test", email, u.org, u.role); err != nil {
				t.Fatal(err)
			}
		}
		h.subscribe(u.name)
	}
	if err := st.SetUserDisabled(ctx, "test", "dave@example.com", true); err != nil {
		t.Fatal(err)
	}
	h.n = &Notifier{Store: st, Now: func() time.Time { return h.now }, Window: 10 * time.Minute,
		Retry: Retry{Attempts: 2, Base: time.Millisecond, Max: time.Millisecond},
		Deliver: func(_ context.Context, tg Target, m Message) error {
			var p payload
			if err := json.Unmarshal(m.Payload, &p); err != nil {
				t.Errorf("payload %s: %v", m.Payload, err)
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			h.sent = append(h.sent, sent{user: strings.TrimPrefix(tg.Endpoint, "https://fcm.googleapis.com/fcm/send/"), p: p, m: m})
			if h.fail != nil {
				return h.fail(tg.Endpoint)
			}
			return nil
		}}
	h.tick() // learns what's there
	return h
}

// subscribe gives a user a device session with a subscription.
func (h *hub) subscribe(name string) {
	h.t.Helper()
	ctx := h.t.Context()
	hash := sha256.Sum256([]byte("session-" + name))
	if err := h.st.CreateDeviceSession(ctx, hash, h.users[name], start.Add(-time.Hour), start.Add(30*24*time.Hour), "100.64.0.1", "Android Chrome"); err != nil {
		h.t.Fatal(err)
	}
	b := newTestBrowser(h.t)
	if err := h.st.SavePushSubscription(ctx, h.users[name], hash, "https://fcm.googleapis.com/fcm/send/"+name,
		b.p256dh, b.auth, "Android Chrome", start); err != nil {
		h.t.Fatal(err)
	}
}

// tick runs one tick and delivers what it queued, here and now.
func (h *hub) tick() {
	h.t.Helper()
	if err := h.n.Tick(h.t.Context()); err != nil {
		h.t.Fatal(err)
	}
	h.drain()
}

func (h *hub) drain() {
	for {
		select {
		case j := <-h.n.jobs:
			h.n.deliver(h.t.Context(), j)
		default:
			return
		}
	}
}

// take returns what was sent since the last take, by user.
func (h *hub) take() map[string][]payload {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string][]payload{}
	for _, s := range h.sent {
		out[s.user] = append(out[s.user], s.p)
	}
	h.sent = nil
	return out
}

func (h *hub) anomaly(host, rule, severity, summary string) {
	h.t.Helper()
	if _, err := h.st.AddAnomaly(h.t.Context(), h.hosts[host], 0, store.Anomaly{Rule: rule, Severity: severity, Summary: summary,
		Detail: map[string]any{"key": time.Now().String()}}, h.now); err != nil {
		h.t.Fatal(err)
	}
}

func (h *hub) settings(name string, edit func(*store.PushSettings)) {
	h.t.Helper()
	p, _ := h.st.PushSettings(h.t.Context(), h.users[name])
	edit(&p)
	if err := h.st.SetPushSettings(h.t.Context(), h.users[name], p); err != nil {
		h.t.Fatal(err)
	}
}

func titles(ps []payload) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Title)
	}
	slices.Sort(out)
	return out
}

// Each user hears only about orgs their role can see; disabled users and
// signed-out devices hear nothing; ban proposals go to operators.
func TestNotifyScope(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	h.anomaly("web-01", "package_drop", "high", "packages vanished")
	h.anomaly("db-01", "collector_changed", "high", "collector changed")
	h.anomaly("web-02", "package_change", "low", "a package changed") // below AlertRule: nobody
	if _, err := h.st.AddBan(t.Context(), store.Ban{Target: "203.0.113.7/32", Kind: "address", Action: "block", Status: store.BanProposed,
		Mode: "propose", Score: 90, Orgs: []int64{2}, Duration: 24 * time.Hour}, "test", h.now); err != nil {
		t.Fatal(err)
	}
	h.tick()
	got := h.take()
	if want := []string{"Anomaly on db-01", "Anomaly on web-01", "Ban proposal waiting for approval"}; !slices.Equal(titles(got["admin"]), want) {
		t.Errorf("admin got %q", titles(got["admin"]))
	}
	if want := []string{"Anomaly on web-01"}; !slices.Equal(titles(got["bob"]), want) {
		t.Errorf("bob (viewer of acme) got %q", titles(got["bob"]))
	}
	if want := []string{"Anomaly on db-01", "Ban proposal waiting for approval"}; !slices.Equal(titles(got["carol"]), want) {
		t.Errorf("carol (operator of globex) got %q", titles(got["carol"]))
	}
	if len(got["dave"]) > 0 {
		t.Errorf("disabled user got %q", titles(got["dave"]))
	}
	for _, p := range got["carol"] {
		if strings.HasPrefix(p.Title, "Ban") && !strings.HasPrefix(p.URL, "/defense#ban-") {
			t.Errorf("ban link %q", p.URL)
		}
	}
	// Nothing new, nothing sent.
	h.now = h.now.Add(time.Minute)
	h.tick()
	if got := h.take(); len(got) > 0 {
		t.Errorf("second tick sent %v", got)
	}
	// A signed-out device gets nothing.
	if err := h.st.DeleteSession(t.Context(), sha256.Sum256([]byte("session-bob"))); err != nil {
		t.Fatal(err)
	}
	h.anomaly("web-02", "trigger_disabled", "medium", "change reporting off")
	h.tick()
	if got := h.take(); len(got["bob"]) > 0 || len(got["admin"]) != 1 {
		t.Errorf("after bob signed out: %v", got)
	}
	subs, _ := h.st.UserPushSubscriptions(t.Context(), h.users["bob"])
	if len(subs) != 0 {
		t.Error("signing out left the subscription")
	}
}

func TestNotifyModesAndDigest(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	h.settings("bob", func(p *store.PushSettings) { p.Modes = map[string]string{KindAnomaly: Off} })
	h.settings("admin", func(p *store.PushSettings) {
		p.Modes = map[string]string{KindAnomaly: Digest}
		p.TimeZone = "America/Chicago"
	})
	h.anomaly("web-01", "package_drop", "high", "x")
	h.tick()
	got := h.take()
	if len(got["bob"]) != 0 || len(got["admin"]) != 0 {
		t.Fatalf("Off and Digest sent now: %v", got)
	}
	// The digest goes at 8 AM in the admin's zone with what was held,
	// and isn't sent twice; bob's (empty) digest isn't sent at all.
	h.now = time.Date(2026, 10, 31, 13, 5, 0, 0, time.UTC) // 8:05 AM CDT
	h.tick()
	got = h.take()
	if len(got["admin"]) != 1 || got["admin"][0].Title != "Daily digest" || !strings.Contains(got["admin"][0].Body, "1 anomaly") {
		t.Fatalf("admin's digest: %+v", got["admin"])
	}
	if len(got["bob"]) != 0 {
		t.Errorf("empty digest sent to bob: %+v", got["bob"])
	}
	h.now = h.now.Add(time.Hour)
	h.tick()
	if got := h.take(); len(got["admin"]) != 0 {
		t.Errorf("second digest: %+v", got["admin"])
	}
	if p, _ := h.st.PushSettings(t.Context(), h.users["admin"]); p.DigestDay != "2026-10-31" {
		t.Errorf("digest day %q", p.DigestDay)
	}
}

func TestDigestFleetCounts(t *testing.T) {
	t.Parallel()
	facts := []fleetFact{{org: 1, security: true, eol: true}, {org: 1, security: true, behind: true}, {org: 2, security: true}}
	ps := fleetParts(facts, store.Scope{Orgs: map[int64]store.Role{1: store.RoleViewer}})
	want := []Part{{"security", 2}, {"eol", 1}, {"behind", 1}}
	if !slices.Equal(ps, want) {
		t.Fatalf("parts %v", ps)
	}
	n := Notice{Kind: kindDigest, Parts: append([]Part{{KindAnomaly, 3}}, ps...)}
	if p := n.payload("Heimdall", DetailHost); p.Body != "3 anomalies, 2 hosts with security updates, 1 host near end of life, 1 collector to upgrade" {
		t.Errorf("digest body %q", p.Body)
	}
	if !releaseTag("v0.5.0") || releaseTag("v0.5.0-3-gabc") || releaseTag("dev") {
		t.Error("releaseTag")
	}
}

// Quiet hours hold notices until they end; known-exploited findings and
// unknown-address privilege come through.
func TestNotifyQuietHours(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	h.settings("bob", func(p *store.PushSettings) { p.TimeZone = "America/Chicago" })
	h.now = time.Date(2026, 10, 31, 4, 0, 0, 0, time.UTC) // 11 PM CDT
	h.anomaly("web-01", "package_drop", "high", "x")
	h.anomaly("web-02", "privilege_unknown_source", "medium", "sudo by alice from 203.0.113.7")
	h.tick()
	got := h.take()
	if want := []string{"Privileged access from an unknown address on web-02"}; !slices.Equal(titles(got["bob"]), want) {
		t.Fatalf("during quiet hours bob got %q", titles(got["bob"]))
	}
	h.anomaly("web-02", "silence", "medium", "no check-in")
	h.now = h.now.Add(5 * time.Hour) // 4 AM: still quiet
	h.tick()
	if got := h.take(); len(got["bob"]) != 0 {
		t.Fatalf("still quiet, sent %q", titles(got["bob"]))
	}
	h.now = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC) // 7 AM CDT
	h.tick()
	got = h.take()
	if len(got["bob"]) != 1 || got["bob"][0].Title != "During quiet hours" ||
		got["bob"][0].Body != "1 anomaly, 1 host stopped reporting" {
		t.Fatalf("after quiet hours: %+v", got["bob"])
	}
}

// Repeats within the window collapse into one notification with a count,
// sent with the same tag when the window ends.
func TestNotifyCollapse(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	h.anomaly("web-01", "package_drop", "high", "x")
	h.tick()
	first := h.take()["bob"]
	if len(first) != 1 || first[0].Title != "Anomaly on web-01" {
		t.Fatalf("first: %+v", first)
	}
	for i := range 2 {
		h.now = h.now.Add(time.Minute)
		h.anomaly("web-01", "collector_changed", "high", "x"+string(rune('a'+i)))
		h.tick()
	}
	if got := h.take()["bob"]; len(got) != 0 {
		t.Fatalf("repeats sent at once: %+v", got)
	}
	h.now = start.Add(11 * time.Minute)
	h.tick()
	got := h.take()["bob"]
	if len(got) != 1 || got[0].Title != "3 anomalies on web-01" || got[0].Tag != first[0].Tag {
		t.Fatalf("collapsed: %+v (first tag %q)", got, first[0].Tag)
	}
	// Another host isn't collapsed with it.
	h.anomaly("web-02", "package_drop", "high", "y")
	h.tick()
	if got := h.take()["bob"]; len(got) != 1 || got[0].Title != "Anomaly on web-02" {
		t.Fatalf("other host: %+v", got)
	}
}

// Many hosts in one go are one notification, not one each.
func TestNotifyGroupsManyHosts(t *testing.T) {
	t.Parallel()
	var evs []Event
	for _, name := range []string{"a", "b", "c", "d"} {
		evs = append(evs, Event{Kind: KindSilent, Host: store.PushHost{OrgSlug: "acme", Name: name}, Count: 1})
	}
	ns := group(evs)
	if len(ns) != 1 || ns[0].Hosts != 4 || ns[0].Host != "" {
		t.Fatalf("group: %+v", ns)
	}
	if p := ns[0].payload("", DetailHost); p.Title != "4 hosts stopped reporting" || p.Tag != KindSilent || p.URL != "/hosts?only=stale&sort=seen" {
		t.Errorf("payload %+v", p)
	}
	if ns := group(evs[:3]); len(ns) != 3 {
		t.Errorf("three hosts: %d notices", len(ns))
	}
}

// Known-exploited findings that newly appear go out at high urgency.
func TestNotifyKEV(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	h.settings("admin", func(p *store.PushSettings) { p.TimeZone = "America/Chicago" })
	h.now = time.Date(2026, 10, 31, 6, 0, 0, 0, time.UTC) // 1 AM CDT: quiet, but KEV comes through
	storetest.SeedKernelCases(t, h.st, "globex", h.now)
	h.tick()
	h.mu.Lock()
	var kev []sent
	for _, s := range h.sent {
		if s.user == "admin" && strings.Contains(s.p.Title, "nown-exploited") {
			kev = append(kev, s)
		}
	}
	h.mu.Unlock()
	if len(kev) == 0 {
		t.Fatalf("no known-exploited notification; sent %+v", h.take())
	}
	if kev[0].m.Urgency != "high" || kev[0].m.TTL != 24*time.Hour || !strings.HasPrefix(kev[0].p.URL, "/hosts/globex/") {
		t.Errorf("KEV message: %+v %+v", kev[0].m, kev[0].p)
	}
	if got := h.take()["bob"]; len(got) != 0 {
		t.Errorf("bob (acme) heard about globex: %+v", got)
	}
}

// "Hidden" shows only the generic line; no notification carries an
// address, a username or an anomaly's summary.
func TestNotifyPrivacy(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	h.settings("bob", func(p *store.PushSettings) { p.Detail = DetailHidden })
	h.anomaly("web-01", "privilege_unknown_source", "medium", "sudo by alice from 203.0.113.7 (openssl 3.0.13)")
	h.anomaly("web-02", "login_then_succeeded", "high", "root logged in from 198.51.100.9 after failures")
	h.st.AddBan(t.Context(), store.Ban{Target: "203.0.113.7/32", Kind: "address", Action: "block", Status: store.BanProposed,
		Mode: "propose", Score: 90, Orgs: []int64{1}, Duration: 24 * time.Hour}, "test", h.now)
	h.tick()
	h.mu.Lock()
	all := h.sent
	h.mu.Unlock()
	if len(all) == 0 {
		t.Fatal("nothing sent")
	}
	for _, s := range all {
		raw := string(s.m.Payload)
		for _, bad := range []string{"203.0.113", "198.51.100", "alice", "root", "openssl", "sudo by"} {
			if strings.Contains(raw, bad) {
				t.Errorf("%s's payload has %q: %s", s.user, bad, raw)
			}
		}
		if s.user == "bob" && (s.p.Title != "Heimdall needs attention" || s.p.URL != "/" || strings.Contains(raw, "web-0")) {
			t.Errorf("hidden payload: %s", raw)
		}
	}
}

// A push service's 404 or 410 deletes the subscription; a success is
// recorded; a 5xx is retried, then recorded. The request is what push
// services expect, and the browser can decrypt it.
func TestSendAndDeadSubscriptions(t *testing.T) {
	t.Parallel()
	st := storetest.New(t)
	ctx := t.Context()
	uid, _ := st.CreateLocalUser(ctx, "test", "a@example.com", "A", true, "$argon2id$x", []byte("0123456789abcdefghij"))
	hash := sha256.Sum256([]byte("s"))
	st.CreateDeviceSession(ctx, hash, uid, start, start.Add(time.Hour), "", "")
	var mu sync.Mutex
	hits := map[string]int{}
	browsers := map[string]testBrowser{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hits[r.URL.Path]++
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Encoding") != "aes128gcm" || r.Header.Get("TTL") != "600" ||
			!strings.HasPrefix(r.Header.Get("Authorization"), "vapid t=") || r.Header.Get("Urgency") != "normal" ||
			len(r.Header.Get("Topic")) != 32 {
			t.Errorf("headers %v", r.Header)
		}
		if b, ok := browsers[r.URL.Path]; ok {
			var p payload
			if err := json.Unmarshal(b.open(t, body), &p); err != nil || p.Title != "Test notification" {
				t.Errorf("decrypted %+v %v", p, err)
			}
		}
		switch r.URL.Path {
		case "/gone":
			w.WriteHeader(http.StatusGone)
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		case "/flaky":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer srv.Close()
	for _, p := range []string{"/ok", "/gone", "/missing", "/flaky", "/forbidden"} {
		b := newTestBrowser(t)
		browsers[p] = b
		if err := st.SavePushSubscription(ctx, uid, hash, srv.URL+p, b.p256dh, b.auth, "x", start); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := NewVAPIDKey()
	v, _ := ParseVAPID(raw)
	n := &Notifier{Store: st, Now: func() time.Time { return start }, Retry: Retry{Attempts: 2, Base: time.Millisecond, Max: time.Millisecond},
		Sender: &Sender{HTTP: srv.Client(), VAPID: v, Subject: "https://hub.example.com", Now: func() time.Time { return start },
			check: func(string) error { return nil }}}
	n.defaults()
	if k, err := n.Test(ctx, uid); err != nil || k != 5 {
		t.Fatalf("Test: %d %v", k, err)
	}
	n.deliver(ctx, <-n.jobs)
	subs, _ := st.UserPushSubscriptions(ctx, uid)
	left := map[string]store.PushSubscription{}
	for _, s := range subs {
		left[strings.TrimPrefix(s.Endpoint, srv.URL)] = s
	}
	if _, ok := left["/gone"]; ok {
		t.Error("410 left the subscription")
	}
	if _, ok := left["/missing"]; ok {
		t.Error("404 left the subscription")
	}
	if s := left["/ok"]; s.LastOKAt.IsZero() || s.LastError != "" {
		t.Errorf("ok: %+v", s)
	}
	if s := left["/flaky"]; s.LastError != "push service answered HTTP 503" || hits["/flaky"] != 2 {
		t.Errorf("flaky: %q after %d tries", s.LastError, hits["/flaky"])
	}
	if s := left["/forbidden"]; s.LastError == "" || hits["/forbidden"] != 1 {
		t.Errorf("403 retried or not recorded: %q, %d tries", s.LastError, hits["/forbidden"])
	}
	// The real check refuses the test server's address at send time (dev
	// builds allow loopback, for a local fake push service).
	if devLoopback {
		return
	}
	n.Sender.check = nil
	if err := n.Sender.Send(ctx, Target{Endpoint: srv.URL + "/ok", P256DH: browsers["/ok"].p256dh, Auth: browsers["/ok"].auth},
		Message{Payload: []byte(`{}`), TTL: time.Minute}); !errors.Is(err, ErrEndpoint) {
		t.Errorf("send to a loopback endpoint: %v", err)
	}
}
