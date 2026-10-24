// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// No test here reaches a real Slack or Discord: every client is rewired to
// a local httptest server, whatever host the request names.

type fakeChat struct {
	srv    *httptest.Server
	mu     sync.Mutex
	bodies [][]byte
	paths  []string
	// respond writes the n-th (0-based) response; nil = 204.
	respond func(n int, w http.ResponseWriter)
}

func newFakeChat(t *testing.T) *fakeChat {
	f := &fakeChat{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		n := len(f.bodies)
		f.bodies = append(f.bodies, b)
		f.paths = append(f.paths, r.Host+r.URL.Path)
		respond := f.respond
		f.mu.Unlock()
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type %q", r.Header.Get("Content-Type"))
		}
		if respond != nil {
			respond(n, w)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// client sends every request to the fake server, keeping the original
// Host so tests can see where it was addressed.
func (f *fakeChat) client() *http.Client {
	base := f.srv.Client().Transport
	target, _ := url.Parse(f.srv.URL)
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Host = r.URL.Host
		r.URL.Scheme, r.URL.Host = "https", target.Host
		return base.RoundTrip(r)
	})}
}

func (f *fakeChat) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

func (f *fakeChat) last(t *testing.T) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.bodies) == 0 {
		t.Fatal("nothing sent")
	}
	var v map[string]any
	if err := json.Unmarshal(f.bodies[len(f.bodies)-1], &v); err != nil {
		t.Fatalf("payload %s: %v", f.bodies[len(f.bodies)-1], err)
	}
	return v
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const (
	slackURL   = "https://hooks.slack.com/services/T0000/B0000/XXXXsecretXXXX"
	discordURL = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz_SECRET-1"
	nastyHost  = "acme/<!channel> @everyone **x** `y` <@&123>"
)

// recordSleeps returns a Retry that records waits instead of sleeping.
func recordSleeps(waits *[]time.Duration) Retry {
	var mu sync.Mutex
	return Retry{Sleep: func(_ context.Context, d time.Duration) error {
		mu.Lock()
		*waits = append(*waits, d)
		mu.Unlock()
		return nil
	}}
}

func silentAlert(hosts ...string) Alert {
	return Alert{Kind: KindSilent, GeneratedAt: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC),
		Hosts: hosts, Count: len(hosts), AlertAfter: "3h0m0s", URL: "https://heimdall.example.ts.net/anomalies"}
}

func TestSlackPayloadAndEscaping(t *testing.T) {
	f := newFakeChat(t)
	s := &Slack{Label: "slack:ops", URL: slackURL, Client: f.client()}
	if err := s.SendAlert(t.Context(), silentAlert("acme/web-01", nastyHost)); err != nil {
		t.Fatal(err)
	}
	if got := f.paths[0]; got != "hooks.slack.com/services/T0000/B0000/XXXXsecretXXXX" {
		t.Errorf("posted to %q", got)
	}
	p := f.last(t)
	if p["text"] != "Heimdall: 2 hosts stopped reporting" {
		t.Errorf("fallback text = %v", p["text"])
	}
	blocks := p["blocks"].([]any)
	if len(blocks) != 3 || blocks[0].(map[string]any)["type"] != "header" {
		t.Fatalf("blocks = %v", blocks)
	}
	section := blocks[1].(map[string]any)["text"].(map[string]any)["text"].(string)
	if !strings.Contains(section, "• `acme/web-01`") || !strings.Contains(section, "more than 3h,") {
		t.Errorf("section = %q", section)
	}
	// Slack's control characters are escaped, and the host is in a code
	// span it can't close.
	if !strings.Contains(section, "`acme/&lt;!channel&gt; @everyone **x** 'y' &lt;@&amp;123&gt;`") {
		t.Errorf("host not escaped: %q", section)
	}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "<!channel>") || strings.Contains(string(raw), `<!channel`) {
		t.Errorf("unescaped mention in %s", raw)
	}
	ctx := blocks[2].(map[string]any)["elements"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.HasPrefix(ctx, "<https://heimdall.example.ts.net/anomalies|Open Heimdall>") {
		t.Errorf("context = %q", ctx)
	}
}

func TestSlackDigest(t *testing.T) {
	f := newFakeChat(t)
	s := &Slack{Label: "slack:ops", URL: slackURL, Client: f.client()}
	if err := s.Send(t.Context(), sample()); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f.last(t))
	for _, want := range []string{"2 known exploited", "5 critical", "12 hosts", "Counts only"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("digest payload lacks %q: %s", want, raw)
		}
	}
}

func TestDiscordPayloadAndMentions(t *testing.T) {
	f := newFakeChat(t)
	d := &Discord{Label: "discord:alerts", URL: discordURL, Client: f.client()}
	a := Alert{Kind: KindAnomaly, GeneratedAt: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC), Count: 2,
		Hosts: []string{nastyHost}, URL: "https://heimdall.example.ts.net/anomalies",
		Anomalies: []AlertAnomaly{{Host: nastyHost, Rule: "privilege_watch_disabled", Severity: "high"},
			{Host: "acme/db-01", Rule: "privileged_access", Severity: "medium"}}}
	if err := d.SendAlert(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	raw := string(f.bodies[0])
	f.mu.Unlock()
	if !strings.Contains(raw, `"allowed_mentions":{"parse":[]}`) {
		t.Errorf("allowed_mentions missing: %s", raw)
	}
	p := f.last(t)
	embed := p["embeds"].([]any)[0].(map[string]any)
	desc := embed["description"].(string)
	if strings.Contains(desc, "@everyone") || strings.Contains(desc, "<@&123>") || strings.Contains(desc, "**x** `y`") {
		t.Errorf("mention or markdown survived: %q", desc)
	}
	if !strings.Contains(desc, "`acme/<!channel> @\u200beveryone **x** 'y' <@\u200b&123>`  privilege watch disabled") {
		t.Errorf("host line = %q", desc)
	}
	if !strings.Contains(desc, "[Open Heimdall](https://heimdall.example.ts.net/anomalies)") {
		t.Errorf("no link: %q", desc)
	}
	if embed["color"].(float64) != float64(discordColors["high"]) || embed["title"] != "Heimdall: 2 new anomalies need a look" ||
		embed["url"] != "https://heimdall.example.ts.net/anomalies" || embed["timestamp"] != "2026-10-23T12:00:00Z" {
		t.Errorf("embed = %v", embed)
	}
	// The anomaly's summary (which may name packages or users) is never sent.
	if strings.Contains(raw, "summary") {
		t.Errorf("summary leaked: %s", raw)
	}

	if err := d.SendAlert(t.Context(), Alert{Kind: KindBack, Hosts: []string{"acme/web-01"}, Count: 1}); err != nil {
		t.Fatal(err)
	}
	if c := f.last(t)["embeds"].([]any)[0].(map[string]any)["color"].(float64); c != float64(discordColors["ok"]) {
		t.Errorf("back colour = %x", int(c))
	}
}

func TestChatCapsHosts(t *testing.T) {
	var hosts []string
	for i := range 80 {
		hosts = append(hosts, "acme/host-"+strings.Repeat("x", 100)+string(rune('a'+i%26)))
	}
	p := discordPayload(alertMessage(silentAlert(hosts...)))
	desc := p["embeds"].([]map[string]any)[0]["description"].(string)
	if !strings.Contains(desc, "… and 60 more") || len([]rune(desc)) > 4096 {
		t.Errorf("discord description: %d runes", len([]rune(desc)))
	}
	sp := slackPayload(alertMessage(silentAlert(hosts...)))
	text := sp["blocks"].([]map[string]any)[1]["text"].(map[string]any)["text"].(string)
	if len([]rune(text)) > 3000 {
		t.Errorf("slack section: %d runes", len([]rune(text)))
	}
}

func TestRetryHonoursRetryAfter(t *testing.T) {
	f := newFakeChat(t)
	f.respond = func(n int, w http.ResponseWriter) {
		switch n {
		case 0:
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
		case 1: // Discord's body form, no header
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"message":"You are being rate limited.","retry_after":1.5,"global":false}`)
		case 2:
			w.WriteHeader(http.StatusBadGateway)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}
	var waits []time.Duration
	d := &Discord{Label: "discord:alerts", URL: discordURL, Client: f.client(), Retry: recordSleeps(&waits)}
	if err := d.SendAlert(t.Context(), silentAlert("acme/web-01")); err != nil {
		t.Fatal(err)
	}
	if f.count() != 4 || len(waits) != 3 || waits[0] != 7*time.Second || waits[1] != 1500*time.Millisecond ||
		waits[2] < 4*time.Second || waits[2] > 5*time.Second {
		t.Errorf("attempts %d, waits %v", f.count(), waits)
	}

	// Retry-After is capped.
	f.mu.Lock()
	f.bodies = nil
	f.mu.Unlock()
	f.respond = func(n int, w http.ResponseWriter) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}
	waits = nil
	err := d.SendAlert(t.Context(), silentAlert("acme/web-01"))
	if err == nil || !strings.Contains(err.Error(), "429") || f.count() != 4 || waits[0] != time.Minute {
		t.Errorf("capped: %v, %d attempts, waits %v", err, f.count(), waits)
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "discord.com") {
		t.Errorf("error leaks the URL: %v", err)
	}
}

func TestNoRetryOnClientError(t *testing.T) {
	f := newFakeChat(t)
	f.respond = func(n int, w http.ResponseWriter) {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "no_service")
	}
	var waits []time.Duration
	s := &Slack{Label: "slack:ops", URL: slackURL, Client: f.client(), Retry: recordSleeps(&waits)}
	err := s.SendAlert(t.Context(), silentAlert("acme/web-01"))
	if err == nil || f.count() != 1 || len(waits) != 0 {
		t.Fatalf("%v after %d attempts", err, f.count())
	}
	if err.Error() != "notify: slack:ops: HTTP 404 (no_service)" {
		t.Errorf("error = %q", err)
	}
}

func TestSendAllIsolatesFailures(t *testing.T) {
	good, bad := newFakeChat(t), newFakeChat(t)
	bad.respond = func(n int, w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }
	var waits []time.Duration
	dests := []Destination{
		&Slack{Label: "slack:ops", URL: slackURL, Client: bad.client(), Retry: recordSleeps(&waits)},
		&Discord{Label: "discord:alerts", URL: discordURL, Client: good.client()},
		&Discord{Label: "discord:broken", URL: "https://example.com/not-discord", Client: good.client()},
	}
	res := SendAll(t.Context(), dests, func(ctx context.Context, d Destination) error {
		return d.SendAlert(ctx, silentAlert("acme/web-01"))
	})
	if res[0].Name != "slack:ops" || res[0].Err == nil || bad.count() != 4 {
		t.Errorf("slack: %+v after %d attempts", res[0], bad.count())
	}
	if res[1].Err != nil || good.count() != 1 {
		t.Errorf("discord: %+v (%d sent)", res[1], good.count())
	}
	if res[2].Err == nil || good.count() != 1 {
		t.Errorf("an invalid URL was sent to: %+v", res[2])
	}
}

func TestURLValidation(t *testing.T) {
	for raw, ok := range map[string]bool{
		slackURL: true,
		"https://hooks.slack.com/T0000/B0000/XXXX":                   true, // OAuth form
		"http://hooks.slack.com/services/T0000/B0000/XXXX":           false,
		"https://hooks.slack.com.evil.example/services/T0/B0/X":      false,
		"https://evil.example/services/T0000/B0000/XXXX":             false,
		"https://hooks.slack.com/services/T0000/B0000/XXXX?x=1":      false,
		"https://user:pw@hooks.slack.com/services/T0000/B0000/XXXX":  false,
		"https://hooks.slack.com:8443/services/T0000/B0000/XXXX":     false,
		"https://hooks.slack.com/services/T0000/B0000/../../x/y/zzz": false,
	} {
		if _, err := SlackURL(raw); (err == nil) != ok {
			t.Errorf("SlackURL(%q) = %v", raw, err)
		}
	}
	for raw, want := range map[string]string{
		discordURL: discordURL,
		"https://discordapp.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz_SECRET-1":         discordURL,
		"https://ptb.discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz_SECRET-1":        discordURL,
		"https://canary.discord.com/api/v10/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz_SECRET-1": discordURL,
		"http://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz_SECRET-1":             "",
		"https://discord.com.evil.example/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz":        "",
		"https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz_SECRET-1?wait=1":     "",
		"https://discord.com/api/channels/123456789012345678/messages":                                       "",
		"https://evil.discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz_SECRET-1":       "",
	} {
		got, err := DiscordURL(raw)
		if got != want || (err == nil) != (want != "") {
			t.Errorf("DiscordURL(%q) = %q, %v", raw, got, err)
		}
	}
	for raw, want := range map[string]string{
		slackURL:   "https://hooks.slack.com/services/…",
		discordURL: "https://discord.com/api/webhooks/…",
		"https://siem.example.com/hook/abc?token=x": "https://siem.example.com/…",
	} {
		if got := RedactURL(raw); got != want {
			t.Errorf("RedactURL(%q) = %q", raw, got)
		}
	}
}

func TestAlertRule(t *testing.T) {
	for _, c := range []struct {
		rule, sev string
		want      bool
	}{
		{"trigger_disabled", "high", true}, {"privilege_watch_disabled", "high", true},
		{"privileged_access", "medium", true}, {"collector_changed", "high", true}, {"replay", "high", true},
		{"package_change", "medium", false}, {"unexpected_reboot", "low", false}, {"silence", "high", false},
	} {
		if got := AlertRule(c.rule, c.sev); got != c.want {
			t.Errorf("AlertRule(%s, %s) = %v", c.rule, c.sev, got)
		}
	}
	if s := (Alert{Kind: KindTest}).Text(); !strings.Contains(s, "test") || !strings.Contains(s, "nothing needs doing") {
		t.Errorf("test text = %q", s)
	}
}

func TestDiscordPostPayloadFile(t *testing.T) {
	var ct, payload, file, name string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Error(err)
		}
		payload = r.FormValue("payload_json")
		if fh := r.MultipartForm.File["files[0]"]; len(fh) == 1 {
			name = fh[0].Filename
			f, _ := fh[0].Open()
			b, _ := io.ReadAll(f)
			file = string(b)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	d := &Discord{Label: "discord:agents", URL: "https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz",
		Client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			r = r.Clone(r.Context())
			r.URL.Scheme, r.URL.Host = u.Scheme, u.Host
			return http.DefaultTransport.RoundTrip(r)
		})}, Retry: Retry{Attempts: 1}}
	if err := d.PostPayloadFile(t.Context(), map[string]any{"content": "hi"}, "a \"b\".json", []byte(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, "multipart/form-data; boundary=") || payload != `{"content":"hi"}` || file != `{"x":1}` || name != `a "b".json` {
		t.Errorf("ct %q payload %q file %q name %q", ct, payload, file, name)
	}
}
