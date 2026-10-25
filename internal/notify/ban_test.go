// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func banCard() Alert {
	at := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	b := &AlertBan{ID: 12, Target: "203.0.113.7", Kind: "address", Action: "block", Reason: "failed, then logged in", Days: 14,
		Offense: 2, Score: 23.4, Prefix: "203.0.113.0/24", Network: "AS64500 Example ISP @everyone (US)",
		Hosts: []string{"acme/web-01", "acme/web-02"}, Failures: 120, Usernames: 9, First: at.Add(-48 * time.Hour), Last: at,
		Succeeded: true, Known: "nothing known"}
	return Alert{Kind: KindBan, GeneratedAt: at, Hosts: b.Hosts, Count: 1, URL: "https://heimdall.example.com/bans#ban-12", Ban: b}
}

func TestBanCard(t *testing.T) {
	a := banCard()
	if s := a.Subject(); s != "Heimdall: ban proposed for 203.0.113.7 (block for 14 days)" {
		t.Errorf("subject %q", s)
	}
	if a.Severity() != "high" {
		t.Errorf("severity %s", a.Severity())
	}
	text := a.Text()
	for _, want := range []string{"203.0.113.0/24", "AS64500 Example ISP", "120 on 2 hosts", "9 distinct usernames", "THEN SUCCEEDED",
		"IP awareness: nothing known", "block for 14 days (offense 2: doubled)", "Score: 23.4", "acme/web-01",
		"Approve / review (sign-in required): https://heimdall.example.com/bans#ban-12", "Nothing is banned until an operator approves it"} {
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q:\n%s", want, text)
		}
	}

	d := &Discord{Label: "discord:ops", URL: "https://discord.com/api/webhooks/123456/abcdefghijklmnopqrstuvwxyz"}
	raw, _ := json.Marshal(d.PreviewAlert(a))
	s := string(raw)
	for _, want := range []string{`[Approve / review](https://heimdall.example.com/bans#ban-12)`, `"parse":[]`, "@\u200beveryone", "203.0.113.7"} {
		if !strings.Contains(s, want) {
			t.Errorf("discord missing %q: %s", want, s)
		}
	}
	sl := &Slack{Label: "slack:ops", URL: "https://hooks.slack.com/services/T0/B0/x"}
	raw, _ = json.Marshal(sl.PreviewAlert(a))
	if !strings.Contains(string(raw), "|Approve / review") {
		t.Errorf("slack: %s", raw)
	}
	w := &Webhook{URL: "https://hooks.example.com/x", Format: "json"}
	raw, _ = json.Marshal(w.PreviewAlert(a))
	if !strings.Contains(string(raw), `"ban":{"id":12,"target":"203.0.113.7"`) {
		t.Errorf("webhook: %s", raw)
	}

	// Auto mode says it's done, and links to review.
	a.Ban.Auto = true
	if !strings.HasPrefix(a.Subject(), "Heimdall: banned 203.0.113.7") || a.banLinkText() != "Review bans" {
		t.Errorf("auto: %s", a.Subject())
	}

	// The shadow digest.
	sh := Alert{Kind: KindBanShadow, GeneratedAt: a.GeneratedAt, URL: "https://heimdall.example.com/bans",
		Ban: &AlertBan{Would: 2, Top: []string{"203.0.113.7 (block, score 23.4)", "198.51.100.0/24 (challenge, score 15.0)"}}}
	if sh.Subject() != "Heimdall: shadow mode would have banned 2 targets" || !strings.Contains(sh.Text(), "198.51.100.0/24") ||
		!strings.Contains(sh.Text(), "nothing was written to Cloudflare") {
		t.Errorf("shadow: %s\n%s", sh.Subject(), sh.Text())
	}
}
