// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Slack posts to a Slack incoming webhook as Block Kit, with a plain
// "text" fallback for notifications.
//
// Payload: https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks
// Escaping: https://docs.slack.dev/messaging/formatting-message-text
// (& < > become &amp; &lt; &gt;, so "<!channel>" in a host name is shown,
// never parsed). Limits: a section's text is at most 3,000 characters, a
// header's 150; webhooks allow about one message per second, and a 429
// carries Retry-After.
type Slack struct {
	Label  string // "slack:ops"
	URL    string // https://hooks.slack.com/services/…
	Client *http.Client
	Retry  Retry
}

func (s *Slack) Name() string { return s.Label }

func (s *Slack) Send(ctx context.Context, d Digest) error {
	return s.post(ctx, digestMessage(d))
}

func (s *Slack) SendAlert(ctx context.Context, a Alert) error {
	return s.post(ctx, alertMessage(a))
}

func (s *Slack) PreviewDigest(d Digest) any { return slackPayload(digestMessage(d)) }
func (s *Slack) PreviewAlert(a Alert) any   { return slackPayload(alertMessage(a)) }
func (s *Slack) Target() string             { return RedactURL(s.URL) }

func (s *Slack) post(ctx context.Context, m message) error {
	u, err := SlackURL(s.URL)
	if err != nil {
		return fmt.Errorf("notify: %s: %w", s.Label, err)
	}
	return postJSON(ctx, s.Client, s.Retry, u, s.Label, slackPayload(m))
}

var slackPath = regexp.MustCompile(`^/(services/)?[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+$`)

// SlackURL checks that raw is a Slack incoming webhook URL,
// https://hooks.slack.com/services/T…/B…/… (or the /T…/B…/… form that
// OAuth installs return), and returns it.
func SlackURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host != "hooks.slack.com" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || !slackPath.MatchString(u.Path) {
		return "", errors.New("not a Slack incoming webhook URL (want https://hooks.slack.com/services/T…/B…/…)")
	}
	return u.String(), nil
}

// slackEscape escapes Slack's control characters.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// slackCode renders s as inline code: escaped, and without backticks so it
// can't close the span.
func slackCode(s string) string {
	return "`" + slackEscape(strings.ReplaceAll(s, "`", "'")) + "`"
}

func slackPayload(m message) map[string]any {
	var b strings.Builder
	b.WriteString(slackEscape(m.Lead))
	for _, l := range m.Lines {
		b.WriteString("\n" + slackEscape(l))
	}
	if len(m.Hosts) > 0 {
		b.WriteString("\n")
		for i, h := range m.Hosts {
			if i == maxChatHosts {
				fmt.Fprintf(&b, "\n… and %d more", len(m.Hosts)-maxChatHosts)
				break
			}
			b.WriteString("\n• " + slackCode(h.Host))
			if h.Label != "" {
				b.WriteString("  " + slackEscape(h.Label))
			}
		}
	}
	if m.Note != "" {
		b.WriteString("\n\n" + slackEscape(m.Note))
	}
	ctx := slackEscape(m.Footer)
	if u := safeLinkURL(m.URL); u != "" {
		ctx = "<" + slackEscape(u) + "|" + slackEscape(cmp.Or(m.LinkText, "Open Heimdall")) + "> (sign-in required) · " + ctx
	}
	blocks := []map[string]any{
		{"type": "header", "text": map[string]any{"type": "plain_text", "text": truncate(m.Title, 150), "emoji": false}},
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": truncate(b.String(), 2900)}},
		{"type": "context", "elements": []map[string]any{{"type": "mrkdwn", "text": truncate(ctx, 2000)}}},
	}
	return map[string]any{"text": slackEscape(m.Title), "blocks": blocks}
}
