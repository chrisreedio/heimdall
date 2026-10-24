// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Discord posts to a Discord channel webhook as one embed, coloured by
// severity, with allowed_mentions {"parse": []} so nothing in a message
// can ping @everyone, a role or a user. Host names are also neutralised
// (inline code, and a zero-width space after every "@"), since bots in the
// channel may read the text.
//
// Execute webhook: https://docs.discord.com/developers/resources/webhook
// Embeds and allowed mentions: https://docs.discord.com/developers/resources/message
// Rate limits (429, Retry-After / retry_after): https://docs.discord.com/developers/topics/rate-limits
// Limits: title 256, description 4,096, 6,000 characters across embeds.
type Discord struct {
	Label  string // "discord:alerts"
	URL    string // https://discord.com/api/webhooks/<id>/<token>
	Client *http.Client
	Retry  Retry
}

func (d *Discord) Name() string { return d.Label }

func (d *Discord) Send(ctx context.Context, g Digest) error {
	return d.post(ctx, digestMessage(g))
}

func (d *Discord) SendAlert(ctx context.Context, a Alert) error {
	return d.post(ctx, alertMessage(a))
}

func (d *Discord) PreviewDigest(g Digest) any { return discordPayload(digestMessage(g)) }
func (d *Discord) PreviewAlert(a Alert) any   { return discordPayload(alertMessage(a)) }
func (d *Discord) Target() string             { return RedactURL(d.URL) }

func (d *Discord) post(ctx context.Context, m message) error {
	u, err := DiscordURL(d.URL)
	if err != nil {
		return fmt.Errorf("notify: %s: %w", d.Label, err)
	}
	return postJSON(ctx, d.Client, d.Retry, u, d.Label, discordPayload(m))
}

// DiscordHost is the one host Discord webhooks are sent to.
const DiscordHost = "discord.com"

var (
	discordPath  = regexp.MustCompile(`^/api(/v[0-9]{1,2})?/webhooks/([0-9]{5,25})/([A-Za-z0-9_-]{20,200})$`)
	discordHosts = map[string]bool{"discord.com": true, "discordapp.com": true,
		"ptb.discord.com": true, "canary.discord.com": true}
)

// DiscordURL checks that raw is a Discord channel webhook URL and returns
// it in canonical form, https://discord.com/api/webhooks/<id>/<token>.
// URLs copied from the legacy discordapp.com domain or the PTB and Canary
// clients are the same webhook, so they're accepted and rewritten.
func DiscordURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || !discordHosts[u.Host] || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("not a Discord webhook URL (want https://discord.com/api/webhooks/…)")
	}
	m := discordPath.FindStringSubmatch(u.Path)
	if m == nil {
		return "", errors.New("not a Discord webhook URL (want https://discord.com/api/webhooks/<id>/<token>)")
	}
	return "https://" + DiscordHost + "/api/webhooks/" + m[2] + "/" + m[3], nil
}

// Embed colours by severity.
var discordColors = map[string]int{"high": 0xD93025, "medium": 0xF29900, "ok": 0x1E8E3E, "info": 0x5865F2}

// neutralize stops Discord (and bots reading the channel) from treating
// text as a mention: a zero-width space after "@" breaks @everyone and
// <@id> alike.
func neutralize(s string) string {
	return strings.ReplaceAll(s, "@", "@\u200b")
}

// discordEscape backslash-escapes Discord markdown and neutralises
// mentions, for text outside code spans.
func discordEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune("\\*_~`|[]()<", r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return neutralize(b.String())
}

// discordCode renders s as inline code, where markdown isn't parsed:
// without backticks (so it can't close the span) and with mentions
// neutralised.
func discordCode(s string) string {
	return "`" + neutralize(strings.ReplaceAll(s, "`", "'")) + "`"
}

func discordPayload(m message) map[string]any {
	var b strings.Builder
	b.WriteString(discordEscape(m.Lead))
	for _, l := range m.Lines {
		b.WriteString("\n" + discordEscape(l))
	}
	if len(m.Hosts) > 0 {
		b.WriteString("\n")
		for i, h := range m.Hosts {
			if i == maxChatHosts {
				fmt.Fprintf(&b, "\n… and %d more", len(m.Hosts)-maxChatHosts)
				break
			}
			b.WriteString("\n• " + discordCode(h.Host))
			if h.Label != "" {
				b.WriteString("  " + discordEscape(h.Label))
			}
		}
	}
	if m.Note != "" {
		b.WriteString("\n\n" + discordEscape(m.Note))
	}
	link := safeLinkURL(m.URL)
	if link != "" {
		b.WriteString("\n\n[Open Heimdall](" + link + ") (sign-in required)")
	}
	embed := map[string]any{
		"title":       truncate(neutralize(m.Title), 256),
		"description": truncate(b.String(), 3500),
		"color":       discordColors[m.Severity],
		"footer":      map[string]any{"text": truncate(neutralize(m.Footer), 200)},
	}
	if link != "" {
		embed["url"] = link
	}
	if !m.At.IsZero() {
		embed["timestamp"] = m.At.UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"username":         "Heimdall",
		"embeds":           []map[string]any{embed},
		"allowed_mentions": map[string]any{"parse": []string{}},
	}
}
