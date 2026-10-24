// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"net/url"
	"strings"
	"sync"
)

// Destination is one place digests and alerts go: email, a generic
// webhook, Slack or Discord.
type Destination interface {
	Sender
	AlertSender
	Name() string // "email", "webhook", "slack:ops", "discord:alerts"
}

// Previewer is a destination that can show the payload it would send.
type Previewer interface {
	PreviewDigest(d Digest) any
	PreviewAlert(a Alert) any
	Target() string // the redacted URL
}

// Result is one destination's outcome.
type Result struct {
	Name string
	Err  error
}

// SendAll runs send for every destination concurrently, so a slow or
// failing one (retrying a 429, say) never delays or blocks the others.
// Results are in the order of dests.
func SendAll(ctx context.Context, dests []Destination, send func(context.Context, Destination) error) []Result {
	out := make([]Result, len(dests))
	var wg sync.WaitGroup
	for i, d := range dests {
		out[i].Name = d.Name()
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i].Err = send(ctx, d)
		}()
	}
	wg.Wait()
	return out
}

// RedactURL keeps a webhook URL's scheme, host and first path segments
// and hides the rest, which for Slack and Discord is the secret:
// "https://hooks.slack.com/services/…".
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(invalid URL)"
	}
	keep := 0
	switch {
	case u.Host == "hooks.slack.com" && strings.HasPrefix(u.Path, "/services/"):
		keep = 1
	case strings.HasPrefix(u.Path, "/api/webhooks/"):
		keep = 2
	}
	segs := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	path := "/"
	if keep > 0 && len(segs) > keep {
		path += strings.Join(segs[:keep], "/") + "/"
	}
	return u.Scheme + "://" + u.Host + path + "…"
}
