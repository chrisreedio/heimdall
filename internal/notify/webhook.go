// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Webhook posts digests to an HTTPS endpoint, as a Slack-style message
// ({"text": ...}) or as the Digest's (or Alert's) JSON.
type Webhook struct {
	Label  string // "webhook" or "webhook:<name>"; "" = "webhook"
	URL    string
	Format string // "slack" or "json"
	// Client must be supplied by the caller (an allowlisted client that
	// doesn't follow redirects to other hosts).
	Client *http.Client
	Retry  Retry
}

func (w *Webhook) Name() string {
	if w.Label == "" {
		return "webhook"
	}
	return w.Label
}

func (w *Webhook) Send(ctx context.Context, d Digest) error {
	return w.post(ctx, w.payload(d.Subject()+"\n\n"+d.Text(), d))
}

// SendAlert posts an alert: Slack-style text, or the Alert's JSON (which
// has a "kind" field, so a receiver can tell it from a digest).
func (w *Webhook) SendAlert(ctx context.Context, a Alert) error {
	return w.post(ctx, w.payload(a.Subject()+"\n\n"+a.Text(), a.capped()))
}

func (w *Webhook) PreviewDigest(d Digest) any {
	return w.payload(d.Subject()+"\n\n"+d.Text(), d)
}
func (w *Webhook) PreviewAlert(a Alert) any {
	return w.payload(a.Subject()+"\n\n"+a.Text(), a.capped())
}
func (w *Webhook) Target() string { return RedactURL(w.URL) }

func (w *Webhook) payload(text string, asJSON any) any {
	if w.Format == "slack" {
		return map[string]string{"text": text}
	}
	return asJSON
}

func (w *Webhook) post(ctx context.Context, payload any) error {
	if w.Client == nil {
		return errors.New("notify: webhook needs an HTTP client")
	}
	if _, err := WebhookURL(w.URL); err != nil {
		return fmt.Errorf("notify: %s: %w", w.Name(), err)
	}
	if w.Format != "slack" && w.Format != "json" {
		return fmt.Errorf("notify: unknown webhook format %q (want slack or json)", w.Format)
	}
	return postJSON(ctx, w.Client, w.Retry, w.URL, w.Name(), payload)
}

// WebhookURL checks that raw is an https URL with a host and no
// credentials in the userinfo part.
func WebhookURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return "", errors.New("webhook URL must be https")
	}
	return u.String(), nil
}
