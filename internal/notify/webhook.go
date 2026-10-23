// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Webhook posts digests to an HTTPS endpoint, as a Slack-style message
// ({"text": ...}) or as the Digest's JSON.
type Webhook struct {
	URL    string
	Format string // "slack" or "json"
	// Client must be supplied by the caller (an allowlisted client that
	// doesn't follow redirects to other hosts).
	Client *http.Client
}

func (w *Webhook) Send(ctx context.Context, d Digest) error {
	if w.Client == nil {
		return errors.New("notify: webhook needs an HTTP client")
	}
	u, err := url.Parse(w.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("notify: webhook URL must be https")
	}
	var payload any
	switch w.Format {
	case "slack":
		payload = map[string]string{"text": d.Subject() + "\n\n" + d.Text()}
	case "json":
		payload = d
	default:
		return fmt.Errorf("notify: unknown webhook format %q (want slack or json)", w.Format)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "heimdall-notify")
	resp, err := w.Client.Do(req)
	if err != nil {
		// *url.Error embeds the URL, which may contain a secret.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("notify: webhook: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The URL may embed a secret (Slack does), so it's not echoed.
		return fmt.Errorf("notify: webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}
