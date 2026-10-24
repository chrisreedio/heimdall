// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Retry is how a chat or webhook destination retries a failed send:
// transport errors, HTTP 429 and 5xx are retried with exponential backoff,
// and a 429's Retry-After (header, or Discord's retry_after field) is
// honoured. Other 4xx (a deleted webhook, a malformed payload) are not
// retried. The zero value means 4 attempts, 1s base, 60s cap.
type Retry struct {
	Attempts int           // total tries; 0 = 4
	Base     time.Duration // first backoff; 0 = 1s
	Max      time.Duration // cap on any single wait, Retry-After included; 0 = 60s
	// Sleep waits (tests record the waits instead). nil sleeps on ctx.
	Sleep func(ctx context.Context, d time.Duration) error
}

func (r Retry) attempts() int {
	if r.Attempts <= 0 {
		return 4
	}
	return r.Attempts
}

func (r Retry) wait(i int, retryAfter time.Duration) time.Duration {
	maxWait := r.Max
	if maxWait <= 0 {
		maxWait = time.Minute
	}
	if retryAfter > 0 {
		return min(retryAfter, maxWait)
	}
	base := r.Base
	if base <= 0 {
		base = time.Second
	}
	d := base << i
	d += time.Duration(rand.Int64N(int64(d)/4 + 1)) // jitter, so destinations don't retry in lockstep
	return min(d, maxWait)
}

func (r Retry) sleep(ctx context.Context, d time.Duration) error {
	if r.Sleep != nil {
		return r.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// attemptTimeout bounds one HTTP attempt.
const attemptTimeout = 30 * time.Second

// postJSON sends payload to rawURL with retries. what names the
// destination in errors ("slack:ops"); the URL is never included, since
// chat webhook URLs are credentials.
func postJSON(ctx context.Context, hc *http.Client, retry Retry, rawURL, what string, payload any) error {
	if hc == nil {
		return fmt.Errorf("notify: %s: needs an HTTP client", what)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return postBody(ctx, hc, retry, rawURL, what, body, "application/json")
}

// postMultipart sends payload as Discord's payload_json form field with one
// file attached as files[0], with the same retries as postJSON.
func postMultipart(ctx context.Context, hc *http.Client, retry Retry, rawURL, what string, payload any, name string, data []byte) error {
	if hc == nil {
		return fmt.Errorf("notify: %s: needs an HTTP client", what)
	}
	pj, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="payload_json"`)
	h.Set("Content-Type", "application/json")
	pw, err := mw.CreatePart(h)
	if err != nil {
		return err
	}
	pw.Write(pj)
	h = textproto.MIMEHeader{}
	h.Set("Content-Disposition", mime.FormatMediaType("form-data", map[string]string{"name": "files[0]", "filename": name}))
	h.Set("Content-Type", "application/json")
	fw, err := mw.CreatePart(h)
	if err != nil {
		return err
	}
	fw.Write(data)
	if err := mw.Close(); err != nil {
		return err
	}
	return postBody(ctx, hc, retry, rawURL, what, buf.Bytes(), mw.FormDataContentType())
}

func postBody(ctx context.Context, hc *http.Client, retry Retry, rawURL, what string, body []byte, contentType string) error {
	var last error
	n := retry.attempts()
	for i := range n {
		retryAfter, retryable, err := postOnce(ctx, hc, rawURL, body, contentType)
		if err == nil {
			return nil
		}
		last = err
		if !retryable || i == n-1 || ctx.Err() != nil {
			break
		}
		if err := retry.sleep(ctx, retry.wait(i, retryAfter)); err != nil {
			break
		}
	}
	return fmt.Errorf("notify: %s: %w", what, last)
}

// statusError is a non-2xx answer. It holds the status and, when the body
// is a short error code (Slack answers e.g. "invalid_payload"), that code.
type statusError struct {
	Status int
	Code   string
}

func (e *statusError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("HTTP %d (%s)", e.Status, e.Code)
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

func postOnce(ctx context.Context, hc *http.Client, rawURL string, body []byte, contentType string) (retryAfter time.Duration, retryable bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return 0, false, errors.New("bad webhook URL")
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "heimdall-notify")
	resp, err := hc.Do(req)
	if err != nil {
		// *url.Error embeds the URL, which may contain a secret.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, true, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return 0, false, nil
	}
	se := &statusError{Status: resp.StatusCode, Code: errorCode(raw)}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return parseRetryAfter(resp.Header.Get("Retry-After"), raw), true, se
	case resp.StatusCode >= 500:
		return parseRetryAfter(resp.Header.Get("Retry-After"), nil), true, se
	}
	return 0, false, se
}

// parseRetryAfter reads Retry-After (seconds or an HTTP date), falling back
// to Discord's JSON {"retry_after": 1.5} (seconds, fractional).
func parseRetryAfter(h string, body []byte) time.Duration {
	h = strings.TrimSpace(h)
	if h != "" {
		if f, err := strconv.ParseFloat(h, 64); err == nil && f >= 0 && f < 86400 {
			return time.Duration(f * float64(time.Second))
		}
		if t, err := http.ParseTime(h); err == nil {
			return max(time.Until(t), 0)
		}
	}
	var v struct {
		RetryAfter float64 `json:"retry_after"`
	}
	if len(body) > 0 && json.Unmarshal(body, &v) == nil && v.RetryAfter > 0 && v.RetryAfter < 86400 {
		return time.Duration(v.RetryAfter * float64(time.Second))
	}
	return 0
}

// errorCode returns the body if it's a short identifier like Slack's
// "channel_not_found", else "". Nothing else from a response is echoed.
func errorCode(b []byte) string {
	s := strings.TrimSpace(string(b))
	if s == "" || len(s) > 48 {
		return ""
	}
	for _, r := range s {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return ""
		}
	}
	return s
}
