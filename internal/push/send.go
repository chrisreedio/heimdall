// SPDX-License-Identifier: AGPL-3.0-or-later

package push

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Target is where one message goes: a subscription's endpoint and keys.
type Target struct {
	Endpoint string
	P256DH   []byte // the browser's public key, 65 bytes
	Auth     []byte // its secret, 16 bytes
}

// Message is one notification on the wire.
type Message struct {
	Payload []byte        // JSON for the service worker (Notice.payload)
	TTL     time.Duration // how long the push service keeps it for an offline device
	Urgency string        // "high", "normal" or "low" (RFC 8030 section 5.3)
	Topic   string        // a newer message with the same topic replaces an undelivered one
}

// ErrGone means the push service no longer knows the subscription (404 or
// 410): the browser unsubscribed or the app was removed. Delete it.
var ErrGone = errors.New("subscription expired or unsubscribed")

// StatusError is any other refusal from a push service.
type StatusError struct {
	Status     int
	RetryAfter time.Duration // from a 429 or 503, if given
}

func (e *StatusError) Error() string { return fmt.Sprintf("push service answered HTTP %d", e.Status) }

// Temporary reports whether trying again later may work.
func (e *StatusError) Temporary() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
}

// Sender posts encrypted messages to push services.
type Sender struct {
	HTTP    *http.Client // allowlisted (NewClient); tests use an httptest client
	VAPID   *VAPID
	Subject string // VAPID contact: the hub's https URL or a mailto: address
	Now     func() time.Time
	// UserAgent identifies the hub.
	UserAgent string

	// check replaces CheckEndpoint in tests, for an httptest server.
	check func(string) error
}

// Send delivers one message to one subscription.
func (s *Sender) Send(ctx context.Context, t Target, m Message) error {
	check := CheckEndpoint
	if s.check != nil {
		check = s.check
	}
	if err := check(t.Endpoint); err != nil { // checked at subscribe time too
		return err
	}
	body, err := Encrypt(m.Payload, t.P256DH, t.Auth)
	if err != nil {
		return err
	}
	authz, err := s.VAPID.Authorization(t.Endpoint, s.Subject, s.Now())
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	h := req.Header
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Encoding", "aes128gcm")
	h.Set("TTL", strconv.Itoa(int(m.TTL.Seconds())))
	h.Set("Authorization", authz)
	if m.Urgency != "" {
		h.Set("Urgency", m.Urgency)
	}
	if m.Topic != "" {
		h.Set("Topic", m.Topic)
	}
	if s.UserAgent != "" {
		h.Set("User-Agent", s.UserAgent)
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return ErrGone
	}
	e := &StatusError{Status: resp.StatusCode}
	if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
		e.RetryAfter = time.Duration(secs) * time.Second
	}
	return e
}
