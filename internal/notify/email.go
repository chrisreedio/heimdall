// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Email sends digests over SMTP. TLS is mandatory: STARTTLS on submission
// ports, implicit TLS on port 465. Nothing (not even AUTH) is sent in clear.
type Email struct {
	Host     string
	Port     int
	Username string // optional; AUTH PLAIN, only over TLS
	Password string
	From     string
	To       []string

	// Dial and TLSConfig exist for tests; nil uses net.Dialer and the
	// system roots with ServerName = Host and TLS 1.2+.
	Dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	TLSConfig *tls.Config
}

const smtpTimeout = 30 * time.Second

// Send delivers the digest to every recipient in one message.
func (e *Email) Send(ctx context.Context, d Digest) error {
	return e.send(ctx, d.Subject(), d.Text())
}

// SendAlert delivers an alert the same way.
func (e *Email) SendAlert(ctx context.Context, a Alert) error {
	return e.send(ctx, a.Subject(), a.Text())
}

func (e *Email) Name() string { return "email" }

func (e *Email) PreviewDigest(d Digest) any { return "Subject: " + d.Subject() + "\n\n" + d.Text() }
func (e *Email) PreviewAlert(a Alert) any   { return "Subject: " + a.Subject() + "\n\n" + a.Text() }
func (e *Email) Target() string {
	return fmt.Sprintf("smtp://%s:%d, %d %s", e.Host, e.Port, len(e.To), plural(len(e.To), "recipient", "recipients"))
}

func (e *Email) send(ctx context.Context, subject, text string) error {
	from, to, err := e.addresses()
	if err != nil {
		return err
	}
	if e.Host == "" || e.Port <= 0 || e.Port > 65535 {
		return errors.New("notify: email needs a host and port")
	}
	msg, err := buildMessage(from, to, subject, text, time.Now())
	if err != nil {
		return err
	}

	tlsCfg := e.tlsConfig()
	dial := e.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: smtpTimeout}).DialContext
	}
	addr := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("notify: connect %s: %w", addr, err)
	}
	deadline := time.Now().Add(smtpTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)

	implicit := e.Port == 465
	if implicit {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return fmt.Errorf("notify: TLS handshake: %w", err)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("notify: smtp: %w", err)
	}
	defer c.Close()
	if err := c.Hello("heimdall"); err != nil {
		return fmt.Errorf("notify: EHLO: %w", err)
	}
	if !implicit {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("notify: SMTP server doesn't offer STARTTLS; refusing to send in clear")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("notify: STARTTLS: %w", err)
		}
	}
	if e.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.Username, e.Password, e.Host)); err != nil {
			return fmt.Errorf("notify: AUTH: %w", err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return fmt.Errorf("notify: MAIL FROM: %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt.Address); err != nil {
			return fmt.Errorf("notify: RCPT TO: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("notify: DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		w.Close()
		return fmt.Errorf("notify: DATA: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("notify: DATA: %w", err)
	}
	return c.Quit()
}

func (e *Email) tlsConfig() *tls.Config {
	if e.TLSConfig != nil {
		cfg := e.TLSConfig.Clone()
		if cfg.MinVersion < tls.VersionTLS12 {
			cfg.MinVersion = tls.VersionTLS12
		}
		return cfg
	}
	return &tls.Config{ServerName: e.Host, MinVersion: tls.VersionTLS12}
}

// addresses validates From and To; anything with CR/LF or that doesn't
// parse as a single address is rejected.
func (e *Email) addresses() (*mail.Address, []*mail.Address, error) {
	parse := func(field, s string) (*mail.Address, error) {
		if s == "" || strings.ContainsAny(s, "\r\n") {
			return nil, fmt.Errorf("notify: invalid %s address %q", field, s)
		}
		a, err := mail.ParseAddress(s)
		if err != nil || strings.ContainsAny(a.Address, "\r\n<>") {
			return nil, fmt.Errorf("notify: invalid %s address %q", field, s)
		}
		return a, nil
	}
	from, err := parse("from", e.From)
	if err != nil {
		return nil, nil, err
	}
	if len(e.To) == 0 {
		return nil, nil, errors.New("notify: email needs at least one recipient")
	}
	if len(e.To) > 100 {
		return nil, nil, errors.New("notify: too many recipients")
	}
	var to []*mail.Address
	for _, s := range e.To {
		a, err := parse("to", s)
		if err != nil {
			return nil, nil, err
		}
		to = append(to, a)
	}
	return from, to, nil
}

// buildMessage renders an RFC 5322 message with a plain-text body.
func buildMessage(from *mail.Address, to []*mail.Address, subject, text string, now time.Time) ([]byte, error) {
	id := make([]byte, 16)
	rand.Read(id)
	domain := "heimdall.invalid"
	if at := strings.LastIndexByte(from.Address, '@'); at >= 0 {
		domain = from.Address[at+1:]
	}
	rcpts := make([]string, len(to))
	for i, a := range to {
		rcpts[i] = a.String()
	}

	var b bytes.Buffer
	header := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	header("From", from.String())
	header("To", strings.Join(rcpts, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", clean(subject, 200)))
	header("Date", now.UTC().Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "8bit")
	header("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	return b.Bytes(), nil
}
