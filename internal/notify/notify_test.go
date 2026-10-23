// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sample() Digest {
	return Digest{
		Org: "acme", GeneratedAt: time.Date(2026, 10, 22, 6, 0, 0, 0, time.UTC),
		Hosts: 12, Stale: 1, KEV: 2, Critical: 5, High: 9, Fixable: 30, NewSinceLast: 4,
		EOLHosts: 3, SitesNeedingAttention: 2, OpenAnomalies: 1,
		URL: "https://heimdall.example.ts.net/",
	}
}

// The digest must not be able to carry hostnames, packages, versions or
// advisory IDs. This guards the type itself: adding any new field (a string
// one especially) means re-reviewing what a leaked digest would reveal.
func TestDigestCarriesOnlyCounts(t *testing.T) {
	allowed := map[string]reflect.Kind{
		"Org": reflect.String, "GeneratedAt": reflect.Struct, "URL": reflect.String,
	}
	typ := reflect.TypeOf(Digest{})
	for i := range typ.NumField() {
		f := typ.Field(i)
		if k, ok := allowed[f.Name]; ok {
			if f.Type.Kind() != k {
				t.Errorf("%s changed type to %s", f.Name, f.Type)
			}
			continue
		}
		if f.Type.Kind() != reflect.Int {
			t.Errorf("Digest.%s is %s; only integer counts are allowed (see package doc)", f.Name, f.Type)
		}
	}
}

func TestTextAndSubject(t *testing.T) {
	d := sample()
	subj := d.Subject()
	if subj != "Heimdall: 2 known-exploited, 5 critical, 4 new (acme)" {
		t.Errorf("subject = %q", subj)
	}
	text := d.Text()
	for _, want := range []string{"2  known exploited", "5  critical", "30  fixable now", "12  hosts reporting",
		"1  host not reporting", "3  hosts with an end-of-life", "https://heimdall.example.ts.net/", "only contains counts"} {
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q:\n%s", want, text)
		}
	}
	if (Digest{}).Subject() != "Heimdall: no urgent findings" {
		t.Errorf("empty subject = %q", (Digest{}).Subject())
	}
	// Control characters can't smuggle extra lines or headers in.
	d.Org = "acme\r\nBcc: evil@example.com"
	if s := d.Subject(); strings.ContainsAny(s, "\r\n") {
		t.Errorf("subject contains CR/LF: %q", s)
	}
}

// ── Fake SMTP server ───────────────────────────────────────────────────────

type received struct {
	from, data, auth string
	to               []string
	tls              bool
}

type fakeSMTP struct {
	ln          net.Listener
	cert        tls.Certificate
	offerTLS    bool
	implicitTLS bool
	got         chan received
}

func newCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func startSMTP(t *testing.T, offerTLS, implicitTLS bool) (*fakeSMTP, *x509.CertPool) {
	t.Helper()
	cert, pool := newCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, cert: cert, offerTLS: offerTLS, implicitTLS: implicitTLS, got: make(chan received, 1)}
	t.Cleanup(func() { ln.Close() })
	go f.serve()
	return f, pool
}

func (f *fakeSMTP) serve() {
	conn, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	cfg := &tls.Config{Certificates: []tls.Certificate{f.cert}}
	var rec received
	if f.implicitTLS {
		conn = tls.Server(conn, cfg)
		rec.tls = true
	}
	tp := textproto.NewConn(conn)
	tp.PrintfLine("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			exts := []string{"fake"}
			if f.offerTLS && !rec.tls {
				exts = append(exts, "STARTTLS")
			}
			if rec.tls {
				exts = append(exts, "AUTH PLAIN")
			}
			exts = append(exts, "8BITMIME")
			for i, e := range exts {
				sep := "-"
				if i == len(exts)-1 {
					sep = " "
				}
				tp.PrintfLine("250%s%s", sep, e)
			}
		case cmd == "STARTTLS":
			tp.PrintfLine("220 go ahead")
			tc := tls.Server(conn, cfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn, rec.tls = tc, true
			tp = textproto.NewConn(tc)
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			rec.auth = strings.TrimSpace(line[len("AUTH PLAIN"):])
			tp.PrintfLine("235 ok")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			rec.from = line[len("MAIL FROM:"):]
			tp.PrintfLine("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			rec.to = append(rec.to, line[len("RCPT TO:"):])
			tp.PrintfLine("250 ok")
		case cmd == "DATA":
			tp.PrintfLine("354 go")
			lines, err := tp.ReadDotLines()
			if err != nil {
				return
			}
			rec.data = strings.Join(lines, "\n")
			tp.PrintfLine("250 queued")
			f.got <- rec
		case cmd == "QUIT":
			tp.PrintfLine("221 bye")
			return
		default:
			tp.PrintfLine("502 unknown")
		}
	}
}

func (f *fakeSMTP) email(pool *x509.CertPool, port int) *Email {
	return &Email{
		Host: "localhost", Port: port, Username: "heimdall", Password: "pw",
		From: "Heimdall <heimdall@example.com>", To: []string{"ops@example.com", "chris@example.com"},
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, f.ln.Addr().String())
		},
		TLSConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"},
	}
}

func TestEmailSTARTTLS(t *testing.T) {
	f, pool := startSMTP(t, true, false)
	if err := f.email(pool, 587).Send(t.Context(), sample()); err != nil {
		t.Fatal(err)
	}
	rec := <-f.got
	if !rec.tls {
		t.Fatal("message was sent without TLS")
	}
	auth, _ := base64.StdEncoding.DecodeString(rec.auth)
	if string(auth) != "\x00heimdall\x00pw" {
		t.Errorf("AUTH PLAIN = %q", auth)
	}
	if !strings.HasPrefix(rec.from, "<heimdall@example.com>") || !slices.Equal(rec.to, []string{"<ops@example.com>", "<chris@example.com>"}) {
		t.Errorf("envelope from %q to %v", rec.from, rec.to)
	}
	for _, want := range []string{"From: \"Heimdall\" <heimdall@example.com>", "To: <ops@example.com>, <chris@example.com>",
		"Subject: Heimdall: 2 known-exploited, 5 critical, 4 new (acme)", "Date: ", "Message-ID: <", "@example.com>",
		"MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8", "2  known exploited"} {
		if !strings.Contains(rec.data, want) {
			t.Errorf("message missing %q:\n%s", want, rec.data)
		}
	}
}

func TestEmailImplicitTLS(t *testing.T) {
	f, pool := startSMTP(t, false, true)
	if err := f.email(pool, 465).Send(t.Context(), sample()); err != nil {
		t.Fatal(err)
	}
	if rec := <-f.got; !rec.tls || rec.auth == "" {
		t.Errorf("implicit TLS: tls=%v auth=%q", rec.tls, rec.auth)
	}
}

func TestEmailRefusesWithoutTLS(t *testing.T) {
	f, pool := startSMTP(t, false, false)
	err := f.email(pool, 25).Send(t.Context(), sample())
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("want STARTTLS refusal, got %v", err)
	}
	select {
	case rec := <-f.got:
		t.Fatalf("server received a message: %+v", rec)
	default:
	}
}

func TestEmailRejectsHeaderInjection(t *testing.T) {
	var dials atomic.Int32
	e := &Email{Host: "localhost", Port: 587, From: "heimdall@example.com",
		Dial: func(context.Context, string, string) (net.Conn, error) { dials.Add(1); return nil, io.EOF }}
	for _, bad := range []string{"ops@example.com\r\nBcc: evil@example.com", "ops@example.com\nX: y", "not an address", ""} {
		e.To = []string{bad}
		if err := e.Send(t.Context(), sample()); err == nil {
			t.Errorf("To %q accepted", bad)
		}
	}
	e.To, e.From = []string{"ops@example.com"}, "heimdall@example.com\r\nBcc: evil@example.com"
	if err := e.Send(t.Context(), sample()); err == nil {
		t.Error("From with CR/LF accepted")
	}
	if dials.Load() != 0 {
		t.Error("invalid addresses must be rejected before connecting")
	}
}

// ── Webhook ────────────────────────────────────────────────────────────────

func TestWebhook(t *testing.T) {
	var got []byte
	status := http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(bufio.NewReader(r.Body))
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type %q", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()

	w := &Webhook{URL: srv.URL + "/hooks/T000/B000/secret-token", Format: "slack", Client: srv.Client()}
	if err := w.Send(t.Context(), sample()); err != nil {
		t.Fatal(err)
	}
	var slack map[string]string
	json.Unmarshal(got, &slack)
	if !strings.HasPrefix(slack["text"], "Heimdall: 2 known-exploited") || !strings.Contains(slack["text"], "30  fixable now") {
		t.Errorf("slack payload = %s", got)
	}

	w.Format = "json"
	if err := w.Send(t.Context(), sample()); err != nil {
		t.Fatal(err)
	}
	var d Digest
	if err := json.Unmarshal(got, &d); err != nil || d.KEV != 2 || d.Org != "acme" {
		t.Errorf("json payload = %s (%v)", got, err)
	}

	status = http.StatusForbidden
	err := w.Send(t.Context(), sample())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("non-2xx: %v", err)
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Errorf("error leaks the webhook URL: %v", err)
	}
}

func TestWebhookRejects(t *testing.T) {
	c := http.DefaultClient
	for _, w := range []*Webhook{
		{URL: "http://hooks.example.com/x", Format: "slack", Client: c},
		{URL: "https://hooks.example.com/x", Format: "xml", Client: c},
		{URL: "https://hooks.example.com/x", Format: "slack"},
		{URL: "not a url", Format: "slack", Client: c},
	} {
		if err := w.Send(t.Context(), sample()); err == nil {
			t.Errorf("%+v accepted", w)
		}
	}
	// Transport errors don't echo the URL (Slack URLs embed a secret).
	w := &Webhook{URL: "https://127.0.0.1:1/secret-token", Format: "json", Client: &http.Client{Timeout: time.Second}}
	if err := w.Send(t.Context(), sample()); err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Errorf("transport error = %v", err)
	}
}
