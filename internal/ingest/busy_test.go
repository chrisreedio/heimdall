// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// A store too busy to look the token up answers 503 with Retry-After (which
// collectors retry), not 400 or 401, and doesn't count as a failed login.
func TestBusyStoreIsRetryable(t *testing.T) {
	e := newEnv(t, nil)
	lookup := e.h.hostByToken
	e.h.lookupTimeout = 20 * time.Millisecond
	e.h.hostByToken = func(ctx context.Context, h [32]byte) (store.IngestHost, error) {
		<-ctx.Done()
		return store.IngestHost{}, ctx.Err()
	}
	for range authFailuresPerMinute + 1 {
		w := e.expect(req{remote: "198.51.100.7:1234"}, http.StatusServiceUnavailable)
		if w.Header().Get("Retry-After") == "" {
			t.Fatal("503 without Retry-After")
		}
	}
	e.h.hostByToken = lookup
	e.expect(req{remote: "198.51.100.7:1234"}, http.StatusCreated)
}

// The body is read before the token lookup, so a lookup that waits past
// the server's read deadline still stores the report.
func TestSlowLookupAfterBodyRead(t *testing.T) {
	e := newEnv(t, nil)
	lookup := e.h.hostByToken
	e.h.hostByToken = func(ctx context.Context, h [32]byte) (store.IngestHost, error) {
		time.Sleep(400 * time.Millisecond)
		return lookup(ctx, h)
	}
	srv := httptest.NewUnstartedServer(e.h)
	srv.Config.ReadTimeout = 150 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)

	// Bigger than the server's read buffer, so the read reaches the socket.
	body := append(bytes.Clone(e.body), bytes.Repeat([]byte(" "), 256<<10)...)
	hr, _ := http.NewRequest(http.MethodPost, srv.URL+Path, bytes.NewReader(body))
	hr.Header.Set("Authorization", "Bearer "+e.token)
	hr.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d, want 201", resp.StatusCode)
	}
}

// A body that stops arriving before the read deadline is a 503 to retry,
// not "invalid gzip body".
func TestBodyReadTimeoutIsRetryable(t *testing.T) {
	e := newEnv(t, nil)
	srv := httptest.NewUnstartedServer(e.h)
	srv.Config.ReadTimeout = 150 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)

	for _, enc := range []string{"", "gzip"} {
		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		body := e.body
		if enc != "" {
			body = gz(e.body)
		}
		fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: hub\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\n", Path, e.token)
		if enc != "" {
			fmt.Fprintf(conn, "Content-Encoding: %s\r\n", enc)
		}
		fmt.Fprintf(conn, "Content-Length: %d\r\n\r\n", len(body))
		conn.Write(body[:5]) // then stall
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		conn.Close()
		if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
			t.Errorf("encoding %q: status %d, Retry-After %q", enc, resp.StatusCode, resp.Header.Get("Retry-After"))
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestBodyStatus(t *testing.T) {
	for _, c := range []struct {
		err  error
		want int
	}{
		{os.ErrDeadlineExceeded, http.StatusServiceUnavailable},
		{fmt.Errorf("read: %w", os.ErrDeadlineExceeded), http.StatusServiceUnavailable},
		{timeoutErr{}, http.StatusServiceUnavailable},
		{&http.MaxBytesError{Limit: 1}, http.StatusRequestEntityTooLarge},
		{fmt.Errorf("gzip: invalid header"), http.StatusBadRequest},
	} {
		if got := bodyStatus(c.err); got != c.want {
			t.Errorf("bodyStatus(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}
