// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"
)

// Pages keep rendering while a long write holds the store's writer. The
// write here is stuck behind another connection's write lock, so it holds
// the hub's only writer connection for the 5s busy timeout, as a big
// first report or a findings recount does.
func TestPagesRenderDuringLongWrite(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seed()
	ctx := t.Context()

	other, err := sql.Open("sqlite", e.dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	conn, err := other.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}
	defer release()

	done := make(chan error, 1)
	go func() {
		_, err := e.st.CreateOrg(context.Background(), "test", "globex", "Globex")
		done <- err
	}()
	time.Sleep(200 * time.Millisecond) // let the write take the writer
	select {
	case err := <-done:
		t.Fatalf("write finished while the lock was held: %v", err)
	default:
	}

	start := time.Now()
	for _, path := range []string{"/", "/hosts", "/hosts/acme/web-01", "/sites", "/anomalies", "/plans", "/drift"} {
		if w := e.get(path, signedIn(e)); w.Code != http.StatusOK {
			t.Errorf("GET %s during a write: %d", path, w.Code)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("pages took %v during a write; they waited for the writer", d)
	}

	release()
	if err := <-done; err != nil {
		t.Fatalf("write after the lock was released: %v", err)
	}
}
