// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// A session touch that's due doesn't make the page wait for a long write
// on the store's writer: it gives up after touchWait and the page goes on.
func TestSessionTouchDoesntWaitForWriter(t *testing.T) {
	e := newEnv(t)
	tok, err := e.login(email, password, e.code())
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()

	// Another connection holds the write lock, so a store write sits on
	// the hub's only writer connection for the 5s busy timeout.
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
	done := make(chan struct{})
	go func() {
		e.st.CreateOrg(context.Background(), "test", "acme", "Acme")
		close(done)
	}()
	time.Sleep(200 * time.Millisecond)

	e.now = e.now.Add(5 * time.Minute) // a touch is due
	start := time.Now()
	if _, err := e.svc.Session(ctx, tok); err != nil {
		t.Fatalf("session during a write: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("session lookup took %v during a write", d)
	}
	conn.ExecContext(ctx, `ROLLBACK`)
	<-done

	// Once the writer is free the touch goes through again.
	if _, err := e.svc.Session(ctx, tok); err != nil {
		t.Fatal(err)
	}
}
