// SPDX-License-Identifier: AGPL-3.0-or-later

// Package storetest gives tests a fresh, migrated database cheaply. Running
// every migration takes a few hundred milliseconds under the race detector,
// and most tests need their own database, so the schema is built once per
// test binary and each test gets a copy of the file.
package storetest

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/realmwatch/heimdall/internal/store"
)

var (
	once     sync.Once
	template []byte
	initErr  error
)

// New returns an open, migrated store in t's temp dir, closed at cleanup.
func New(t testing.TB) *store.Store {
	t.Helper()
	once.Do(func() { template, initErr = build() })
	if initErr != nil {
		t.Fatal(initErr)
	}
	path := filepath.Join(t.TempDir(), "h.db")
	if err := os.WriteFile(path, template, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// build migrates an empty database and returns the file's bytes. Closing
// the only connection checkpoints the WAL, so the file is complete.
func build() ([]byte, error) {
	dir, err := os.MkdirTemp("", "heimdall-storetest-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "h.db")
	if err := store.Create(path); err != nil {
		return nil, err
	}
	st, err := store.Open(context.Background(), path)
	if err != nil {
		return nil, err
	}
	if _, err := st.Migrate(context.Background()); err != nil {
		st.Close()
		return nil, err
	}
	if err := st.Close(); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}
