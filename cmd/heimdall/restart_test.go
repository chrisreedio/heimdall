// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
)

func TestRestart(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	cfgPath := t.TempDir() + "/heimdall.toml"
	src := setTOMLKeys(config.Template("heimdall.db"), "ui", [][2]string{{"listen", strconv.Quote(strings.TrimPrefix(srv.URL, "http://"))}})
	os.WriteFile(cfgPath, src, 0o600)
	stub(t, &isRoot, func() bool { return true })
	stub(t, &restartWait, 300*time.Millisecond)
	var calls []string
	stub(t, &systemctl, func(a *app, args ...string) error { calls = append(calls, args[0]); return nil })
	journal := 0
	stub(t, &showJournal, func(*app) { journal++ })

	var out, errb bytes.Buffer
	if err := run(t.Context(), []string{"-c", cfgPath, "restart"}, &out, &errb); err != nil || !strings.Contains(errb.String(), "is running") {
		t.Fatalf("restart: %v %q", err, errb.String())
	}
	if strings.Join(calls, ",") != "daemon-reload,restart,is-active" || journal != 0 {
		t.Errorf("calls %v journal %d", calls, journal)
	}
	status = http.StatusInternalServerError
	if err := run(t.Context(), []string{"-c", cfgPath, "restart"}, &out, &errb); err == nil || journal != 1 {
		t.Errorf("unhealthy hub: err=%v journal=%d", err, journal)
	}
	// A broken config is caught before the running hub is stopped.
	os.WriteFile(cfgPath, []byte("[ui\n"), 0o600)
	calls = nil
	if err := run(t.Context(), []string{"-c", cfgPath, "restart"}, &out, &errb); err == nil || len(calls) != 0 {
		t.Errorf("broken config: err=%v calls=%v", err, calls)
	}
}
