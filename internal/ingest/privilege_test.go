// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

func TestParsePrivilege(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ts := func(d time.Duration) string { return fmt.Sprint(now.Add(d).Unix()) }
	for _, bad := range []string{"", "v2 " + ts(0) + ":sudo", ts(0) + ":sudo", "v1 " + strings.Repeat("x", maxPrivilegeHeader)} {
		if got := parsePrivilege(bad, now); got != nil {
			t.Errorf("parsePrivilege(%.40q) = %v, want nil", bad, got)
		}
	}
	got := parsePrivilege("v1 "+strings.Join([]string{
		ts(-time.Hour) + ":sudo",
		ts(-time.Hour) + ":sudo", // duplicate
		ts(-time.Minute) + ":root-ssh:root",
		ts(-time.Minute) + ":su:?",
		ts(-time.Minute) + ":su:Bad-User", // invalid name
		ts(-time.Minute) + ":su:" + strings.Repeat("a", 33),
		ts(-time.Minute) + ":shell",           // unknown kind
		ts(-9*24*time.Hour) + ":sudo",         // too old
		ts(time.Hour) + ":sudo",               // too far ahead
		"abc:sudo", "-5:sudo", ":", "1:2:3:4", // garbage
	}, ","), now)
	want := []store.PrivilegeEvent{
		{At: now.Add(-time.Hour).UTC(), Kind: "sudo"},
		{At: now.Add(-time.Minute).UTC(), Kind: "root-ssh", User: "root"},
		{At: now.Add(-time.Minute).UTC(), Kind: "su", User: "?"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("parsePrivilege = %v\nwant %v", got, want)
	}

	var many []string
	for i := range 300 {
		many = append(many, ts(-time.Duration(i)*time.Second)+":sudo")
	}
	if got := parsePrivilege("v1 "+strings.Join(many, ","), now); len(got) != maxPrivilegeEvents {
		t.Errorf("kept %d events, want %d", len(got), maxPrivilegeEvents)
	}
	for v, want := range map[string]string{"on": "on", " partial ": "partial", "off": "off", "ON": "", "maybe": ""} {
		if got := parsePrivilegeWatch(v); got != want {
			t.Errorf("parsePrivilegeWatch(%q) = %q, want %q", v, got, want)
		}
	}
}

// pushPrivilege pushes the fixture with privilege headers ("" leaves one out).
func (e *env) pushPrivilege(events, watch string) int {
	e.t.Helper()
	hr := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(e.body))
	hr.Header.Set("Authorization", "Bearer "+e.token)
	hr.Header.Set("Content-Type", "application/json")
	if events != "" {
		hr.Header.Set(PrivilegeHeader, events)
	}
	if watch != "" {
		hr.Header.Set(PrivilegeWatchHeader, watch)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, hr)
	if w.Code >= 300 {
		e.t.Fatalf("push status %d: %s", w.Code, w.Body.String())
	}
	return w.Code
}

func (e *env) openAnomalies() []store.AnomalyRow {
	e.t.Helper()
	as, err := e.st.Anomalies(e.t.Context(), e.host.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return as
}

func TestPrivilegeWatch(t *testing.T) {
	e := newEnv(t, nil)
	at := func(d time.Duration) string { return fmt.Sprint(e.now.Add(d).Unix()) }

	// Malformed headers never fail a push.
	e.pushPrivilege("garbage", "sideways")
	if a := e.openAnomalies(); len(a) != 0 {
		t.Fatalf("anomalies after garbage headers: %v", a)
	}

	e.pushPrivilege("v1 "+at(-2*time.Hour)+":sudo,"+at(-time.Hour)+":root-ssh", "on")
	as := e.openAnomalies()
	if len(as) != 1 || as[0].Rule != "privileged_access" ||
		!strings.Contains(as[0].Summary, "2 privileged accesses") || !strings.Contains(as[0].Summary, "1 sudo, 1 root SSH") {
		t.Fatalf("anomalies = %+v", as)
	}

	// Resent events are deduped; a new one adds to the same day's anomaly.
	e.pushPrivilege("v1 "+at(-2*time.Hour)+":sudo,"+at(-time.Hour)+":root-ssh,"+at(-time.Minute)+":sudo", "on")
	as = e.openAnomalies()
	if len(as) != 1 || !strings.Contains(as[0].Summary, "3 privileged accesses") || !strings.Contains(as[0].Summary, "2 sudo, 1 root SSH") {
		t.Fatalf("after resend: %+v", as)
	}
	sum, err := e.st.PrivilegeSummary(t.Context(), e.host.ID, e.now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sum.State != "on" || !sum.EverOn || sum.Counts["sudo"] != 2 || sum.Counts["root-ssh"] != 1 {
		t.Errorf("summary = %+v", sum)
	}

	// No header: the state is unknown, not "off".
	e.pushPrivilege("", "")
	if a := e.openAnomalies(); len(a) != 1 {
		t.Fatalf("missing headers raised %v", a)
	}
	// A PAM line removed while still reporting.
	e.pushPrivilege("", "partial")
	as = e.openAnomalies()
	if len(as) != 2 || as[0].Rule != "privilege_watch_disabled" {
		t.Fatalf("after partial: %+v", as)
	}
	// Still partial, then off: no new alert until it's back on.
	e.pushPrivilege("", "off")
	if a := e.openAnomalies(); len(a) != 2 {
		t.Fatalf("partial→off raised again: %v", a)
	}
}

func TestPrivilegeNeverEnabledNeverAlerts(t *testing.T) {
	e := newEnv(t, nil)
	e.pushPrivilege("", "off")
	e.pushPrivilege("", "partial")
	if a := e.openAnomalies(); len(a) != 0 {
		t.Fatalf("anomalies = %v", a)
	}
	sum, err := e.st.PrivilegeSummary(t.Context(), e.host.ID, e.now.Add(-24*time.Hour))
	if err != nil || sum.EverOn {
		t.Fatalf("summary = %+v, %v", sum, err)
	}
}

func TestPrivilegeWindowsAndSuppression(t *testing.T) {
	e := newEnv(t, nil)
	ctx := t.Context()
	at := func(d time.Duration) string { return fmt.Sprint(e.now.Add(d).Unix()) }
	if _, err := e.st.CreateWindow(ctx, "test", store.Window{OrgSlug: "acme", Host: "web-01",
		Starts: e.now.Add(-3 * time.Hour), Ends: e.now.Add(-30 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	e.pushPrivilege("v1 "+at(-2*time.Hour)+":sudo:alice", "on")
	if a := e.openAnomalies(); len(a) != 0 {
		t.Fatalf("event inside a window raised %v", a)
	}
	e.pushPrivilege("v1 "+at(-time.Minute)+":su:bob", "on")
	as := e.openAnomalies()
	if len(as) != 1 || !strings.Contains(as[0].Summary, "1 privileged access ") || !strings.Contains(as[0].Summary, "by bob") {
		t.Fatalf("anomalies = %+v", as)
	}

	f := newEnv(t, nil)
	if err := f.st.Suppress(ctx, "test", 0, f.host, "privileged_access", f.now.Add(time.Hour), "maintenance", f.now); err != nil {
		t.Fatal(err)
	}
	f.pushPrivilege("v1 "+fmt.Sprint(f.now.Add(-time.Minute).Unix())+":sudo", "on")
	if a := f.openAnomalies(); len(a) != 0 {
		t.Fatalf("suppressed rule raised %v", a)
	}
}

func TestPrivilegeRetention(t *testing.T) {
	e := newEnv(t, nil)
	ctx := t.Context()
	old := []store.PrivilegeEvent{{At: e.now.Add(-store.PrivilegeRetention - time.Hour).Truncate(time.Second), Kind: "sudo"}}
	if _, _, err := e.st.RecordPrivilege(ctx, e.host.ID, old, "on", e.now.Add(-store.PrivilegeRetention)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.st.RecordPrivilege(ctx, e.host.ID, nil, "on", e.now); err != nil {
		t.Fatal(err)
	}
	sum, err := e.st.PrivilegeSummary(ctx, e.host.ID, time.Unix(0, 0))
	if err != nil || !sum.Last.IsZero() || len(sum.Counts) != 0 {
		t.Fatalf("old event not pruned: %+v, %v", sum, err)
	}
}
