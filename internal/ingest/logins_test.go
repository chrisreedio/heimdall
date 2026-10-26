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

	"github.com/realmwatch/heimdall/internal/store"
)

func TestParseLogins(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	ts := fmt.Sprint(now.Add(-time.Minute).Unix())
	for _, bad := range []string{"", "v2 journal 0", "v1 journal", "v1 elsewhere 0", "v1 journal -1", "v1 journal abc",
		"v1 journal 0 2026-10-25:1:1 2026-10-24:1:1 2026-10-23:1:1 2026-10-22:1:1", // too many days
		"v1 journal 0 2026-10-25:1", // a bad day head
		"v1 journal 0 " + strings.Repeat("x", maxLoginsHeader)} {
		if _, ok := parseLogins(bad, now); ok {
			t.Errorf("parseLogins(%.60q) ok", bad)
		}
	}
	rep, ok := parseLogins("v1 auth.log "+ts+" 2026-10-25:10:3="+strings.Join([]string{
		"5:3:100:200:1:203.0.113.9",
		"5:3:100:200:0:203.0.113.9",         // duplicate address
		"2:1:300:400:0:::ffff:198.51.100.7", // IPv4-mapped: stored as IPv4
		"1:0:0:0:0:2001:db8::1",
		"0:0:0:0:0:203.0.113.1",            // no failures
		"1:0:500:400:0:203.0.113.2",        // first after last
		"1:0:0:86400:0:203.0.113.3",        // past the day
		"1:0:0:50000:0:203.0.113.4",        // in the future (13:53 UTC)
		"1:0:0:1:2:203.0.113.5",            // succeeded isn't 0 or 1
		"1:0:0:1:0:fe80::1%eth0",           // a zone
		"1:0:0:1:0:999.1.1.1",              // not an address
		"1:0:0:1:0:host.example.com",       // a host name
		"x:0:0:1:0:203.0.113.6", "1:0:0:1", // garbage
	}, ",")+" 2026-10-24:7:0=1:1:86000:86399:0:203.0.113.9 2026-10-01:5:5=1:1:1:1:0:203.0.113.8", now)
	if !ok || rep.Source != "auth.log" || !rep.CountedAt.Equal(now.Add(-time.Minute)) || len(rep.Days) != 2 {
		t.Fatalf("parseLogins = %+v, %v", rep, ok)
	}
	d := rep.Days[0]
	if d.Day != "2026-10-25" || d.Failures != 10 || d.Addresses != 3 || len(d.Rows) != 3 {
		t.Fatalf("today = %+v", d)
	}
	first := store.LoginFailure{IP: "203.0.113.9", Failures: 5, Usernames: 3, First: now.Truncate(24 * time.Hour).Add(100 * time.Second),
		Last: now.Truncate(24 * time.Hour).Add(200 * time.Second), Succeeded: true}
	if d.Rows[0] != first || d.Rows[1].IP != "198.51.100.7" || d.Rows[2].IP != "2001:db8::1" {
		t.Errorf("rows = %+v", d.Rows)
	}
	// A day's total is at least what it lists.
	if y := rep.Days[1]; y.Day != "2026-10-24" || y.Failures != 7 || y.Addresses != 1 {
		t.Errorf("yesterday = %+v", y)
	}

	// Caps: 200 rows a push across its days; a stale counted-at is dropped.
	var many []string
	for i := range 300 {
		many = append(many, fmt.Sprintf("1:1:0:0:0:2001:db8::%x", i+1))
	}
	rep, ok = parseLogins("v1 journal 1 2026-10-25:300:300="+strings.Join(many[:150], ",")+" 2026-10-24:150:150="+strings.Join(many[150:], ","), now)
	if !ok || len(rep.Days[0].Rows)+len(rep.Days[1].Rows) != maxLoginRows || !rep.CountedAt.IsZero() {
		t.Errorf("kept %d+%d rows (counted %v), want %d", len(rep.Days[0].Rows), len(rep.Days[1].Rows), rep.CountedAt, maxLoginRows)
	}
}

func (e *env) pushLogins(vals ...string) {
	e.t.Helper()
	hr := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(e.body))
	hr.Header.Set("Authorization", "Bearer "+e.token)
	hr.Header.Set("Content-Type", "application/json")
	for _, v := range vals {
		hr.Header.Add(LoginsHeader, v)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, hr)
	if w.Code >= 300 {
		e.t.Fatalf("push status %d: %s", w.Code, w.Body.String())
	}
}

func TestLoginsIngest(t *testing.T) {
	e := newEnv(t, nil)
	ctx := t.Context()
	day := e.now.UTC().Format(time.DateOnly)
	rows := func() []store.HostLoginFailure {
		t.Helper()
		r, err := e.st.LoginFailuresSince(ctx, store.AllScope, e.host.ID, "", e.now.Add(-48*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// Malformed or repeated headers never fail a push, and store nothing.
	e.pushLogins("garbage")
	e.pushLogins("v1 journal 0 "+day+":1:1=1:1:0:0:0:203.0.113.9", "v1 journal 0 "+day+":1:1=1:1:0:0:0:203.0.113.9")
	if w, _ := e.st.LoginWatchOf(ctx, e.host.ID); w.Source != "" || len(rows()) != 0 {
		t.Fatalf("stored from bad headers: %+v %v", w, rows())
	}

	e.pushLogins("v1 journal 0 " + day + ":4:1=4:2:0:10:0:203.0.113.9")
	// A resend never counts twice; counts only grow; "then succeeded" sticks.
	e.pushLogins("v1 journal 0 " + day + ":4:1=4:2:0:10:1:203.0.113.9")
	e.pushLogins("v1 journal 0 " + day + ":6:1=6:1:5:20:0:203.0.113.9")
	got := rows()
	if len(got) != 1 || got[0].Failures != 6 || got[0].Usernames != 2 || !got[0].Succeeded ||
		got[0].First.Format("15:04:05") != "00:00:00" || got[0].Last.Format("15:04:05") != "00:00:20" {
		t.Fatalf("rows = %+v", got)
	}
	if w, _ := e.st.LoginWatchOf(ctx, e.host.ID); w.Source != "journal" || w.ReportedAt.IsZero() {
		t.Errorf("watch = %+v", w)
	}
	// "on, but nothing to read" still records the state.
	e.pushLogins("v1 none 0")
	if w, _ := e.st.LoginWatchOf(ctx, e.host.ID); w.Source != "none" {
		t.Errorf("watch = %+v", w)
	}
	if n, err := e.st.LoginDayTotals(ctx, store.AllScope, "", e.host.ID, day); err != nil || n != 6 {
		t.Errorf("day totals = %d, %v", n, err)
	}
}

func TestLoginsRetention(t *testing.T) {
	e := newEnv(t, nil)
	ctx := t.Context()
	old := e.now.Add(-store.LoginRetention - 48*time.Hour).UTC()
	rep := store.LoginReport{Source: "journal", Days: []store.LoginDay{{Day: old.Format(time.DateOnly), Failures: 1, Addresses: 1,
		Rows: []store.LoginFailure{{IP: "203.0.113.9", Failures: 1, First: old, Last: old}}}}}
	if err := e.st.RecordLogins(ctx, e.host.ID, rep, old); err != nil {
		t.Fatal(err)
	}
	if err := e.st.RecordLogins(ctx, e.host.ID, store.LoginReport{Source: "journal"}, e.now); err != nil {
		t.Fatal(err)
	}
	r, err := e.st.LoginFailuresSince(ctx, store.AllScope, 0, "", time.Unix(0, 0))
	if n, _ := e.st.LoginDayTotals(ctx, store.AllScope, "", 0, "2000-01-01"); err != nil || len(r) != 0 || n != 0 {
		t.Fatalf("old rows kept: %v %d %v", r, n, err)
	}
}
