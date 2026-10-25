// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

// The collector's login watch (collector/login-watch.sh) against sshd's
// log formats, under each POSIX shell found here, and its header
// (collect.sh --logins) through the hub's parser.

const (
	loginWatch = "../../collector/login-watch.sh"
	collectSh  = "../../collector/collect.sh"
	fixtureNow = 1792929600 // 2026-10-25T12:00:00Z
)

func shells(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, sh := range []string{"dash", "bash", "busybox", "sh"} {
		if p, err := exec.LookPath(sh); err == nil {
			if sh == "busybox" {
				p += " sh"
			}
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		t.Skip("no POSIX shell")
	}
	return out
}

// count runs login-watch count over input into dir and returns the rows
// it kept (sorted, without the header line).
func count(t *testing.T, shell, dir, input string, now int64, tz int) []string {
	t.Helper()
	args := append(strings.Fields(shell), loginWatch, "count", dir, fmt.Sprint(now), fmt.Sprint(tz), "journal")
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(input)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s count: %v\n%s", shell, err, out)
	}
	return countsOf(t, dir)
}

func countsOf(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "counts"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if !strings.HasPrefix(lines[0], "# heimdall-logins v1 ") {
		t.Fatalf("counts header %q", lines[0])
	}
	rows := lines[1:]
	slices.Sort(rows)
	return rows
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata/logins", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func sorted(rows ...string) []string { slices.Sort(rows); return rows }

func TestLoginWatchFormats(t *testing.T) {
	want := map[string][]string{
		// Debian/Ubuntu auth.log, traditional syslog. One address per
		// connection however many lines sshd and PAM log about it;
		// probes without a password ("Received disconnect", "Failed
		// none") don't count; a username crafted to look like
		// "x from 192.0.2.66 port 22" doesn't move the failure there.
		"debian-auth.log": sorted(
			"D 2026-10-24 1 1",
			"D 2026-10-25 8 4",
			"I 2026-10-24 203.0.113.9 1 1 86281 86286 0",
			"I 2026-10-25 198.51.100.23 5 3 22211 25261 0", // 3 tries (max of Failed and PAM), a username probe, a closed attempt
			"I 2026-10-25 192.0.2.10 1 1 28800 28800 1",    // failed, then got in
			"I 2026-10-25 203.0.113.77 1 1 32700 32701 0",
			"I 2026-10-25 203.0.113.9 1 1 32940 32940 0", // got in before it failed: not "then succeeded"
		),
		// RHEL /var/log/secure: IPv6; PAM naming the client by host name
		// (UseDNS) joins sshd's line by PID, or counts in the total only.
		"rhel-secure": sorted(
			"D 2026-10-25 5 3",
			"I 2026-10-25 2001:db8::5 1 1 36000 36005 0",
			"I 2026-10-25 198.51.100.23 2 1 36300 36305 0",
			"I 2026-10-25 203.0.113.200 1 1 36360 36361 0",
		),
		// journalctl -o short-iso --utc (both offset styles), sshd-session,
		// RFC 3339 with an offset, busybox syslog; older days dropped.
		"journal-short-iso": sorted(
			"D 2026-10-24 1 1",
			"D 2026-10-25 5 4",
			"I 2026-10-24 203.0.113.9 1 1 79200 79200 0",
			"I 2026-10-25 198.51.100.23 1 1 41400 41400 1",
			"I 2026-10-25 203.0.113.10 1 1 39600 39600 0",
			"I 2026-10-25 203.0.113.11 1 1 42300 42300 0",
			"I 2026-10-25 203.0.113.9 2 1 39600 39605 0",
		),
	}
	for _, sh := range shells(t) {
		for name, rows := range want {
			t.Run(filepath.Base(sh)+"/"+name, func(t *testing.T) {
				got := count(t, sh, t.TempDir(), fixture(t, name), fixtureNow, 0)
				if !slices.Equal(got, rows) {
					t.Errorf("counts:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(rows, "\n"))
				}
			})
		}
	}
}

func TestLoginWatchIncremental(t *testing.T) {
	log := strings.SplitAfter(fixture(t, "debian-auth.log"), "\n")
	for _, sh := range shells(t) {
		t.Run(filepath.Base(sh), func(t *testing.T) {
			once := count(t, sh, t.TempDir(), strings.Join(log, ""), fixtureNow, 0)
			dir := t.TempDir()
			// Split between connections: the same counts (and distinct
			// usernames across runs), never counted twice.
			for _, part := range [][]string{log[:5], log[5:12], log[12:]} {
				count(t, sh, dir, strings.Join(part, ""), fixtureNow, 0)
			}
			if got := countsOf(t, dir); !slices.Equal(got, once) {
				t.Errorf("in parts:\n%s\nat once:\n%s", strings.Join(got, "\n"), strings.Join(once, "\n"))
			}
			// The next day: yesterday is kept, the day before is dropped.
			got := count(t, sh, dir, "", fixtureNow+86400, 0)
			if slices.ContainsFunc(got, func(r string) bool { return strings.Contains(r, "2026-10-24") }) ||
				!slices.Contains(got, "D 2026-10-25 8 4") {
				t.Errorf("a day later: %v", got)
			}
		})
	}
}

func TestLoginWatchTimes(t *testing.T) {
	sh := shells(t)[0]
	// Local time (traditional syslog has no zone) at UTC-5.
	got := count(t, sh, t.TempDir(), "Oct 25 06:10:11 h sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2\n", fixtureNow, -5*3600)
	if !slices.Contains(got, "I 2026-10-25 203.0.113.1 1 1 40211 40211 0") {
		t.Errorf("UTC-5: %v", got)
	}
	// No year: a December line read on January 1 is last year's.
	jan1 := time.Date(2027, 1, 1, 0, 30, 0, 0, time.UTC).Unix()
	got = count(t, sh, t.TempDir(), "Dec 31 23:59:00 h sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2\n", jan1, 0)
	if !slices.Contains(got, "I 2026-12-31 203.0.113.1 1 1 86340 86340 0") {
		t.Errorf("New Year: %v", got)
	}
}

// TestLoginWatchRun reads a log file from where the last run stopped,
// across a half-written line and a rotation.
func TestLoginWatchRun(t *testing.T) {
	sh := shells(t)[0]
	dir, state := t.TempDir(), t.TempDir()
	logf := filepath.Join(dir, "auth.log")
	now := time.Now().UTC().Add(-time.Minute)
	line := func(pid int, ip string) string {
		return fmt.Sprintf("%s web-01 sshd[%d]: Failed password for root from %s port 22 ssh2\n", now.Format("Jan _2 15:04:05"), pid, ip)
	}
	run := func() []string {
		t.Helper()
		cmd := exec.Command(sh, loginWatch, "run")
		cmd.Env = append(os.Environ(), "HEIMDALL_LOGIN_STATE="+state, "HEIMDALL_LOGIN_FILES="+logf, "HEIMDALL_LOGIN_JOURNAL=0", "TZ=UTC")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("run: %v\n%s", err, out)
		}
		var ips []string
		for _, r := range countsOf(t, state) {
			if f := strings.Fields(r); f[0] == "I" {
				ips = append(ips, f[2]+"="+f[3])
			}
		}
		return ips
	}
	write := func(name, s string, flag int) {
		f, err := os.OpenFile(filepath.Join(dir, name), flag|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(s)
		f.Close()
	}
	full := line(1, "203.0.113.1")
	write("auth.log", line(1, "203.0.113.1")+full[:20], os.O_TRUNC)
	if got := run(); !slices.Equal(got, []string{"203.0.113.1=1"}) {
		t.Fatalf("first run: %v", got)
	}
	write("auth.log", full[20:]+line(2, "203.0.113.2"), os.O_APPEND) // the half line, finished
	if got := run(); !slices.Equal(got, []string{"203.0.113.1=2", "203.0.113.2=1"}) {
		t.Fatalf("second run: %v", got)
	}
	if got := run(); !slices.Equal(got, []string{"203.0.113.1=2", "203.0.113.2=1"}) {
		t.Fatalf("nothing new counted again: %v", got)
	}
	// Rotated: the old file's last lines, then the new file's.
	write("auth.log", line(3, "203.0.113.3"), os.O_APPEND)
	if err := os.Rename(logf, logf+".1"); err != nil {
		t.Fatal(err)
	}
	write("auth.log", line(4, "203.0.113.4"), os.O_TRUNC)
	if got := run(); !slices.Equal(got, []string{"203.0.113.1=2", "203.0.113.2=1", "203.0.113.3=1", "203.0.113.4=1"}) {
		t.Fatalf("after rotation: %v", got)
	}
	if fi, err := os.Stat(filepath.Join(state, "users")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("users file: %v %v", fi, err)
	}
}

// TestLoginWatchHeader: what collect.sh sends parses on the hub as counted,
// and a flood of addresses stays inside the header budget.
func TestLoginWatchHeader(t *testing.T) {
	sh := shells(t)[0]
	header := func(dir string) string {
		t.Helper()
		cmd := exec.Command(sh, collectSh, "--logins")
		cmd.Env = append(os.Environ(), "HEIMDALL_LOGIN_COUNTS="+filepath.Join(dir, "counts"))
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("--logins: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	dir := t.TempDir()
	count(t, sh, dir, fixture(t, "debian-auth.log"), fixtureNow, 0)
	v := header(dir)
	rep, ok := parseLogins(v, time.Unix(fixtureNow, 0))
	if !ok || rep.Source != "journal" || len(rep.Days) != 2 || rep.Days[0].Day != "2026-10-25" || rep.Days[0].Failures != 8 {
		t.Fatalf("parseLogins(%q) = %+v %v", v, rep, ok)
	}
	top := rep.Days[0].Rows[0]
	if top.IP != "198.51.100.23" || top.Failures != 5 || top.Usernames != 3 ||
		!top.First.Equal(time.Date(2026, 10, 25, 6, 10, 11, 0, time.UTC)) || top.Succeeded {
		t.Errorf("top row %+v", top)
	}
	if r := rep.Days[0].Rows; !slices.ContainsFunc(r, func(f store.LoginFailure) bool { return f.IP == "192.0.2.10" && f.Succeeded }) {
		t.Errorf("rows %+v: 192.0.2.10 should have then succeeded", r)
	}

	// 300 addresses: the top 200 at most, about 5 KB, and every failure in the total.
	var b strings.Builder
	for i := range 300 {
		for range 1 + i%7 {
			fmt.Fprintf(&b, "Oct 25 10:%02d:00 h sshd[%d]: Failed password for root from 2001:db8::%x port 1 ssh2\n", i%60, 1000+i, 0x1000+i)
		}
	}
	dir = t.TempDir()
	count(t, sh, dir, b.String(), fixtureNow, 0)
	v = header(dir)
	if len(v) > 5100 {
		t.Errorf("header is %d bytes", len(v))
	}
	rep, ok = parseLogins(v, time.Unix(fixtureNow, 0))
	if !ok || len(rep.Days) != 1 || len(rep.Days[0].Rows) == 0 || len(rep.Days[0].Rows) > maxLoginRows ||
		rep.Days[0].Addresses != 300 || rep.Days[0].Rows[0].Failures != 7 {
		t.Fatalf("flood: ok %v, %d rows, %+v", ok, len(rep.Days[0].Rows), rep.Days[0].Rows[:1])
	}
	total := 0
	for i := range 300 {
		total += 1 + i%7
	}
	if rep.Days[0].Failures != total {
		t.Errorf("total %d, want %d", rep.Days[0].Failures, total)
	}
}
