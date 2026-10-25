// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

// LoginsHeader carries what the opt-in login watch (install.sh
// --watch-logins) counted: failed SSH logins per source address for today
// and yesterday (UTC). Counts only, never usernames (docs/failed-logins.md):
//
//	v1 <source> <counted-at> <day>:<failures>:<addresses>[=<entry>,...] ...
//	entry: <failures>:<usernames>:<first>:<last>:<succeeded>:<ip>
//
// first and last are seconds into the day. A header, not a snapshot field,
// like the privilege watch's, so hubs and collectors of different versions
// still accept each other. A malformed header is ignored and a malformed
// entry skipped; neither fails the push.
const LoginsHeader = "X-Heimdall-Logins"

const (
	maxLoginsHeader = 8 << 10
	maxLoginRows    = 200 // per push, across its days
	maxLoginDays    = 3
	maxLoginCount   = 1_000_000_000
	maxLoginUsers   = 1_000_000
)

// loginSources are where a login watch can read failures from.
var loginSources = map[string]bool{"journal": true, "auth.log": true, "secure": true, "messages": true,
	"none": true, "unreadable": true}

// parseLogins parses a LoginsHeader value; ok is false when it's absent or
// malformed as a whole.
func parseLogins(v string, now time.Time) (rep store.LoginReport, ok bool) {
	if len(v) > maxLoginsHeader {
		return rep, false
	}
	f := strings.Fields(v)
	if len(f) < 3 || f[0] != "v1" || !loginSources[f[1]] {
		return rep, false
	}
	rep.Source = f[1]
	counted, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil || counted < 0 {
		return rep, false
	}
	if at := time.Unix(counted, 0); counted > 0 && !at.Before(now.Add(-maxPrivilegeAge)) && !at.After(now.Add(MaxSkew)) {
		rep.CountedAt = at.UTC()
	}
	if len(f) > 3+maxLoginDays {
		return rep, false
	}
	today := now.UTC().Truncate(24 * time.Hour)
	rows := 0
	for _, g := range f[3:] {
		head, list, _ := strings.Cut(g, "=")
		parts := strings.Split(head, ":")
		if len(parts) != 3 {
			return rep, false
		}
		start, err := time.Parse(time.DateOnly, parts[0])
		if err != nil || start.Before(today.AddDate(0, 0, -2)) || start.After(today.AddDate(0, 0, 1)) ||
			slices.ContainsFunc(rep.Days, func(d store.LoginDay) bool { return d.Day == parts[0] }) {
			continue
		}
		d := store.LoginDay{Day: parts[0]}
		var ok1, ok2 bool
		d.Failures, ok1 = loginCount(parts[1], 0, maxLoginCount)
		d.Addresses, ok2 = loginCount(parts[2], 0, maxLoginCount)
		if !ok1 || !ok2 {
			continue
		}
		seen := map[string]bool{}
		sum := 0
		for e := range strings.SplitSeq(list, ",") {
			if e == "" || rows == maxLoginRows {
				continue
			}
			r, ok := parseLoginEntry(e, start, now)
			if !ok || seen[r.IP] {
				continue
			}
			seen[r.IP] = true
			d.Rows = append(d.Rows, r)
			sum += r.Failures
			rows++
		}
		d.Failures = max(d.Failures, min(sum, maxLoginCount))
		d.Addresses = max(d.Addresses, len(d.Rows))
		rep.Days = append(rep.Days, d)
	}
	return rep, true
}

// loginCount parses a non-negative count in [lo, hi].
func loginCount(s string, lo, hi int) (int, bool) {
	if s == "" || len(s) > 10 || strings.TrimLeft(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	return n, err == nil && n >= lo && n <= hi
}

func parseLoginEntry(e string, day time.Time, now time.Time) (store.LoginFailure, bool) {
	var r store.LoginFailure
	p := strings.SplitN(e, ":", 6)
	if len(p) != 6 {
		return r, false
	}
	var ok [4]bool
	var first, last int
	r.Failures, ok[0] = loginCount(p[0], 1, maxLoginCount)
	r.Usernames, ok[1] = loginCount(p[1], 0, maxLoginUsers)
	first, ok[2] = loginCount(p[2], 0, 86399)
	last, ok[3] = loginCount(p[3], 0, 86399)
	if ok != [4]bool{true, true, true, true} || first > last || (p[4] != "0" && p[4] != "1") {
		return r, false
	}
	a, err := netip.ParseAddr(p[5])
	if err != nil || a.Zone() != "" || len(p[5]) > 45 {
		return r, false
	}
	r.IP = a.Unmap().String()
	r.First, r.Last = day.Add(time.Duration(first)*time.Second), day.Add(time.Duration(last)*time.Second)
	if r.Last.After(now.Add(MaxSkew)) {
		return r, false
	}
	r.Succeeded = p[4] == "1"
	return r, true
}

// recordLogins stores what a push's LoginsHeader reported. Failures are
// logged, never returned: the snapshot is already stored.
func (h *Handler) recordLogins(ctx context.Context, log *slog.Logger, host store.IngestHost, r *http.Request) {
	vals := r.Header.Values(LoginsHeader)
	if len(vals) == 0 {
		return
	}
	rep, ok := parseLogins(onlyHeader(r, LoginsHeader), h.acc.Now())
	if !ok {
		log.Warn("ignored a malformed " + LoginsHeader + " header")
		return
	}
	if err := h.store.RecordLogins(ctx, host.ID, rep, h.acc.Now()); err != nil {
		log.Error("could not store failed logins", "err", err)
	}
}
