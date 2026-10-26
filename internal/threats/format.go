// SPDX-License-Identifier: AGPL-3.0-or-later

package threats

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// Formats.
const (
	FormatJSON  = "json"
	FormatCSV   = "csv"
	FormatPlain = "plain" // one address (or CIDR) per line, for firewalls
)

// Limits are a caller's default and largest row counts.
type Limits struct{ Default, Max int }

// RESTLimits and MCPLimits: a firewall wants the whole list, an
// assistant's context a short one.
var (
	RESTLimits = Limits{Default: 1000, Max: 10000}
	MCPLimits  = Limits{Default: 25, Max: 100}
)

func bad(field, msg string) error { return &store.ValidationError{Field: field, Msg: msg} }

// Parse reads a query's filters (the same for REST and MCP): since, org,
// min_score, min_hosts, source, limit and, for networks, kind and
// min_addresses. get returns a parameter's value ("" when absent).
func Parse(get func(string) string, lim Limits) (Query, error) {
	q := Query{Window: DefaultWindow, Source: SourceAll, Limit: lim.Default}
	var err error
	if s := strings.TrimSpace(get("since")); s != "" {
		if q.Window, err = ParseWindow(s); err != nil {
			return q, err
		}
	}
	q.Org = strings.TrimSpace(get("org"))
	if s := strings.TrimSpace(get("min_score")); s != "" {
		if q.MinScore, err = strconv.ParseFloat(s, 64); err != nil || q.MinScore < 0 {
			return q, bad("min_score", "must be a number, 0 or more")
		}
	}
	if q.MinHosts, err = intParam(get, "min_hosts", 0, 0, 1000); err != nil {
		return q, err
	}
	switch s := strings.ToLower(strings.TrimSpace(get("source"))); s {
	case "", SourceAll:
	case SourceSSH, SourceWeb:
		q.Source = s
	default:
		return q, bad("source", "must be ssh, web or all")
	}
	if q.Limit, err = intParam(get, "limit", lim.Default, 1, lim.Max); err != nil {
		return q, err
	}
	switch s := strings.ToLower(strings.TrimSpace(get("kind"))); s {
	case "", "all":
	case KindPrefix, KindASN:
		q.Kind = s
	default:
		return q, bad("kind", "must be prefix, asn or all")
	}
	if q.MinAddresses, err = intParam(get, "min_addresses", 1, 1, 100000); err != nil {
		return q, err
	}
	return q, nil
}

func intParam(get func(string) string, k string, def, lo, hi int) (int, error) {
	s := strings.TrimSpace(get(k))
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < lo || n > hi {
		return 0, bad(k, fmt.Sprintf("must be a whole number from %d to %d", lo, hi))
	}
	return n, nil
}

// ParseWindow reads "since": a Go duration (36h, 90m) or days (7d), from
// 1 minute to MaxWindow (30 days, how long failed logins are kept).
func ParseWindow(s string) (time.Duration, error) {
	var d time.Duration
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil {
			return 0, bad("since", "must be a duration like 24h or 7d")
		}
		d = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, bad("since", "must be a duration like 24h or 7d")
		}
	}
	if d < time.Minute || d > MaxWindow {
		return 0, bad("since", "must be from 1m to 30d (failed logins are kept 30 days)")
	}
	return d, nil
}

// ContentType is a format's media type.
func ContentType(format string) string {
	switch format {
	case FormatCSV:
		return "text/csv; charset=utf-8"
	case FormatPlain:
		return "text/plain; charset=utf-8"
	}
	return "application/json"
}

// ParseFormat reads "format" (json when empty).
func ParseFormat(s string) (string, error) {
	switch s = strings.ToLower(strings.TrimSpace(s)); s {
	case "", FormatJSON:
		return FormatJSON, nil
	case FormatCSV, FormatPlain:
		return s, nil
	}
	return "", bad("format", "must be json, csv or plain")
}

// WriteAddresses writes a result in a format.
func WriteAddresses(w io.Writer, format string, r Result) error {
	switch format {
	case FormatPlain:
		var b strings.Builder
		for _, a := range r.Addresses {
			b.WriteString(a.IP)
			b.WriteByte('\n')
		}
		_, err := io.WriteString(w, b.String())
		return err
	case FormatCSV:
		cw := csv.NewWriter(w)
		cw.Write([]string{"ip", "sources", "first_seen", "last_seen", "score", "ssh_hosts", "ssh_failures", "ssh_usernames",
			"ssh_days", "ssh_succeeded", "web_events", "web_actions", "web_zones", "web_days", "asn", "as_name", "country",
			"ban_status", "ban_action", "ban_target"})
		for _, a := range r.Addresses {
			var bs, ba, bt string
			if a.Ban != nil {
				bs, ba, bt = a.Ban.Status, a.Ban.Action, a.Ban.Target
			}
			cw.Write([]string{a.IP, strings.Join(a.Sources, " "), ts(a.FirstSeen), ts(a.LastSeen), num(a.Score),
				strconv.Itoa(a.SSH.Hosts), strconv.Itoa(a.SSH.Failures), strconv.Itoa(a.SSH.Usernames),
				strconv.Itoa(a.SSH.Days), strconv.FormatBool(a.SSH.Succeeded), strconv.Itoa(a.Web.Events),
				csvSafe(actions(a.Web.Actions)), csvSafe(strings.Join(a.Web.Zones, " ")), strconv.Itoa(a.Web.Days),
				asn(a.ASN), csvSafe(a.ASName), csvSafe(a.Country), bs, ba, bt})
		}
		cw.Flush()
		return cw.Error()
	}
	return json.NewEncoder(w).Encode(r)
}

// WriteNetworks writes a network result in a format. Plain lists only the
// /24 and /48 prefixes (an ASN isn't a range a firewall can match).
func WriteNetworks(w io.Writer, format string, r NetworkResult) error {
	switch format {
	case FormatPlain:
		var b strings.Builder
		for _, n := range r.Networks {
			if n.Kind == KindPrefix {
				b.WriteString(n.Network)
				b.WriteByte('\n')
			}
		}
		_, err := io.WriteString(w, b.String())
		return err
	case FormatCSV:
		cw := csv.NewWriter(w)
		cw.Write([]string{"network", "kind", "asn", "as_name", "country", "addresses", "failures", "events", "hosts",
			"first_seen", "last_seen", "top"})
		for _, n := range r.Networks {
			cw.Write([]string{n.Network, n.Kind, asn(n.ASN), csvSafe(n.ASName), csvSafe(n.Country), strconv.Itoa(n.Addresses),
				strconv.Itoa(n.Failures), strconv.Itoa(n.Events), strconv.Itoa(n.Hosts), ts(n.FirstSeen), ts(n.LastSeen),
				strings.Join(n.Top, " ")})
		}
		cw.Flush()
		return cw.Error()
	}
	return json.NewEncoder(w).Encode(r)
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func num(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func asn(n int64) string {
	if n == 0 {
		return ""
	}
	return strconv.FormatInt(n, 10)
}

// actions is "block:3 managed_challenge:12", sorted by action.
func actions(m map[string]int) string {
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		parts = append(parts, k+":"+strconv.Itoa(m[k]))
	}
	return strings.Join(parts, " ")
}

// csvSafe stops spreadsheets from treating a cell as a formula.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
