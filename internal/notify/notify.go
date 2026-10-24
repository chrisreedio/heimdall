// SPDX-License-Identifier: AGPL-3.0-or-later

// Package notify sends digests and alerts by email, a generic webhook,
// Slack or Discord. A digest carries only counts and a link to the UI: no
// hostnames, package names, versions or advisory IDs, so a leaked email or
// chat message doesn't reveal where the fleet is weak. The Digest type has
// no field that could hold such details.
//
// The one exception is the Alert (alert.go): it names the hosts that
// stopped or resumed reporting, or raised a high-signal anomaly (with a
// fixed label for the rule), and nothing else about them.
package notify

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// Digest is a count-only summary of an install or one org.
type Digest struct {
	Org         string    `json:"org"` // org slug ("" = whole install)
	GeneratedAt time.Time `json:"generated_at"`

	Hosts int `json:"hosts"`
	Stale int `json:"stale_hosts"`

	KEV      int `json:"kev"`      // open findings that are known exploited
	Critical int `json:"critical"` // open critical findings
	High     int `json:"high"`
	Fixable  int `json:"fixable"` // open findings with a fix available

	NewSinceLast int `json:"new_since_last"` // findings first seen since the previous digest

	EOLHosts              int `json:"eol_hosts"`
	SitesNeedingAttention int `json:"sites_needing_attention"`
	OpenAnomalies         int `json:"open_anomalies"`

	URL string `json:"url"` // link to the UI dashboard
}

// Sender delivers a digest.
type Sender interface {
	Send(ctx context.Context, d Digest) error
}

// Subject is a one-line summary, e.g.
// "Heimdall: 2 known-exploited, 5 critical (acme)".
func (d Digest) Subject() string {
	var parts []string
	if d.KEV > 0 {
		parts = append(parts, fmt.Sprintf("%d known-exploited", d.KEV))
	}
	if d.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", d.Critical))
	}
	if d.NewSinceLast > 0 {
		parts = append(parts, fmt.Sprintf("%d new", d.NewSinceLast))
	}
	summary := "no urgent findings"
	if len(parts) > 0 {
		summary = strings.Join(parts, ", ")
	}
	s := "Heimdall: " + summary
	if org := clean(d.Org, 64); org != "" {
		s += " (" + org + ")"
	}
	return s
}

// Text renders the plain-text body.
func (d Digest) Text() string {
	var b strings.Builder
	scope := "all organizations"
	if org := clean(d.Org, 64); org != "" {
		scope = "org " + org
	}
	fmt.Fprintf(&b, "Heimdall digest for %s, %s\n\n", scope, d.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC"))
	line := func(n int, what string) { fmt.Fprintf(&b, "  %6d  %s\n", n, what) }
	b.WriteString("Findings (open)\n")
	line(d.KEV, "known exploited (CISA KEV)")
	line(d.Critical, "critical")
	line(d.High, "high")
	line(d.Fixable, "fixable now")
	line(d.NewSinceLast, "new since the last digest")
	b.WriteString("\nFleet\n")
	line(d.Hosts, plural(d.Hosts, "host reporting", "hosts reporting"))
	line(d.Stale, plural(d.Stale, "host not reporting (stale)", "hosts not reporting (stale)"))
	line(d.EOLHosts, plural(d.EOLHosts, "host with an end-of-life OS or runtime", "hosts with an end-of-life OS or runtime"))
	line(d.SitesNeedingAttention, plural(d.SitesNeedingAttention, "site needing attention", "sites needing attention"))
	line(d.OpenAnomalies, plural(d.OpenAnomalies, "open anomaly", "open anomalies"))
	if u := clean(d.URL, 512); u != "" {
		fmt.Fprintf(&b, "\nDetails (sign-in required): %s\n", u)
	}
	b.WriteString("\nThis digest only contains counts, by design.\n")
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// clean drops control characters (including CR/LF) and caps length, so a
// value can't inject headers or lines.
func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}
