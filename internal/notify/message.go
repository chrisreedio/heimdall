// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"fmt"
	"strings"
	"time"
)

// message is what the chat destinations (Slack, Discord) render: the same
// facts as the plain-text Subject and Text, split into parts so each
// destination can escape and lay them out its own way. Every string here
// is plain text; renderers escape it.
type message struct {
	Title    string // no host names: it lands in notifications and headers
	Severity string // "high", "medium", "ok" or "info"
	Lead     string
	Lines    []string   // count lines (digest)
	Hosts    []hostLine // host lines (alerts), rendered as code
	Note     string
	URL      string
	Footer   string
	At       time.Time
}

type hostLine struct {
	Host  string // "org/host"
	Label string // anomaly label, or ""
}

// maxChatHosts caps host lines in chat messages, which should stay short.
const maxChatHosts = 20

func digestMessage(d Digest) message {
	scope := "all organizations"
	if org := clean(d.Org, 64); org != "" {
		scope = "org " + org
	}
	sev := "ok"
	switch {
	case d.KEV > 0 || d.Critical > 0:
		sev = "high"
	case d.High > 0 || d.NewSinceLast > 0 || d.Stale > 0 || d.OpenAnomalies > 0:
		sev = "medium"
	}
	return message{
		Title:    d.Subject(),
		Severity: sev,
		Lead:     "Digest for " + scope + ".",
		Lines: []string{
			fmt.Sprintf("Findings: %d known exploited · %d critical · %d high · %d fixable · %d new since the last digest",
				d.KEV, d.Critical, d.High, d.Fixable, d.NewSinceLast),
			fmt.Sprintf("Fleet: %d %s · %d stale · %d end-of-life · %d %s · %d %s",
				d.Hosts, plural(d.Hosts, "host", "hosts"), d.Stale, d.EOLHosts,
				d.SitesNeedingAttention, plural(d.SitesNeedingAttention, "site needs attention", "sites need attention"),
				d.OpenAnomalies, plural(d.OpenAnomalies, "open anomaly", "open anomalies")),
		},
		URL:    clean(d.URL, 512),
		Footer: "Counts only, by design.",
		At:     d.GeneratedAt,
	}
}

func alertMessage(a Alert) message {
	return message{
		Title:    a.Subject(),
		Severity: a.Severity(),
		Lead:     a.lead(),
		Hosts:    a.lines(),
		Note:     a.note(),
		URL:      clean(a.URL, 512),
		Footer:   a.footer(),
		At:       a.GeneratedAt,
	}
}

// truncate cuts s to at most max runes, at a line break when it can,
// ending with an ellipsis.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	cut := string(r[:max-1])
	if i := strings.LastIndexByte(cut, '\n'); i > len(cut)/2 {
		cut = cut[:i]
	}
	return cut + "…"
}

// safeLinkURL returns u if it's a plain http(s) URL that can't break out
// of a chat link's syntax, else "".
func safeLinkURL(u string) string {
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return ""
	}
	if strings.ContainsAny(u, " <>|()[]`\"'\\") {
		return ""
	}
	return u
}
