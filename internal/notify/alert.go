// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Alert is an immediate notice that hosts went silent, or reported again
// after a silence alert. Unlike a Digest it names the hosts, since "which
// one stopped" is the whole point, but it carries nothing else: no OS,
// packages, versions or findings. The type has no field that could.
type Alert struct {
	Kind        string    `json:"kind"` // "silent" or "back"
	GeneratedAt time.Time `json:"generated_at"`
	Hosts       []string  `json:"hosts"` // "org/host"
	Count       int       `json:"count"`
	AlertAfter  string    `json:"alert_after,omitempty"` // the threshold, e.g. "3h0m0s"
	URL         string    `json:"url"`                   // link to the UI's Anomalies page
}

// AlertSender delivers an Alert. Email and Webhook implement it.
type AlertSender interface {
	SendAlert(ctx context.Context, a Alert) error
}

// maxAlertHosts caps how many names an alert lists.
const maxAlertHosts = 50

// Subject is a one-line summary, e.g. "Heimdall: 2 hosts stopped reporting".
func (a Alert) Subject() string {
	if a.Kind == "back" {
		return fmt.Sprintf("Heimdall: %d %s reporting again", a.Count, plural(a.Count, "host is", "hosts are"))
	}
	return fmt.Sprintf("Heimdall: %d %s stopped reporting", a.Count, plural(a.Count, "host", "hosts"))
}

// Text renders the plain-text body.
func (a Alert) Text() string {
	var b strings.Builder
	at := a.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC")
	if a.Kind == "back" {
		fmt.Fprintf(&b, "Reporting again as of %s, after a silence alert:\n\n", at)
	} else {
		quiet := "recently"
		if s := clean(a.AlertAfter, 32); s != "" {
			quiet = "for more than " + s
		}
		fmt.Fprintf(&b, "No report %s, as of %s:\n\n", quiet, at)
	}
	for i, h := range a.Hosts {
		if i == maxAlertHosts {
			fmt.Fprintf(&b, "  … and %d more\n", len(a.Hosts)-maxAlertHosts)
			break
		}
		fmt.Fprintf(&b, "  %s\n", clean(h, 160))
	}
	if a.Kind == "back" {
		b.WriteString("\nThe silence anomaly stays open until someone acknowledges it.\n")
	} else {
		b.WriteString("\nA collector that stops is the easiest way to hide changes. Check whether the host is\n" +
			"down or its collector was disabled.\n")
	}
	if u := clean(a.URL, 512); u != "" {
		fmt.Fprintf(&b, "\nDetails (sign-in required): %s\n", u)
	}
	b.WriteString("\nThis alert only contains host names, by design.\n")
	return b.String()
}

// capped returns a copy with at most maxAlertHosts names (for JSON).
func (a Alert) capped() Alert {
	hosts := make([]string, 0, min(len(a.Hosts), maxAlertHosts))
	for _, h := range a.Hosts[:min(len(a.Hosts), maxAlertHosts)] {
		hosts = append(hosts, clean(h, 160))
	}
	a.Hosts = hosts
	return a
}
