// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Alert kinds.
const (
	KindSilent  = "silent"  // hosts stopped reporting (hosts.alert_after)
	KindBack    = "back"    // hosts reporting again after a silence alert
	KindAnomaly = "anomaly" // new high-signal anomalies (see AlertRule)
	KindTest    = "test"    // `heimdall notify test`
)

// Alert is an immediate notice: hosts went silent, came back, or raised a
// high-signal anomaly. Unlike a Digest it names the hosts, since "which one"
// is the whole point, but it carries nothing else about them: no OS,
// packages, versions, findings or the anomaly's own summary (which can name
// packages or users). The type has no field that could.
type Alert struct {
	Kind        string         `json:"kind"` // KindSilent, KindBack, KindAnomaly or KindTest
	GeneratedAt time.Time      `json:"generated_at"`
	Hosts       []string       `json:"hosts"` // "org/host"
	Count       int            `json:"count"`
	AlertAfter  string         `json:"alert_after,omitempty"` // the threshold, e.g. "3h0m0s"
	Anomalies   []AlertAnomaly `json:"anomalies,omitempty"`   // KindAnomaly only
	URL         string         `json:"url"`                   // link to the UI's Anomalies page
	Ban         *AlertBan      `json:"ban,omitempty"`         // KindBan and KindBanShadow only (ban.go)
}

// AlertAnomaly is one anomaly in an alert: where, which rule, how bad.
type AlertAnomaly struct {
	Host     string `json:"host"` // "org/host"
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
}

// AlertSender delivers an Alert. Every destination implements it.
type AlertSender interface {
	SendAlert(ctx context.Context, a Alert) error
}

// maxAlertHosts caps how many names an alert lists.
const maxAlertHosts = 50

// alwaysAlert are the rules that notify immediately whatever their
// severity: a switched-off watch, privileged access outside a window, or an
// origin no longer behind Cloudflare.
var alwaysAlert = map[string]bool{"trigger_disabled": true, "privilege_watch_disabled": true, "privileged_access": true,
	"dns_unproxied": true} // an origin made public is worth knowing now

// AlertRule reports whether a new anomaly is sent as an immediate alert:
// the rules above, plus anything high or critical. Silence has its own
// alert (KindSilent), so it's excluded here.
func AlertRule(rule, severity string) bool {
	if rule == "silence" {
		return false
	}
	return alwaysAlert[rule] || severity == "high" || severity == "critical"
}

// ruleLabels are the fixed, human names used in alerts. An anomaly's own
// summary is never sent, since it may name packages or users.
var ruleLabels = map[string]string{
	"trigger_disabled":         "change reporting disabled",
	"privilege_watch_disabled": "privilege watch disabled",
	"privileged_access":        "privileged access outside a maintenance window",
	"privilege_unknown_source": "privileged access from an unknown address",
	"privilege_off_tailnet":    "SSH from outside the tailnet",
	"silent_online":            "stopped reporting, still on the tailnet",
	"login_then_succeeded":     "failed logins, then a successful one, from an unknown address",
	"dns_unproxied":            "a public name stopped going through Cloudflare",
	"cname_takeover":           "a public name points at a CNAME anyone could claim",
	"collector_changed":        "collector changed",
	"collector_downgrade":      "collector downgraded",
	"package_downgrade":        "package downgraded",
	"package_drop":             "packages vanished from the inventory",
	"package_change":           "packages changed outside a window",
	"replay":                   "replayed report",
	"clock_skew":               "clock skew",
	"silence":                  "went silent",
}

// RuleLabel is the alert's name for a rule.
func RuleLabel(rule string) string {
	if l, ok := ruleLabels[rule]; ok {
		return l
	}
	return strings.ReplaceAll(clean(rule, 40), "_", " ")
}

// Subject is a one-line summary, e.g. "Heimdall: 2 hosts stopped reporting".
func (a Alert) Subject() string {
	if a.isBan() {
		return a.banSubject()
	}
	switch a.Kind {
	case KindBack:
		return fmt.Sprintf("Heimdall: %d %s reporting again", a.Count, plural(a.Count, "host is", "hosts are"))
	case KindAnomaly:
		return fmt.Sprintf("Heimdall: %d new %s", a.Count, plural(a.Count, "anomaly needs a look", "anomalies need a look"))
	case KindTest:
		return "Heimdall: test message"
	}
	return fmt.Sprintf("Heimdall: %d %s stopped reporting", a.Count, plural(a.Count, "host", "hosts"))
}

// Severity is how loud the alert is: "high", "medium", "ok" or "info".
func (a Alert) Severity() string {
	if a.isBan() {
		if a.Kind == KindBan && (a.Ban.Succeeded || a.Ban.Auto) {
			return "high"
		}
		return map[bool]string{true: "info", false: "medium"}[a.Kind == KindBanShadow]
	}
	switch a.Kind {
	case KindBack:
		return "ok"
	case KindTest:
		return "info"
	case KindAnomaly:
		sev := "medium"
		for _, an := range a.Anomalies {
			if an.Severity == "high" || an.Severity == "critical" {
				sev = "high"
			}
		}
		return sev
	}
	return "high"
}

// quietFor is the silence threshold in words ("for more than 3h").
func (a Alert) quietFor() string {
	if s := clean(a.AlertAfter, 32); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			s = shortDuration(d)
		}
		return "for more than " + s
	}
	return "recently"
}

// lead is the alert's first sentence, without hosts.
func (a Alert) lead() string {
	if a.isBan() {
		return a.banLead()
	}
	at := a.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC")
	switch a.Kind {
	case KindBack:
		return "Reporting again as of " + at + ", after a silence alert:"
	case KindAnomaly:
		return "New as of " + at + ":"
	case KindTest:
		return "This is a test from heimdall notify test, sent " + at + ". Alerts and digests will arrive here."
	}
	return "No report " + a.quietFor() + ", as of " + at + ":"
}

// note is the alert's closing advice.
func (a Alert) note() string {
	if a.isBan() {
		return a.banNote()
	}
	switch a.Kind {
	case KindBack:
		return "The silence anomaly stays open until someone acknowledges it."
	case KindAnomaly:
		return "Review and acknowledge them on the Anomalies page."
	case KindTest:
		return ""
	}
	return "A collector that stops is the easiest way to hide changes. Check whether the host is down or its collector was disabled."
}

// lines are the alert's hosts, each with its anomaly label for KindAnomaly.
func (a Alert) lines() []hostLine {
	if a.isBan() {
		if a.Kind == KindBanShadow {
			return nil
		}
		return a.banHosts()
	}
	if a.Kind == KindAnomaly {
		out := make([]hostLine, 0, len(a.Anomalies))
		for _, an := range a.Anomalies {
			out = append(out, hostLine{Host: clean(an.Host, 160), Label: RuleLabel(an.Rule)})
		}
		return out
	}
	out := make([]hostLine, 0, len(a.Hosts))
	for _, h := range a.Hosts {
		out = append(out, hostLine{Host: clean(h, 160)})
	}
	return out
}

// Text renders the plain-text body.
func (a Alert) Text() string {
	if a.isBan() {
		return a.banText()
	}
	var b strings.Builder
	b.WriteString(a.lead() + "\n")
	if lines := a.lines(); len(lines) > 0 {
		b.WriteString("\n")
		for i, l := range lines {
			if i == maxAlertHosts {
				fmt.Fprintf(&b, "  … and %d more\n", len(lines)-maxAlertHosts)
				break
			}
			if l.Label != "" {
				fmt.Fprintf(&b, "  %s: %s\n", l.Host, l.Label)
			} else {
				fmt.Fprintf(&b, "  %s\n", l.Host)
			}
		}
	}
	if n := a.note(); n != "" {
		b.WriteString("\n" + n + "\n")
	}
	if u := clean(a.URL, 512); u != "" {
		fmt.Fprintf(&b, "\nDetails (sign-in required): %s\n", u)
	}
	b.WriteString("\n" + a.footer() + "\n")
	return b.String()
}

func (a Alert) footer() string {
	if a.isBan() {
		return banFooter()
	}
	if a.Kind == KindTest {
		return "Test only: nothing needs doing."
	}
	return "This alert only contains host names, by design."
}

// capped returns a copy with at most maxAlertHosts names (for JSON).
func (a Alert) capped() Alert {
	hosts := make([]string, 0, min(len(a.Hosts), maxAlertHosts))
	for _, h := range a.Hosts[:min(len(a.Hosts), maxAlertHosts)] {
		hosts = append(hosts, clean(h, 160))
	}
	a.Hosts = hosts
	if len(a.Anomalies) > 0 {
		ans := make([]AlertAnomaly, 0, min(len(a.Anomalies), maxAlertHosts))
		for _, an := range a.Anomalies[:min(len(a.Anomalies), maxAlertHosts)] {
			ans = append(ans, AlertAnomaly{Host: clean(an.Host, 160), Rule: clean(an.Rule, 40), Severity: clean(an.Severity, 16)})
		}
		a.Anomalies = ans
	}
	if a.Ban != nil {
		a.Ban = a.banCapped()
	}
	return a
}

// shortDuration formats 3h0m0s as "3h" and 1h30m0s as "1h30m".
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}
