// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Ban alert kinds (internal/bans).
const (
	KindBan       = "ban"        // a ban was proposed (or, in auto mode, made)
	KindBanShadow = "ban_shadow" // shadow mode's daily "would have banned"
)

// AlertBan is a ban card: everything an operator needs to decide, and a
// link to the hub's ban page, where approving takes one click. Unlike
// other alerts it names an attacker's address and the hosts it tried;
// the owner asked for full context, and none of it is about the fleet's
// weaknesses. There are no buttons: approval happens only in the UI,
// behind sign-in.
type AlertBan struct {
	ID        int64     `json:"id"`
	Target    string    `json:"target"`            // 203.0.113.7, 198.51.100.0/24
	Kind      string    `json:"kind"`              // address, network
	Action    string    `json:"action"`            // challenge, block
	Reason    string    `json:"reason,omitempty"`  // why this action
	Days      int       `json:"days"`              // proposed duration
	Offense   int       `json:"offense"`           // 1 for a first ban
	Score     float64   `json:"score"`             //
	Auto      bool      `json:"auto"`              // banned without approval (auto mode)
	Prefix    string    `json:"prefix"`            // its /24 or /48
	Network   string    `json:"network,omitempty"` // "AS64500 Example ISP (US)"
	Hosts     []string  `json:"hosts"`             // "org/host"
	Failures  int       `json:"failures"`
	Usernames int       `json:"usernames"`
	Members   int       `json:"members,omitempty"` // network bans: addresses in it
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	Succeeded bool      `json:"succeeded"`
	Known     string    `json:"known"`          // what IP awareness says
	More      int       `json:"more,omitempty"` // further proposals from the same run, on the page only
	// Shadow digest only.
	Would int      `json:"would,omitempty"`
	Top   []string `json:"top,omitempty"` // "203.0.113.7 (challenge, score 14.2)"
}

func (a Alert) banSubject() string {
	b := a.Ban
	if a.Kind == KindBanShadow {
		return fmt.Sprintf("Heimdall: shadow mode would have banned %d %s", b.Would, plural(b.Would, "target", "targets"))
	}
	what := fmt.Sprintf("%s for %d %s", b.Action, b.Days, plural(b.Days, "day", "days"))
	if b.Auto {
		return "Heimdall: banned " + clean(b.Target, 64) + " (" + what + ")"
	}
	return "Heimdall: ban proposed for " + clean(b.Target, 64) + " (" + what + ")"
}

func (a Alert) banLead() string {
	at := a.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC")
	if a.Kind == KindBanShadow {
		return "Shadow mode, as of " + at + ": nothing was written to Cloudflare. These would have been proposed or banned:"
	}
	if a.Ban.Auto {
		return "Banned automatically at Cloudflare's edge, as of " + at + ":"
	}
	return "Proposed, as of " + at + ". Nothing is banned until an operator approves it:"
}

// banFacts are the card's lines, plain text.
func (a Alert) banFacts() []string {
	b := a.Ban
	if a.Kind == KindBanShadow {
		var out []string
		for i, t := range b.Top {
			if i == 10 {
				out = append(out, fmt.Sprintf("… and %d more", len(b.Top)-10))
				break
			}
			out = append(out, "• "+clean(t, 120))
		}
		return out
	}
	day := func(t time.Time) string { return t.UTC().Format("Jan 2 15:04 UTC") }
	target := clean(b.Target, 64)
	if b.Kind == "network" {
		target += fmt.Sprintf(" (a network: %d addresses in it failed)", b.Members)
	}
	out := []string{"Address: " + target}
	net := clean(b.Prefix, 64)
	if b.Network != "" {
		net += " · " + clean(b.Network, 120)
	} else {
		net += " · network name not cached"
	}
	out = append(out, "Network: "+net)
	out = append(out, fmt.Sprintf("Failed logins: %d on %d %s · %d distinct %s", b.Failures, len(b.Hosts),
		plural(len(b.Hosts), "host", "hosts"), b.Usernames, plural(b.Usernames, "username", "usernames")))
	out = append(out, "First seen "+day(b.First)+" · last seen "+day(b.Last))
	if b.Succeeded {
		out = append(out, "THEN SUCCEEDED: a login from it got in after failing")
	}
	out = append(out, "IP awareness: "+clean(b.Known, 200))
	act := fmt.Sprintf("Action: %s for %d %s", b.Action, b.Days, plural(b.Days, "day", "days"))
	if b.Offense > 1 {
		act += fmt.Sprintf(" (offense %d: doubled)", b.Offense)
	}
	if r := clean(b.Reason, 120); r != "" {
		act += " · " + r
	}
	out = append(out, act, fmt.Sprintf("Score: %.1f", b.Score))
	if b.More > 0 {
		out = append(out, fmt.Sprintf("… and %d more %s waiting on the Bans page", b.More, plural(b.More, "ban", "bans")))
	}
	return out
}

func (a Alert) banHosts() []hostLine {
	out := make([]hostLine, 0, len(a.Ban.Hosts))
	for _, h := range a.Ban.Hosts {
		out = append(out, hostLine{Host: clean(h, 160)})
	}
	return out
}

func (a Alert) banNote() string {
	switch {
	case a.Kind == KindBanShadow:
		return "Shadow mode only records. Review the scores on the hub's Bans page, then switch [bans] mode to propose."
	case a.Ban.Auto:
		return "Unban it with one click on the hub's Bans page if it's a mistake."
	}
	return "Approve or reject it on the hub's Bans page: one click after sign-in."
}

func (a Alert) banCapped() *AlertBan {
	b := *a.Ban
	b.Hosts = slices.Clone(b.Hosts[:min(len(b.Hosts), maxAlertHosts)])
	b.Top = slices.Clone(b.Top[:min(len(b.Top), maxAlertHosts)])
	for i := range b.Hosts {
		b.Hosts[i] = clean(b.Hosts[i], 160)
	}
	b.Target, b.Network, b.Known = clean(b.Target, 64), clean(b.Network, 120), clean(b.Known, 200)
	return &b
}

// banLinkText labels the card's link.
func (a Alert) banLinkText() string {
	if a.Kind == KindBan && !a.Ban.Auto {
		return "Approve / review"
	}
	return "Review bans"
}

func banFooter() string {
	return "Bans are approved only in the Heimdall UI (sign-in required)."
}

// isBan reports whether the alert is a ban card.
func (a Alert) isBan() bool {
	return (a.Kind == KindBan || a.Kind == KindBanShadow) && a.Ban != nil
}

// banText is the plain-text body of a ban card.
func (a Alert) banText() string {
	var b strings.Builder
	b.WriteString(a.banLead() + "\n\n")
	for _, l := range a.banFacts() {
		b.WriteString("  " + l + "\n")
	}
	if a.Kind == KindBan && len(a.Ban.Hosts) > 0 {
		b.WriteString("\nHosts:\n")
		for i, h := range a.Ban.Hosts {
			if i == maxAlertHosts {
				fmt.Fprintf(&b, "  … and %d more\n", len(a.Ban.Hosts)-maxAlertHosts)
				break
			}
			b.WriteString("  " + clean(h, 160) + "\n")
		}
	}
	b.WriteString("\n" + a.banNote() + "\n")
	if u := clean(a.URL, 512); u != "" {
		fmt.Fprintf(&b, "\n%s (sign-in required): %s\n", a.banLinkText(), u)
	}
	b.WriteString("\n" + banFooter() + "\n")
	return b.String()
}
