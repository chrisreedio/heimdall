// SPDX-License-Identifier: AGPL-3.0-or-later

package push

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Kinds of notice that aren't events.
const (
	kindTest   = "test"   // "Send a test notification"
	kindDigest = "digest" // the daily digest
	kindHeld   = "held"   // what waited for quiet hours to end
)

// Notice is one notification, before it's worded. It names at most a host
// and counts: no package, address, username or summary can reach a
// notification, since there's no field to hold one.
type Notice struct {
	Kind    string
	OrgSlug string // with Host: for the link to the host's page
	Host    string // the one host it's about, or ""
	Hosts   int    // about more than one host: how many
	Count   int    // how many events
	Ref     int64  // a ban's ID, for its link
	Parts   []Part // digest and held: what's in it
}

// Part is one line of a digest or held summary: a kind (or a digest
// count's name) and how many.
type Part struct {
	What string
	N    int
}

// Lock-screen detail.
const (
	DetailHost   = "host"   // the kind and the host: "Known-exploited finding on web-01"
	DetailHidden = "hidden" // only "Heimdall needs attention"
)

// payload is what the service worker gets (static/sw.js): the words to
// show, the same-site path to open, and the tag a newer notification with
// the same subject replaces.
type payload struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	URL   string `json:"url"`
	Tag   string `json:"tag"`
}

// Tag is what collapses repeats: the same kind on the same host (or the
// same ban) replaces the notification already showing.
func (n Notice) Tag() string {
	switch {
	case n.Kind == KindBan && n.Ref > 0 && n.Count <= 1:
		return "ban:" + strconv.FormatInt(n.Ref, 10)
	case n.Host != "":
		return n.Kind + ":" + n.OrgSlug + "/" + n.Host
	}
	return n.Kind
}

// Urgency is the push service's delivery priority (RFC 8030): high for
// what bypasses quiet hours, normal for the rest.
func (n Notice) Urgency() string {
	if bypassQuiet[n.Kind] {
		return "high"
	}
	return "normal"
}

// TTL is how long a push service keeps the message for a phone that's off.
func (n Notice) TTL() time.Duration {
	switch n.Kind {
	case kindTest:
		return 10 * time.Minute
	case kindDigest:
		return 12 * time.Hour
	}
	return 24 * time.Hour
}

// topic names the message for the push service, so an undelivered one is
// replaced by a newer one with the same tag. RFC 8030: up to 32 characters
// of the URL-safe base64 alphabet.
func topic(tag string) string {
	sum := sha256.Sum256([]byte(tag))
	return b64.EncodeToString(sum[:])[:32]
}

// message is the wire form of a notice for one user's detail setting.
// name is the hub's display name.
func (n Notice) message(name, detail string) (Message, error) {
	p := n.payload(name, detail)
	b, err := json.Marshal(p)
	if err != nil {
		return Message{}, err
	}
	return Message{Payload: b, TTL: n.TTL(), Urgency: n.Urgency(), Topic: topic(p.Tag)}, nil
}

func (n Notice) payload(name, detail string) payload {
	name = clean(name, 30)
	if name == "" {
		name = "Heimdall"
	}
	if n.Kind == kindTest { // says nothing about the fleet either way
		return payload{Title: "Test notification", Body: "Notifications from " + name + " reach this device.",
			URL: "/account/notifications", Tag: kindTest}
	}
	if detail == DetailHidden {
		return payload{Title: name + " needs attention", Body: "Open the app to see what's new.", URL: "/", Tag: "heimdall"}
	}
	host := clean(n.Host, 100)
	on := " on " + host
	if host == "" {
		on = " on " + plural(n.Hosts, "host", "hosts")
	}
	p := payload{Tag: n.Tag()}
	hostPage := func(fallback string) string {
		if host != "" && n.OrgSlug != "" {
			return "/hosts/" + url.PathEscape(n.OrgSlug) + "/" + url.PathEscape(n.Host)
		}
		return fallback
	}
	switch n.Kind {
	case KindKEV:
		p.Title = counted(n, "Known-exploited finding", "known-exploited findings") + on
		p.Body = "Being exploited in the wild: patch it first."
		p.URL = hostPage("/hosts?only=kev&sort=priority")
	case KindNews:
		p.Title = "In the news: an incident affects " + strings.TrimPrefix(on, " on ")
		if n.Count > 1 && host != "" {
			p.Title = fmt.Sprintf("In the news: %d incidents affect %s", n.Count, host)
		}
		p.Body = "Being exploited now, and it matches this host's findings."
		p.URL = "/news?affects=me"
	case KindAnomaly:
		p.Title = counted(n, "Anomaly", "anomalies") + on
		p.Body = "A tripwire fired. Review it on Alerts."
		p.URL = "/alerts"
	case KindPrivilege:
		p.Title = "Privileged access from an unknown address" + on
		if n.Count > 1 && host != "" {
			p.Title = fmt.Sprintf("%d privileged sessions from unknown addresses%s", n.Count, on)
		}
		p.Body = "Nothing is known about the address it came from."
		p.URL = "/alerts"
	case KindBan:
		p.Title = "Ban proposal waiting for approval"
		if n.Count > 1 {
			p.Title = fmt.Sprintf("%d ban proposals waiting for approval", n.Count)
		}
		p.Body = "Approve or dismiss it on Defense."
		p.URL = "/defense"
		if n.Ref > 0 && n.Count <= 1 {
			p.URL = "/defense#ban-" + strconv.FormatInt(n.Ref, 10)
		}
	case KindSilent:
		if host != "" {
			p.Title = host + " stopped reporting"
		} else {
			p.Title = plural(n.Hosts, "host", "hosts") + " stopped reporting"
		}
		p.Body = "No report past the stale threshold. Check the host and its collector."
		p.URL = hostPage("/hosts?only=stale&sort=seen")
	case kindDigest:
		p.Title = "Daily digest"
		p.Body = parts(n.Parts)
		p.URL = "/"
	case kindHeld:
		p.Title = "During quiet hours"
		p.Body = parts(n.Parts)
		p.URL = "/alerts"
	default:
		p.Title, p.Body, p.URL = name+" needs attention", "Open the app to see what's new.", "/"
	}
	return p
}

// counted is "Anomaly" for one and "3 anomalies" for more (on one host),
// or the plural alone across several hosts.
func counted(n Notice, one, many string) string {
	switch {
	case n.Host == "":
		return strings.ToUpper(many[:1]) + many[1:]
	case n.Count > 1:
		return strconv.Itoa(n.Count) + " " + many
	}
	return one
}

// partWords are a digest line's words, singular and plural.
var partWords = map[string][2]string{
	KindKEV:       {"known-exploited finding", "known-exploited findings"},
	KindNews:      {"incident in the news", "incidents in the news"},
	KindAnomaly:   {"anomaly", "anomalies"},
	KindPrivilege: {"privileged session from an unknown address", "privileged sessions from unknown addresses"},
	KindBan:       {"ban proposal waiting", "ban proposals waiting"},
	KindSilent:    {"host stopped reporting", "hosts stopped reporting"},
	"security":    {"host with security updates", "hosts with security updates"},
	"eol":         {"host near end of life", "hosts near end of life"},
	"behind":      {"collector to upgrade", "collectors to upgrade"},
}

// parts words a digest: "2 anomalies, 5 hosts with security updates".
func parts(ps []Part) string {
	var out []string
	for _, p := range ps {
		w, ok := partWords[p.What]
		if !ok || p.N <= 0 {
			continue
		}
		out = append(out, strconv.Itoa(p.N)+" "+map[bool]string{true: w[0], false: w[1]}[p.N == 1])
	}
	return strings.Join(out, ", ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// clean drops control characters and caps length.
func clean(s string, max int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}
