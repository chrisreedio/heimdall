// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"html/template"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/realmwatch/heimdall/internal/report"
)

// An AI answer is plain text (the prompt asks for no markup, and it's never
// trusted as HTML). aiLinker escapes it, then turns the hostnames and site
// domains Heimdall knows in the org, and CVE IDs, into small linked badges.
// Names match whole and ignoring case; anything else stays plain text.
type aiLinker struct {
	links map[string]aiLink // by lowercased name
	re    *regexp.Regexp
}

type aiLink struct {
	Kind, Name, URL string // Kind is "host", "site" or "cve"
}

var cvePattern = `CVE-\d{4}-\d{4,7}`

// newAILinker builds a linker for an org's hosts and their sites. A site
// domain served by more than one host is left plain (which would it mean?),
// and a hostname wins over a site domain spelled the same.
func newAILinker(org string, hosts []report.Host) *aiLinker {
	l := &aiLinker{links: map[string]aiLink{}}
	sites := map[string]aiLink{}
	ambiguous := map[string]bool{}
	for _, h := range hosts {
		l.links[strings.ToLower(h.Name)] = aiLink{Kind: "host", Name: h.Name, URL: hostURL(org, h.Name)}
		for _, s := range h.Sites {
			for _, n := range s.ServerNames {
				key := strings.ToLower(n)
				if !linkableSite.MatchString(n) || ambiguous[key] {
					continue
				}
				if prev, ok := sites[key]; ok && prev.URL != siteURL(org, h.Name, s.Root) {
					delete(sites, key)
					ambiguous[key] = true
					continue
				}
				sites[key] = aiLink{Kind: "site", Name: n, URL: siteURL(org, h.Name, s.Root)}
			}
		}
	}
	for k, s := range sites {
		if _, isHost := l.links[k]; !isHost {
			l.links[k] = s
		}
	}
	names := make([]string, 0, len(l.links))
	for k := range l.links {
		names = append(names, regexp.QuoteMeta(k))
	}
	// Longest first, so web-01.example.com wins over web-01.
	slices.SortFunc(names, func(a, b string) int { return len(b) - len(a) })
	l.re = regexp.MustCompile(`(?i)` + strings.Join(append(names, cvePattern), "|"))
	return l
}

// linkableSite is a server name worth linking: a dotted domain, not "_",
// a wildcard or an address.
var linkableSite = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$`)

var cveName = regexp.MustCompile(`(?i)^` + cvePattern + `$`)

// wordByte is part of a name: a match next to one isn't the whole name.
func wordByte(b byte) bool {
	return b == '-' || b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// HTML is text, escaped, with the names it knows linked. A nil linker
// only escapes (AI text without an org, or with linking unavailable).
func (l *aiLinker) HTML(text string) template.HTML {
	if l == nil {
		return template.HTML(template.HTMLEscapeString(text))
	}
	var b strings.Builder
	last := 0
	for _, m := range l.re.FindAllStringIndex(text, -1) {
		i, j := m[0], m[1]
		before := i > 0 && (wordByte(text[i-1]) || text[i-1] == '.')
		// A trailing period ends a sentence; one followed by more name doesn't.
		after := j < len(text) && (wordByte(text[j]) || text[j] == '.' && j+1 < len(text) && wordByte(text[j+1]))
		if before || after {
			continue
		}
		word := text[i:j]
		link, ok := l.links[strings.ToLower(word)]
		if !ok && cveName.MatchString(word) {
			link, ok = aiLink{Kind: "cve", Name: strings.ToUpper(word), URL: "/search?q=" + url.QueryEscape(strings.ToUpper(word))}, true
		}
		if !ok {
			continue
		}
		b.WriteString(template.HTMLEscapeString(text[last:i]))
		b.WriteString(link.html(word))
		last = j
	}
	b.WriteString(template.HTMLEscapeString(text[last:]))
	return template.HTML(b.String())
}

// refIcons are the badges' icons: the "server" and "globe" ones from the
// icon partial.
var refIcons = map[string]string{
	"host": `<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>`,
	"site": `<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>`,
}

var refTitles = map[string]string{"host": "Host", "site": "Site", "cve": "Search for this CVE"}

func (a aiLink) html(text string) string {
	var b strings.Builder
	b.WriteString(`<a class="ref ref-` + a.Kind + `" href="` + template.HTMLEscapeString(a.URL) + `" title="` + refTitles[a.Kind] + `">`)
	if icon := refIcons[a.Kind]; icon != "" {
		b.WriteString(`<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">` + icon + `</svg>`)
	}
	b.WriteString(template.HTMLEscapeString(text))
	b.WriteString(`</a>`)
	return b.String()
}
