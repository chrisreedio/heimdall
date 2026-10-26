// SPDX-License-Identifier: AGPL-3.0-or-later

// Package news fetches and parses curated incident feeds in pwn.watch's
// incidents.json shape. Everything in a feed is untrusted input: items are
// validated strictly (types, lengths, https-only links, a known category
// set) and anything malformed is dropped and counted, never stored.
package news

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/realmwatch/heimdall/internal/netx"
)

// MaxBytes caps a download. pwn.watch's full list is about 1 MB.
const MaxBytes = 8 << 20

// Timeout bounds one fetch.
const Timeout = 60 * time.Second

// maxItems caps how many incidents one feed may hold.
const maxItems = 5000

// Limits for individual fields (in characters).
const (
	maxSlug    = 128
	maxTitle   = 300
	maxURL     = 2048
	maxProduct = 200
	maxSummary = 4000
	maxWord    = 64  // one stack or tag
	maxLine    = 500 // one affected/fixed version line
	maxList    = 32  // entries in stacks, tags, versions
	maxCVEs    = 100
)

// Categories are the incident kinds Heimdall understands.
var Categories = []string{"patch", "breach", "supply-chain"}

var (
	severities   = []string{"critical", "high", "medium", "low", "unknown"}
	statuses     = []string{"live", "closed"}
	patchStatus  = []string{"", "patched", "partial", "unpatched", "no-fix-needed"}
	slugRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	wordRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9.+_-]*$`)
	cveRe        = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	errEmptyFeed = errors.New("feed has no valid incidents; keeping the stored copy")
)

// Item is one validated incident.
type Item struct {
	Slug        string
	Title       string
	URL         string
	Category    string
	Status      string // live or closed
	Severity    string
	PatchStatus string // "" when the feed doesn't say
	Product     string
	Stacks      []string
	Tags        []string
	CVEs        []string // only well-formed CVE IDs
	Affected    []string // free text, shown, never used for matching
	Fixed       []string
	Summary     string
	StartedAt   time.Time
	UpdatedAt   time.Time
	ClosedAt    *time.Time
}

// Feed is a parsed feed.
type Feed struct {
	Items      []Item
	Dropped    int // malformed or duplicate incidents
	IgnoredIDs int // entries in cveIds that aren't CVE IDs (e.g. GHSA-…, MAL-…)
}

type rawFeed struct {
	Incidents *[]json.RawMessage `json:"incidents"`
}

type rawItem struct {
	Slug             string   `json:"slug"`
	Title            string   `json:"title"`
	URL              string   `json:"url"`
	Category         string   `json:"category"`
	Status           string   `json:"status"`
	Severity         string   `json:"severity"`
	PatchStatus      string   `json:"patchStatus"`
	Product          string   `json:"product"`
	Stacks           []string `json:"stacks"`
	Tags             []string `json:"tags"`
	CVEIDs           []string `json:"cveIds"`
	AffectedVersions []string `json:"affectedVersions"`
	FixedVersions    []string `json:"fixedVersions"`
	Summary          string   `json:"summary"`
	StartedAt        string   `json:"startedAt"`
	UpdatedAt        string   `json:"updatedAt"`
	ClosedAt         *string  `json:"closedAt"`
	IsExample        bool     `json:"isExample"`
}

// Parse parses a feed. It fails if the document is structurally wrong or
// has no valid incidents, so a broken or empty feed never replaces a
// stored one; individual bad incidents are dropped and counted.
func Parse(raw []byte) (*Feed, error) {
	var rf rawFeed
	if err := json.Unmarshal(raw, &rf); err != nil {
		return nil, fmt.Errorf("news: not a feed: %w", err)
	}
	if rf.Incidents == nil {
		return nil, errors.New("news: no incidents array")
	}
	if len(*rf.Incidents) > maxItems {
		return nil, fmt.Errorf("news: %d incidents is more than the %d allowed", len(*rf.Incidents), maxItems)
	}
	f := &Feed{}
	seen := map[string]bool{}
	for _, msg := range *rf.Incidents {
		var ri rawItem
		if err := json.Unmarshal(msg, &ri); err != nil {
			f.Dropped++
			continue
		}
		if ri.IsExample {
			continue // a sample entry, not news
		}
		it, ignored, ok := validate(ri)
		if !ok || seen[it.Slug] {
			f.Dropped++
			continue
		}
		seen[it.Slug] = true
		f.IgnoredIDs += ignored
		f.Items = append(f.Items, it)
	}
	if len(f.Items) == 0 {
		return f, fmt.Errorf("news: %w (%d dropped)", errEmptyFeed, f.Dropped)
	}
	return f, nil
}

func validate(r rawItem) (Item, int, bool) {
	it := Item{
		Slug:        r.Slug,
		Category:    r.Category,
		Status:      r.Status,
		Severity:    r.Severity,
		PatchStatus: r.PatchStatus,
	}
	if it.Severity == "" {
		it.Severity = "unknown"
	}
	if len(it.Slug) > maxSlug || !slugRe.MatchString(it.Slug) ||
		!slices.Contains(Categories, it.Category) || !slices.Contains(statuses, it.Status) ||
		!slices.Contains(severities, it.Severity) || !slices.Contains(patchStatus, it.PatchStatus) {
		return it, 0, false
	}
	var ok bool
	if it.Title, ok = line(r.Title, maxTitle); !ok || it.Title == "" {
		return it, 0, false
	}
	if it.Product, ok = line(r.Product, maxProduct); !ok {
		return it, 0, false
	}
	if it.Summary, ok = text(r.Summary, maxSummary); !ok {
		return it, 0, false
	}
	if it.URL, ok = httpsURL(r.URL); !ok {
		return it, 0, false
	}
	if it.Stacks, ok = words(r.Stacks); !ok {
		return it, 0, false
	}
	if it.Tags, ok = words(r.Tags); !ok {
		return it, 0, false
	}
	if it.Affected, ok = lines(r.AffectedVersions); !ok {
		return it, 0, false
	}
	if it.Fixed, ok = lines(r.FixedVersions); !ok {
		return it, 0, false
	}
	if len(r.CVEIDs) > maxCVEs {
		return it, 0, false
	}
	ignored := 0
	for _, id := range r.CVEIDs {
		// Other IDs (GHSA-…, MAL-…) aren't matched in phase 1.
		if !cveRe.MatchString(id) || len(id) > 32 {
			ignored++
			continue
		}
		if !slices.Contains(it.CVEs, id) {
			it.CVEs = append(it.CVEs, id)
		}
	}
	if it.StartedAt, ok = parseTime(r.StartedAt); !ok {
		return it, 0, false
	}
	if it.UpdatedAt, ok = parseTime(r.UpdatedAt); !ok {
		return it, 0, false
	}
	if r.ClosedAt != nil && *r.ClosedAt != "" {
		t, ok := parseTime(*r.ClosedAt)
		if !ok {
			return it, 0, false
		}
		it.ClosedAt = &t
	}
	return it, ignored, true
}

// line is single-line text: trimmed, no control characters, capped.
func line(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max || strings.ContainsFunc(s, unicode.IsControl) {
		return "", false
	}
	return s, true
}

// text allows newlines and tabs but no other control characters.
func text(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	bad := func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max || strings.ContainsFunc(s, bad) {
		return "", false
	}
	return s, true
}

func words(in []string) ([]string, bool) {
	if len(in) > maxList {
		return nil, false
	}
	out := []string{}
	for _, w := range in {
		w = strings.ToLower(strings.TrimSpace(w))
		if len(w) > maxWord || !wordRe.MatchString(w) {
			return nil, false
		}
		if !slices.Contains(out, w) {
			out = append(out, w)
		}
	}
	return out, true
}

func lines(in []string) ([]string, bool) {
	if len(in) > maxList {
		return nil, false
	}
	out := []string{}
	for _, l := range in {
		l, ok := line(l, maxLine)
		if !ok {
			return nil, false
		}
		if l != "" {
			out = append(out, l)
		}
	}
	return out, true
}

func httpsURL(s string) (string, bool) {
	if len(s) > maxURL || strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
		return "", false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	return u.String(), true
}

// parseTime accepts a plain date ("2026-10-23", kept as midnight UTC) or
// an RFC 3339 timestamp, within a sane range.
func parseTime(s string) (time.Time, bool) {
	var t time.Time
	var err error
	if len(s) == len(time.DateOnly) {
		t, err = time.Parse(time.DateOnly, s)
	} else {
		t, err = time.Parse(time.RFC3339Nano, s)
	}
	if err != nil || t.Year() < 1990 || t.Year() > 2200 {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// Validators is what conditional requests need to remember per source.
type Validators struct{ ETag, LastModified string }

// Fetch downloads one feed. It sends the stored validators; on 304 Not
// Modified it returns a nil feed and the same validators. url must be
// https and its host on c's allowlist.
func Fetch(ctx context.Context, c *netx.Client, url string, prev Validators) (*Feed, Validators, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	h := http.Header{}
	if prev.ETag != "" {
		h.Set("If-None-Match", prev.ETag)
	}
	if prev.LastModified != "" {
		h.Set("If-Modified-Since", prev.LastModified)
	}
	raw, hdr, err := c.Get(ctx, url, MaxBytes, h)
	if err != nil {
		return nil, prev, fmt.Errorf("news: %w", err)
	}
	if raw == nil { // 304
		return nil, prev, nil
	}
	f, err := Parse(raw)
	if err != nil {
		return nil, prev, err
	}
	next := Validators{ETag: header(hdr, "ETag"), LastModified: header(hdr, "Last-Modified")}
	return f, next, nil
}

// header returns a short, printable response header value (or "").
func header(h http.Header, name string) string {
	v := h.Get(name)
	if len(v) > 256 || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
		return ""
	}
	return v
}
