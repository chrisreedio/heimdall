// SPDX-License-Identifier: AGPL-3.0-or-later

// Package osv queries the OSV.dev API (https://google.github.io/osv.dev/api/)
// and parses its vulnerability records. Records are untrusted remote input:
// responses are size-capped, IDs are validated, and iteration is bounded.
package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/netx"
)

const DefaultBaseURL = "https://api.osv.dev"

const (
	maxBatch        = 1000     // OSV's limit on queries per querybatch request
	maxBatchBytes   = 32 << 20 // per querybatch response
	maxVulnBytes    = 4 << 20  // per vulnerability record
	maxPages        = 100      // per query, guards against a looping page token
	maxAffected     = 10000    // affected entries examined per record
	maxEventsPerRng = 1000
)

type Query struct{ Ecosystem, Name, Version string }

type VulnRef struct {
	ID       string
	Modified time.Time
}

type Client struct {
	HTTP    *netx.Client
	BaseURL string // DefaultBaseURL if empty
}

func (c *Client) base() string {
	if c.BaseURL == "" {
		return DefaultBaseURL
	}
	return strings.TrimRight(c.BaseURL, "/")
}

// Wire types for /v1/querybatch.
type batchQuery struct {
	Package   batchPackage `json:"package"`
	Version   string       `json:"version"`
	PageToken string       `json:"page_token,omitempty"`
}
type batchPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}
type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// QueryBatch runs POST /v1/querybatch. Chunks to <=1000 queries per
// request, follows each query's next_page_token until exhausted, and
// returns one []VulnRef per input query (same order).
func (c *Client) QueryBatch(ctx context.Context, qs []Query) ([][]VulnRef, error) {
	out := make([][]VulnRef, len(qs))
	type pending struct {
		idx   int    // index into qs/out
		token string // page token, "" for the first page
	}
	todo := make([]pending, len(qs))
	for i := range qs {
		todo[i] = pending{idx: i}
	}
	pages := make([]int, len(qs))

	for len(todo) > 0 {
		chunk := todo[:min(maxBatch, len(todo))]
		todo = todo[len(chunk):]

		req := struct {
			Queries []batchQuery `json:"queries"`
		}{Queries: make([]batchQuery, len(chunk))}
		for i, p := range chunk {
			q := qs[p.idx]
			req.Queries[i] = batchQuery{
				Package:   batchPackage{Ecosystem: q.Ecosystem, Name: q.Name},
				Version:   q.Version,
				PageToken: p.token,
			}
		}
		var resp batchResponse
		if err := c.HTTP.PostJSON(ctx, c.base()+"/v1/querybatch", req, maxBatchBytes, &resp); err != nil {
			return nil, fmt.Errorf("osv querybatch: %w", err)
		}
		if len(resp.Results) != len(chunk) {
			return nil, fmt.Errorf("osv querybatch: got %d results for %d queries", len(resp.Results), len(chunk))
		}
		for i, r := range resp.Results {
			p := chunk[i]
			for _, v := range r.Vulns {
				if !idRe.MatchString(v.ID) {
					return nil, fmt.Errorf("osv querybatch: invalid vulnerability id %q", truncate(v.ID))
				}
				out[p.idx] = append(out[p.idx], VulnRef{ID: v.ID, Modified: parseTime(v.Modified)})
			}
			if r.NextPageToken != "" {
				pages[p.idx]++
				if pages[p.idx] > maxPages {
					return nil, fmt.Errorf("osv querybatch: more than %d pages for %s/%s", maxPages, qs[p.idx].Ecosystem, qs[p.idx].Name)
				}
				todo = append(todo, pending{idx: p.idx, token: r.NextPageToken})
			}
		}
	}
	return out, nil
}

// idRe is what an OSV ID may contain (e.g. "RLSA-2024:6783", "GHSA-xxxx-...").
var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Vuln fetches GET /v1/vulns/{id} and returns the parsed record and the
// raw JSON bytes (kept for storage).
func (c *Client) Vuln(ctx context.Context, id string) (*Vuln, []byte, error) {
	if !idRe.MatchString(id) {
		return nil, nil, fmt.Errorf("osv: invalid vulnerability id %q", truncate(id))
	}
	raw, _, err := c.HTTP.Get(ctx, c.base()+"/v1/vulns/"+url.PathEscape(id), maxVulnBytes, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("osv vuln %s: %w", id, err)
	}
	v, err := Parse(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("osv vuln %s: %w", id, err)
	}
	if v.ID != id {
		return nil, nil, fmt.Errorf("osv vuln %s: response is for %q", id, truncate(v.ID))
	}
	return v, raw, nil
}

type Vuln struct {
	ID, Summary, Details string
	Aliases              []string
	Upstream             []string // e.g. the CVE a DEBIAN-CVE-* record tracks
	Related              []string
	Modified, Published  time.Time
	Withdrawn            *time.Time
	Severity             []Severity
	Affected             []Affected
	DatabaseSpecific     json.RawMessage
}

// Severity is an OSV "severity" entry, e.g. {CVSS_V3, "CVSS:3.1/AV:N/..."}
// or Ubuntu's {Ubuntu, "low"}.
type Severity struct{ Type, Score string }

type Affected struct {
	Package struct{ Ecosystem, Name string }
	Ranges  []Range
	// Versions lists explicitly affected versions. Heimdall doesn't match
	// on them; OSV's querybatch does the matching.
	Versions          []string
	EcosystemSpecific json.RawMessage
	DatabaseSpecific  json.RawMessage
}

type Range struct {
	Type   string
	Events []Event
}

type Event struct{ Introduced, Fixed, LastAffected, Limit string }

// wire is the JSON shape of an OSV record; times stay strings so one odd
// timestamp can't fail the whole record.
type wire struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Upstream  []string `json:"upstream"`
	Related   []string `json:"related"`
	Modified  string   `json:"modified"`
	Published string   `json:"published"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
				Limit        string `json:"limit"`
			} `json:"events"`
		} `json:"ranges"`
		Versions          []string        `json:"versions"`
		EcosystemSpecific json.RawMessage `json:"ecosystem_specific"`
		DatabaseSpecific  json.RawMessage `json:"database_specific"`
	} `json:"affected"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

// Parse decodes a single OSV record (e.g. one stored earlier as raw JSON).
func Parse(raw []byte) (*Vuln, error) {
	if len(raw) > maxVulnBytes {
		return nil, fmt.Errorf("record larger than %d bytes", maxVulnBytes)
	}
	var w wire
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, err
	}
	if !idRe.MatchString(w.ID) {
		return nil, fmt.Errorf("invalid vulnerability id %q", truncate(w.ID))
	}
	if len(w.Affected) > maxAffected {
		return nil, fmt.Errorf("record has %d affected entries (max %d)", len(w.Affected), maxAffected)
	}
	v := &Vuln{
		ID: w.ID, Summary: w.Summary, Details: w.Details,
		Aliases: w.Aliases, Upstream: w.Upstream, Related: w.Related,
		Modified: parseTime(w.Modified), Published: parseTime(w.Published),
		DatabaseSpecific: w.DatabaseSpecific,
	}
	if w.Withdrawn != "" {
		t := parseTime(w.Withdrawn)
		v.Withdrawn = &t
	}
	for _, s := range w.Severity {
		v.Severity = append(v.Severity, Severity{Type: s.Type, Score: s.Score})
	}
	for _, a := range w.Affected {
		var af Affected
		af.Package.Ecosystem, af.Package.Name = a.Package.Ecosystem, a.Package.Name
		af.Versions = a.Versions
		af.EcosystemSpecific, af.DatabaseSpecific = a.EcosystemSpecific, a.DatabaseSpecific
		for _, r := range a.Ranges {
			if len(r.Events) > maxEventsPerRng {
				return nil, fmt.Errorf("range with %d events (max %d)", len(r.Events), maxEventsPerRng)
			}
			rng := Range{Type: r.Type}
			for _, e := range r.Events {
				rng.Events = append(rng.Events, Event{Introduced: e.Introduced, Fixed: e.Fixed, LastAffected: e.LastAffected, Limit: e.Limit})
			}
			af.Ranges = append(af.Ranges, rng)
		}
		v.Affected = append(v.Affected, af)
	}
	return v, nil
}

// parseTime accepts RFC 3339 with or without fractional seconds (Go's
// parser accepts any fraction length); unparseable times are zero.
func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func truncate(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

// EcosystemMatches reports whether a record's ecosystem (e.g.
// "Ubuntu:22.04:LTS") matches the one Heimdall queried with (e.g.
// "Ubuntu:22.04"): exact, or the record's ecosystem has the query as a
// prefix followed by ':'.
func EcosystemMatches(record, query string) bool {
	return record == query || (query != "" && strings.HasPrefix(record, query+":"))
}

// FixedVersions returns the "fixed" event versions for affected entries
// matching (ecosystem, package name), de-duplicated, in record order.
// Empty if none (unfixed).
func (v *Vuln) FixedVersions(ecosystem, name string) []string {
	var out []string
	for _, a := range v.Affected {
		if a.Package.Name != name || !EcosystemMatches(a.Package.Ecosystem, ecosystem) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && !slices.Contains(out, e.Fixed) {
					out = append(out, e.Fixed)
				}
			}
		}
	}
	return out
}

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// CVEs returns the CVE IDs among ID, Aliases, Upstream and Related,
// de-duplicated in that order. Debian, Ubuntu and Rocky records name their
// CVE in "upstream"; AlmaLinux uses "related".
func (v *Vuln) CVEs() []string {
	var out []string
	for _, list := range [][]string{{v.ID}, v.Aliases, v.Upstream, v.Related} {
		for _, id := range list {
			if cveRe.MatchString(id) && !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
	}
	return out
}

var ratingRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// normalizeRating maps the vocabularies used by distros and GHSA onto
// critical/high/medium/low; anything else (e.g. Debian's "not yet
// assigned") is "".
func normalizeRating(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low", "negligible", "unimportant":
		return "low"
	}
	return ""
}

func higher(a, b string) string {
	if ratingRank[b] > ratingRank[a] {
		return b
	}
	return a
}

// DistroRating returns the distro's own severity rating normalized to one
// of "critical", "high", "medium", "low", or "" if the record carries none.
// Where each source keeps it:
//   - Ubuntu (UBUNTU-CVE-*): a severity entry of type "Ubuntu" ("low", …)
//   - Debian (DEBIAN-CVE-*): affected[].ecosystem_specific.urgency
//   - Rocky (RLSA) and AlmaLinux (ALSA): the summary prefix, "Moderate: …"
//   - GHSA and others: top-level database_specific.severity ("MODERATE")
//   - Alpine records carry only CVSS vectors, so they return "".
//
// When several entries disagree (e.g. Debian urgency per release), the
// highest wins.
func (v *Vuln) DistroRating() string {
	best := ""
	for _, s := range v.Severity {
		if strings.EqualFold(s.Type, "Ubuntu") {
			best = higher(best, normalizeRating(s.Score))
		}
	}
	for i, a := range v.Affected {
		if i >= maxAffected {
			break
		}
		var es struct {
			Urgency string `json:"urgency"`
		}
		if len(a.EcosystemSpecific) > 0 && json.Unmarshal(a.EcosystemSpecific, &es) == nil {
			best = higher(best, normalizeRating(es.Urgency))
		}
	}
	if prefix, _, ok := strings.Cut(v.Summary, ":"); ok && len(prefix) <= 16 {
		best = higher(best, normalizeRating(prefix))
	}
	if len(v.DatabaseSpecific) > 0 {
		var ds struct {
			Severity json.RawMessage `json:"severity"`
		}
		if json.Unmarshal(v.DatabaseSpecific, &ds) == nil && len(ds.Severity) > 0 {
			var s string
			if json.Unmarshal(ds.Severity, &s) == nil { // ignore non-string shapes
				best = higher(best, normalizeRating(s))
			}
		}
	}
	return best
}
