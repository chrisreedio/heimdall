// SPDX-License-Identifier: AGPL-3.0-or-later

// Package kev fetches and parses CISA's Known Exploited Vulnerabilities
// catalog. The feed is treated as untrusted input: malformed entries are
// skipped and text is cleaned and length-capped.
package kev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/realmwatch/heimdall/internal/netx"
)

const DefaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// maxBytes caps the download; the real catalog is a few MB.
const maxBytes = 32 << 20

const maxText = 200

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)

type Entry struct {
	CVE             string // "CVE-2024-12345"
	Vendor, Product string
	Name            string    // vulnerabilityName
	DateAdded       time.Time // date only (UTC)
	DueDate         *time.Time
	KnownRansomware bool // knownRansomwareCampaignUse == "Known"
}

type Catalog struct {
	Version  string    // catalogVersion
	Released time.Time // dateReleased
	Entries  []Entry
	Skipped  int // entries dropped as invalid or duplicate
}

// Fetch downloads and parses the catalog via c. url = DefaultURL if empty.
func Fetch(ctx context.Context, c *netx.Client, url string) (*Catalog, error) {
	if url == "" {
		url = DefaultURL
	}
	raw, _, err := c.Get(ctx, url, maxBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	return Parse(raw)
}

type rawCatalog struct {
	CatalogVersion  string             `json:"catalogVersion"`
	DateReleased    string             `json:"dateReleased"`
	Vulnerabilities *[]json.RawMessage `json:"vulnerabilities"`
}

type rawEntry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	DueDate           string `json:"dueDate"`
	KnownRansomware   string `json:"knownRansomwareCampaignUse"`
}

// Parse parses catalog JSON. Individual bad entries are skipped and
// counted; the catalog fails only if it is structurally wrong or has no
// valid entries.
func Parse(raw []byte) (*Catalog, error) {
	var rc rawCatalog
	if err := json.Unmarshal(raw, &rc); err != nil {
		return nil, fmt.Errorf("kev: decode catalog: %w", err)
	}
	if rc.Vulnerabilities == nil {
		return nil, errors.New("kev: catalog has no vulnerabilities list")
	}

	cat := &Catalog{Version: clean(rc.CatalogVersion, 64)}
	if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(rc.DateReleased)); err == nil {
		cat.Released = t.UTC()
	} else if t, err := parseDate(rc.DateReleased); err == nil {
		cat.Released = t
	}

	seen := make(map[string]bool, len(*rc.Vulnerabilities))
	for _, item := range *rc.Vulnerabilities {
		var re rawEntry
		if err := json.Unmarshal(item, &re); err != nil {
			cat.Skipped++
			continue
		}
		cve := strings.TrimSpace(re.CVEID)
		added, err := parseDate(re.DateAdded)
		if !cveRe.MatchString(cve) || err != nil || seen[cve] {
			cat.Skipped++
			continue
		}
		seen[cve] = true
		e := Entry{
			CVE:             cve,
			Vendor:          clean(re.VendorProject, maxText),
			Product:         clean(re.Product, maxText),
			Name:            clean(re.VulnerabilityName, maxText),
			DateAdded:       added,
			KnownRansomware: strings.EqualFold(strings.TrimSpace(re.KnownRansomware), "Known"),
		}
		if due, err := parseDate(re.DueDate); err == nil {
			e.DueDate = &due
		}
		cat.Entries = append(cat.Entries, e)
	}
	if len(cat.Entries) == 0 {
		return nil, fmt.Errorf("kev: catalog has no valid entries (%d skipped)", cat.Skipped)
	}
	return cat, nil
}

func parseDate(s string) (time.Time, error) {
	return time.Parse(time.DateOnly, strings.TrimSpace(s))
}

// clean drops control characters and invalid UTF-8, trims, and caps length.
func clean(s string, max int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max])
	}
	return s
}
