// SPDX-License-Identifier: AGPL-3.0-or-later

// Package eol reads end-of-life data from endoflife.date and maps OS
// releases and runtimes to its products and release cycles.
//
// It uses the v1 API (GET /api/v1/products/{product}) rather than the
// legacy /api/{product}.json: v1 carries a schema_version, and states
// end-of-life explicitly as isEol plus an eolFrom date, where the legacy
// "eol" field is either a date or a bare boolean.
package eol

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/netx"
)

const DefaultBaseURL = "https://endoflife.date"

// maxResponse caps one product's data; real products are well under 100 KB.
const maxResponse = 4 << 20

type Cycle struct {
	Product, Cycle string // e.g. "ubuntu", "22.04"
	ReleaseDate    *time.Time
	SupportUntil   *time.Time // active support end, if published
	EOL            *time.Time // security support end; nil if none announced
	EOLReached     bool       // true when the feed says EOL without a date
	Latest         string
}

type Client struct {
	HTTP    *netx.Client
	BaseURL string // DefaultBaseURL if empty
}

var (
	productRe = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
	cycleRe   = regexp.MustCompile(`^[0-9A-Za-z._-]{1,32}$`)
	latestRe  = regexp.MustCompile(`^[0-9A-Za-z._+~-]{1,64}$`)
)

// v1 API response, only the fields used.
type productResponse struct {
	Result struct {
		Name     string `json:"name"`
		Releases []struct {
			Name        string  `json:"name"`
			ReleaseDate *string `json:"releaseDate"`
			EOASFrom    *string `json:"eoasFrom"`
			IsEOL       *bool   `json:"isEol"`
			EOLFrom     *string `json:"eolFrom"`
			Latest      *struct {
				Name string `json:"name"`
			} `json:"latest"`
		} `json:"releases"`
	} `json:"result"`
}

// Product fetches all cycles of a product. Malformed cycles are skipped; a
// product with no valid cycles is an error.
func (c *Client) Product(ctx context.Context, product string) ([]Cycle, error) {
	if !productRe.MatchString(product) {
		return nil, fmt.Errorf("eol: invalid product %q", product)
	}
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	var resp productResponse
	if err := c.HTTP.GetJSON(ctx, strings.TrimRight(base, "/")+"/api/v1/products/"+product, maxResponse, &resp); err != nil {
		return nil, fmt.Errorf("eol: %s: %w", product, err)
	}

	var cycles []Cycle
	for _, r := range resp.Result.Releases {
		if !cycleRe.MatchString(r.Name) {
			continue
		}
		cy := Cycle{Product: product, Cycle: r.Name}
		var bad bool
		parse := func(s *string) *time.Time {
			if s == nil || *s == "" {
				return nil
			}
			t, err := time.Parse(time.DateOnly, *s)
			if err != nil {
				bad = true
				return nil
			}
			return &t
		}
		cy.ReleaseDate = parse(r.ReleaseDate)
		cy.SupportUntil = parse(r.EOASFrom)
		cy.EOL = parse(r.EOLFrom)
		if bad {
			continue
		}
		cy.EOLReached = cy.EOL == nil && r.IsEOL != nil && *r.IsEOL
		if r.Latest != nil && latestRe.MatchString(r.Latest.Name) {
			cy.Latest = r.Latest.Name
		}
		cycles = append(cycles, cy)
	}
	if len(cycles) == 0 {
		return nil, fmt.Errorf("eol: %s: no valid release cycles in response", product)
	}
	return cycles, nil
}

// Product slugs on endoflife.date.
const (
	ProductUbuntu  = "ubuntu"
	ProductDebian  = "debian"
	ProductRocky   = "rocky-linux"
	ProductAlma    = "almalinux"
	ProductAlpine  = "alpine-linux"
	ProductRHEL    = "rhel"
	ProductPHP     = "php"
	ProductNodeJS  = "nodejs"
	ProductPython  = "python"
	ProductLaravel = "laravel"
)

// osProducts maps os-release IDs to products and how many version
// components make up a cycle.
var osProducts = map[string]struct {
	product string
	parts   int
}{
	"ubuntu":    {ProductUbuntu, 2}, // 22.04
	"debian":    {ProductDebian, 1}, // 12
	"rocky":     {ProductRocky, 1},  // 9
	"almalinux": {ProductAlma, 1},   // 9
	"alpine":    {ProductAlpine, 2}, // 3.20
	"rhel":      {ProductRHEL, 1},   // 9
}

// OSCycle maps os-release ID/VERSION_ID to an endoflife.date product and
// cycle, falling back to ID_LIKE entries for derivatives.
func OSCycle(osID, versionID, idLike string) (product, cycle string, ok bool) {
	if osID == "windows" {
		return windowsCycle(versionID, idLike)
	}
	ids := append([]string{osID}, strings.Fields(idLike)...)
	for _, id := range ids {
		p, found := osProducts[id]
		if !found {
			continue
		}
		c, valid := leadingParts(versionID, p.parts)
		if !valid {
			return "", "", false
		}
		return p.product, c, true
	}
	return "", "", false
}

// windowsServerBuilds maps kernel build numbers to Windows Server LTSC
// cycles on endoflife.date (version_id is e.g. "10.0.20348").
var windowsServerBuilds = map[string]string{
	"9200": "2012", "9600": "2012-r2", "14393": "2016", "17763": "2019", "20348": "2022", "26100": "2025",
}

// ProductWindowsServer is endoflife.date's Windows Server product.
const ProductWindowsServer = "windows-server"

// windowsCycle maps Windows Server LTSC builds. Desktop Windows editions
// have per-edition cycles that the collector can't tell apart yet.
func windowsCycle(versionID, idLike string) (string, string, bool) {
	if !strings.Contains(" "+idLike+" ", " windows-server ") {
		return "", "", false
	}
	parts := strings.Split(versionID, ".")
	if len(parts) < 3 {
		return "", "", false
	}
	c, ok := windowsServerBuilds[parts[2]]
	return ProductWindowsServer, c, ok
}

// runtimeParts is how many version components make up a runtime's cycle.
var runtimeParts = map[string]int{
	ProductPHP:     2, // 8.3
	ProductNodeJS:  1, // 20
	ProductPython:  2, // 3.12
	ProductLaravel: 1, // 11
}

// RuntimeCycle maps a runtime product and full version to its cycle.
func RuntimeCycle(product, version string) (string, bool) {
	n, ok := runtimeParts[product]
	if !ok {
		return "", false
	}
	return leadingParts(strings.TrimPrefix(version, "v"), n)
}

// leadingParts returns the first n numeric dot-separated components of v.
func leadingParts(v string, n int) (string, bool) {
	parts := strings.SplitN(v, ".", n+1)
	if len(parts) < n {
		return "", false
	}
	for _, p := range parts[:n] {
		if p == "" || len(p) > 8 || strings.Trim(p, "0123456789") != "" {
			return "", false
		}
	}
	return strings.Join(parts[:n], "."), true
}

type Status struct {
	Known    bool       // cycle found in data
	EOL      bool       // security support has ended as of now
	EOLDate  *time.Time // nil if none announced
	DaysLeft int        // days until EOL (negative if past); 0 if no date
}

// Evaluate finds the cycle in cycles and reports its status at now.
func Evaluate(cycles []Cycle, cycle string, now time.Time) Status {
	for _, c := range cycles {
		if c.Cycle != cycle {
			continue
		}
		s := Status{Known: true, EOLDate: c.EOL}
		switch {
		case c.EOL != nil:
			// EOL dates are whole days; support ends at the start of that day (UTC).
			s.EOL = !now.Before(*c.EOL)
			s.DaysLeft = int(math.Floor(c.EOL.Sub(now).Hours() / 24))
		case c.EOLReached:
			s.EOL = true
		}
		return s
	}
	return Status{}
}
