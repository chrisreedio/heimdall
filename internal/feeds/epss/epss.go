// SPDX-License-Identifier: AGPL-3.0-or-later

// Package epss fetches FIRST EPSS scores: the estimated probability that a
// CVE is exploited in the next 30 days, used to rank findings.
package epss

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/netx"
)

const DefaultBaseURL = "https://api.first.org"

const (
	// BatchSize matches the API's default page size (100), so one request
	// returns a whole batch, and keeps the URL around 1.7 KB.
	BatchSize   = 100
	maxBatches  = 200
	maxResponse = 4 << 20
	maxPages    = 5 // per batch; only needed if the API ever pages a batch
)

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)

type Score struct {
	CVE              string
	EPSS, Percentile float64
	Date             time.Time
}

type Client struct {
	HTTP    *netx.Client
	BaseURL string // DefaultBaseURL if empty
}

type response struct {
	Total  int `json:"total"`
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
	Data   []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

// Scores fetches scores for the given CVEs (deduplicated; invalid IDs are
// skipped), batching requests. CVEs without a score are absent from the result.
func (c *Client) Scores(ctx context.Context, cves []string) (map[string]Score, error) {
	seen := map[string]bool{}
	var ids []string
	for _, id := range cves {
		id = strings.ToUpper(strings.TrimSpace(id))
		if cveRe.MatchString(id) && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	out := make(map[string]Score, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	if (len(ids)+BatchSize-1)/BatchSize > maxBatches {
		return nil, fmt.Errorf("epss: %d CVEs needs more than %d requests", len(ids), maxBatches)
	}
	for start := 0; start < len(ids); start += BatchSize {
		batch := ids[start:min(start+BatchSize, len(ids))]
		if err := c.fetch(ctx, batch, seen, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (c *Client) fetch(ctx context.Context, batch []string, wanted map[string]bool, out map[string]Score) error {
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	offset := 0
	for page := 0; page < maxPages; page++ {
		q := url.Values{}
		q.Set("cve", strings.Join(batch, ","))
		q.Set("limit", strconv.Itoa(BatchSize))
		if offset > 0 {
			q.Set("offset", strconv.Itoa(offset))
		}
		raw, _, err := c.HTTP.Get(ctx, strings.TrimSuffix(base, "/")+"/data/v1/epss?"+q.Encode(), maxResponse, nil)
		if err != nil {
			return fmt.Errorf("epss: %w", err)
		}
		var resp response
		if err := json.Unmarshal(raw, &resp); err != nil {
			return fmt.Errorf("epss: decode: %w", err)
		}
		for _, row := range resp.Data {
			s, ok := parseRow(row.CVE, row.EPSS, row.Percentile, row.Date)
			if ok && wanted[s.CVE] {
				out[s.CVE] = s
			}
		}
		offset += len(resp.Data)
		if len(resp.Data) == 0 || offset >= resp.Total || offset >= len(batch) {
			return nil
		}
	}
	return errors.New("epss: too many pages for one batch")
}

func parseRow(cve, epss, pct, date string) (Score, bool) {
	cve = strings.ToUpper(strings.TrimSpace(cve))
	if !cveRe.MatchString(cve) {
		return Score{}, false
	}
	e, err1 := strconv.ParseFloat(epss, 64)
	p, err2 := strconv.ParseFloat(pct, 64)
	if err1 != nil || err2 != nil || !(e >= 0 && e <= 1) || !(p >= 0 && p <= 1) {
		return Score{}, false
	}
	d, err := time.Parse(time.DateOnly, date)
	if err != nil {
		return Score{}, false
	}
	return Score{CVE: cve, EPSS: e, Percentile: p, Date: d}, true
}
