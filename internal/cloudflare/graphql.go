// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// GraphQLError is the GraphQL Analytics API's errors for a query. Kind
// is "plan" (the zone's plan doesn't include the dataset), "permission"
// (the token can't read analytics) or "" (anything else).
type GraphQLError struct {
	Kind     string
	Messages []string
}

func (e *GraphQLError) Error() string {
	return "Cloudflare GraphQL: " + strings.Join(e.Messages, "; ")
}

// IsPlan reports whether err says the zone's plan lacks the dataset.
func IsPlan(err error) bool {
	var ge *GraphQLError
	return errors.As(err, &ge) && ge.Kind == "plan"
}

// classify reads an error message. Cloudflare answers HTTP 200 with
// "errors" for both; the wording is all there is to go on (e.g. "zone
// '…' does not have access to the path", "not authorized for that
// account"), so this errs towards "" (shown as an error, retried).
func classify(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "does not have access to the path"), strings.Contains(m, "not available"),
		strings.Contains(m, "upgrade"), strings.Contains(m, "plan"):
		return "plan"
	case strings.Contains(m, "not authorized"), strings.Contains(m, "authz"), strings.Contains(m, "permission"),
		strings.Contains(m, "authentication"), strings.Contains(m, "unauthorized"):
		return "permission"
	}
	return ""
}

// graphql runs a query (POST /graphql) and decodes "data" into out. Any
// listed error fails the query.
func (c *Client) graphql(ctx context.Context, query string, out any) error {
	body, _ := json.Marshal(map[string]any{"query": query, "variables": map[string]any{}})
	b, err := c.do(ctx, http.MethodPost, "/graphql", nil, body)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Permission() {
			return &GraphQLError{Kind: "permission", Messages: ae.Messages}
		}
		return err
	}
	var resp struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return fmt.Errorf("cloudflare GraphQL: %w", err)
	}
	if len(resp.Errors) > 0 {
		ge := &GraphQLError{}
		for _, e := range resp.Errors {
			ge.Messages = append(ge.Messages, clip(e.Message))
			if k := classify(e.Message); k != "" && ge.Kind == "" {
				ge.Kind = k
			}
		}
		return ge
	}
	if out != nil {
		return json.Unmarshal(resp.Data, out)
	}
	return nil
}

// Datasets are the GraphQL datasets Heimdall uses, in the order status
// shows them.
var Datasets = []string{"firewallEventsAdaptiveGroups", "firewallEventsAdaptive", "httpRequests1hGroups", "httpRequestsAdaptiveGroups"}

// Dataset is a dataset's availability for a zone, from the settings node
// (https://developers.cloudflare.com/analytics/graphql-api/features/discovery/settings/).
type Dataset struct {
	Enabled      bool  `json:"enabled"`
	MaxDuration  int64 `json:"maxDuration"`  // seconds a query may span
	NotOlderThan int64 `json:"notOlderThan"` // seconds back a query may reach
}

// DatasetSettings asks whether a zone can query a dataset. One query per
// dataset, so an unknown one fails alone.
func (c *Client) DatasetSettings(ctx context.Context, zoneID, dataset string) (Dataset, error) {
	if !zoneIDRe(zoneID) || !identRe(dataset) {
		return Dataset{}, fmt.Errorf("bad zone or dataset")
	}
	var out struct {
		Viewer struct {
			Zones []struct {
				Settings map[string]*Dataset `json:"settings"`
			} `json:"zones"`
		} `json:"viewer"`
	}
	q := `{ viewer { zones(filter: {zoneTag: "` + zoneID + `"}) { settings { ` + dataset +
		` { enabled maxDuration notOlderThan } } } } }`
	if err := c.graphql(ctx, q, &out); err != nil {
		return Dataset{}, err
	}
	if len(out.Viewer.Zones) == 0 || out.Viewer.Zones[0].Settings[dataset] == nil {
		return Dataset{}, nil
	}
	return *out.Viewer.Zones[0].Settings[dataset], nil
}

func identRe(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return s != ""
}
