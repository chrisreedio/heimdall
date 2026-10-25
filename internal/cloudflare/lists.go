// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
)

// The only writes Heimdall makes to Cloudflare, for bans (internal/bans),
// with a second token that has edit rights: an account-level IP list per
// action and, in each opted-in zone, one custom rule per list. The
// read-only token never calls these.
//
// API references (checked Oct 2026):
//   - accounts: https://developers.cloudflare.com/api/resources/accounts/methods/list/
//   - lists: https://developers.cloudflare.com/api/resources/rules/subresources/lists/
//     (Account > Account Filter Lists > Edit). Items are added and deleted
//     by asynchronous bulk operations, one pending per account.
//   - list items: https://developers.cloudflare.com/api/resources/rules/subresources/lists/subresources/items/
//   - bulk operations: https://developers.cloudflare.com/api/resources/rules/subresources/lists/subresources/bulk_operations/methods/get/
//   - phase entrypoint: https://developers.cloudflare.com/api/resources/rulesets/subresources/phases/methods/get/
//   - ruleset rules: https://developers.cloudflare.com/api/resources/rulesets/subresources/rules/ (Zone > Zone WAF > Edit)
//   - custom rules and lists: https://developers.cloudflare.com/waf/custom-rules/ and
//     https://developers.cloudflare.com/waf/tools/lists/custom-lists/

// call sends a request with an optional JSON body and decodes the result.
func (c *Client) call(ctx context.Context, method, path string, q url.Values, body, out any) (*resultInfo, error) {
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}
	raw, err := c.do(ctx, method, path, q, b)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("cloudflare API %s: %w", path, err)
	}
	if !env.Success {
		ae := &APIError{Status: http.StatusOK}
		for _, m := range env.Errors {
			ae.Codes, ae.Messages = append(ae.Codes, m.Code), append(ae.Messages, clip(m.Message))
		}
		return nil, ae
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return nil, fmt.Errorf("cloudflare API %s: %w", path, err)
		}
	}
	return env.Info, nil
}

// IsNotFound reports whether err is the API saying the thing doesn't exist.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// Account is an account the token can see.
type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Accounts lists the token's accounts (first page: a ban token is meant
// for one).
func (c *Client) Accounts(ctx context.Context) ([]Account, error) {
	var out []Account
	_, err := c.call(ctx, http.MethodGet, "/accounts", url.Values{"per_page": {"50"}}, nil, &out)
	return out, err
}

// IPList is an account-level list.
type IPList struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Kind        string `json:"kind"`
	NumItems    int    `json:"num_items"`
}

var listNameRe = regexp.MustCompile(`^[a-z0-9_]{1,50}$`)

func accountPath(accountID string) (string, error) {
	if !zoneIDRe(accountID) {
		return "", fmt.Errorf("bad account ID %q", accountID)
	}
	return "/accounts/" + accountID + "/rules/lists", nil
}

// opaqueID accepts the IDs the API hands back (lists, items, rules,
// rulesets and operations), which go into paths.
func opaqueID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Lists returns the account's lists.
func (c *Client) Lists(ctx context.Context, accountID string) ([]IPList, error) {
	p, err := accountPath(accountID)
	if err != nil {
		return nil, err
	}
	var out []IPList
	_, err = c.call(ctx, http.MethodGet, p, nil, nil, &out)
	return out, err
}

// CreateList makes an IP list.
func (c *Client) CreateList(ctx context.Context, accountID, name, description string) (IPList, error) {
	var l IPList
	p, err := accountPath(accountID)
	if err != nil {
		return l, err
	}
	if !listNameRe.MatchString(name) {
		return l, fmt.Errorf("bad list name %q", name)
	}
	_, err = c.call(ctx, http.MethodPost, p, nil, map[string]string{"name": name, "kind": "ip", "description": description}, &l)
	return l, err
}

// ListItem is an entry in an IP list.
type ListItem struct {
	ID      string `json:"id"`
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

// NewItem is an entry to add.
type NewItem struct {
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
}

// ListItems returns every item in a list, following the cursor.
func (c *Client) ListItems(ctx context.Context, accountID, listID string) ([]ListItem, error) {
	p, err := accountPath(accountID)
	if err != nil {
		return nil, err
	}
	if !opaqueID(listID) {
		return nil, fmt.Errorf("bad list ID %q", listID)
	}
	var out []ListItem
	cursor := ""
	for page := 0; page < maxPages; page++ {
		q := url.Values{"per_page": {"500"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		raw, err := c.do(ctx, http.MethodGet, p+"/"+listID+"/items", q, nil)
		if err != nil {
			return nil, err
		}
		var env struct {
			Success bool         `json:"success"`
			Errors  []apiMessage `json:"errors"`
			Result  []ListItem   `json:"result"`
			Info    struct {
				Cursors struct {
					After string `json:"after"`
				} `json:"cursors"`
			} `json:"result_info"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, fmt.Errorf("cloudflare API list items: %w", err)
		}
		if !env.Success {
			ae := &APIError{Status: http.StatusOK}
			for _, m := range env.Errors {
				ae.Codes, ae.Messages = append(ae.Codes, m.Code), append(ae.Messages, clip(m.Message))
			}
			return nil, ae
		}
		out = append(out, env.Result...)
		if env.Info.Cursors.After == "" || len(env.Result) == 0 {
			return out, nil
		}
		cursor = env.Info.Cursors.After
	}
	return nil, errors.New("cloudflare API list items: too many pages")
}

// AddItems starts a bulk operation adding items; it returns its ID.
func (c *Client) AddItems(ctx context.Context, accountID, listID string, items []NewItem) (string, error) {
	p, err := accountPath(accountID)
	if err != nil {
		return "", err
	}
	if !opaqueID(listID) {
		return "", fmt.Errorf("bad list ID %q", listID)
	}
	var op struct {
		OperationID string `json:"operation_id"`
	}
	_, err = c.call(ctx, http.MethodPost, p+"/"+listID+"/items", nil, items, &op)
	return op.OperationID, err
}

// DeleteItems starts a bulk operation deleting items by ID.
func (c *Client) DeleteItems(ctx context.Context, accountID, listID string, ids []string) (string, error) {
	p, err := accountPath(accountID)
	if err != nil {
		return "", err
	}
	if !opaqueID(listID) {
		return "", fmt.Errorf("bad list ID %q", listID)
	}
	type item struct {
		ID string `json:"id"`
	}
	body := struct {
		Items []item `json:"items"`
	}{}
	for _, id := range ids {
		if !opaqueID(id) {
			return "", fmt.Errorf("bad item ID %q", id)
		}
		body.Items = append(body.Items, item{ID: id})
	}
	var op struct {
		OperationID string `json:"operation_id"`
	}
	_, err = c.call(ctx, http.MethodDelete, p+"/"+listID+"/items", nil, body, &op)
	return op.OperationID, err
}

// Operation is a bulk operation's state: pending, running, completed or
// failed.
type Operation struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

// Operation reads a bulk operation's state.
func (c *Client) Operation(ctx context.Context, accountID, opID string) (Operation, error) {
	var op Operation
	p, err := accountPath(accountID)
	if err != nil {
		return op, err
	}
	if !opaqueID(opID) {
		return op, fmt.Errorf("bad operation ID %q", opID)
	}
	_, err = c.call(ctx, http.MethodGet, p+"/bulk_operations/"+opID, nil, nil, &op)
	return op, err
}

// ── Custom rules ───────────────────────────────────────────────────────────

// CustomPhase is the phase custom rules run in.
const CustomPhase = "http_request_firewall_custom"

// Rule is a rule in a ruleset.
type Rule struct {
	ID          string `json:"id,omitempty"`
	Ref         string `json:"ref,omitempty"`
	Description string `json:"description,omitempty"`
	Expression  string `json:"expression"`
	Action      string `json:"action"`
	Enabled     bool   `json:"enabled"`
}

// Ruleset is a zone's phase entrypoint.
type Ruleset struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Phase string `json:"phase"`
	Rules []Rule `json:"rules"`
}

// CustomEntrypoint reads the zone's custom rules ruleset; found is false
// when the zone has none yet.
func (c *Client) CustomEntrypoint(ctx context.Context, zoneID string) (rs Ruleset, found bool, err error) {
	if !zoneIDRe(zoneID) {
		return rs, false, fmt.Errorf("bad zone ID %q", zoneID)
	}
	_, err = c.call(ctx, http.MethodGet, "/zones/"+zoneID+"/rulesets/phases/"+CustomPhase+"/entrypoint", nil, nil, &rs)
	if IsNotFound(err) {
		return rs, false, nil
	}
	return rs, err == nil, err
}

// CreateCustomEntrypoint creates the zone's custom rules ruleset with
// rules. It fails if the zone already has one, so nothing is overwritten.
func (c *Client) CreateCustomEntrypoint(ctx context.Context, zoneID string, rules []Rule) (Ruleset, error) {
	var rs Ruleset
	if !zoneIDRe(zoneID) {
		return rs, fmt.Errorf("bad zone ID %q", zoneID)
	}
	body := map[string]any{"name": "default", "kind": "zone", "phase": CustomPhase, "rules": rules}
	_, err := c.call(ctx, http.MethodPost, "/zones/"+zoneID+"/rulesets", nil, body, &rs)
	return rs, err
}

// AddRule appends a rule to a zone ruleset; the answer is the ruleset.
func (c *Client) AddRule(ctx context.Context, zoneID, rulesetID string, r Rule) (Ruleset, error) {
	var rs Ruleset
	if !zoneIDRe(zoneID) || !opaqueID(rulesetID) {
		return rs, fmt.Errorf("bad zone or ruleset ID")
	}
	_, err := c.call(ctx, http.MethodPost, "/zones/"+zoneID+"/rulesets/"+rulesetID+"/rules", nil, r, &rs)
	return rs, err
}

// UpdateRule replaces one rule's fields (PATCH).
func (c *Client) UpdateRule(ctx context.Context, zoneID, rulesetID string, r Rule) (Ruleset, error) {
	var rs Ruleset
	if !zoneIDRe(zoneID) || !opaqueID(rulesetID) || !opaqueID(r.ID) {
		return rs, fmt.Errorf("bad zone, ruleset or rule ID")
	}
	id := r.ID
	r.ID = ""
	_, err := c.call(ctx, http.MethodPatch, "/zones/"+zoneID+"/rulesets/"+rulesetID+"/rules/"+id, nil, r, &rs)
	return rs, err
}

// DeleteRule removes one rule.
func (c *Client) DeleteRule(ctx context.Context, zoneID, rulesetID, ruleID string) error {
	if !zoneIDRe(zoneID) || !opaqueID(rulesetID) || !opaqueID(ruleID) {
		return fmt.Errorf("bad zone, ruleset or rule ID")
	}
	_, err := c.call(ctx, http.MethodDelete, "/zones/"+zoneID+"/rulesets/"+rulesetID+"/rules/"+ruleID, nil, nil, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}
