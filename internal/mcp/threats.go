// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/threats"
)

// The threat list's REST API (docs/threats.md): attacker addresses and
// networks for firewalls, fail2ban and other services to pull. It lives on
// the MCP listener because that's the hub's machine-facing, bearer-token
// endpoint (tailnet only); the UI listener is for people with sessions.
// It takes threat-list tokens only: an MCP token gets 403 here, and a
// threat-list token gets 403 on /mcp.

const (
	ThreatsPath        = "/api/v1/threats"
	ThreatNetworksPath = ThreatsPath + "/networks"
)

// maxQuery bounds the query string (a GET has no body to limit).
const maxQuery = 2048

func (s *Server) serveThreats(w http.ResponseWriter, r *http.Request, c caller) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(r.URL.RawQuery) > maxQuery || r.ContentLength > 0 {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	qv := r.URL.Query()
	format, err := threats.ParseFormat(qv.Get("format"))
	if err == nil {
		var q threats.Query
		if q, err = threats.Parse(qv.Get, threats.RESTLimits); err == nil {
			q.Scope = c.scope
			var buf bytes.Buffer
			if r.URL.Path == ThreatNetworksPath {
				var res threats.NetworkResult
				if res, err = s.threats.Networks(r.Context(), q); err == nil {
					err = threats.WriteNetworks(&buf, format, res)
				}
			} else {
				var res threats.Result
				if res, err = s.threats.Addresses(r.Context(), q); err == nil {
					err = threats.WriteAddresses(&buf, format, res)
				}
			}
			if err == nil {
				w.Header().Set("Content-Type", threats.ContentType(format))
				w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
				if r.Method != http.MethodHead {
					w.Write(buf.Bytes())
				}
				return
			}
		}
	}
	var ve *store.ValidationError
	switch {
	case errors.As(err, &ve):
		http.Error(w, ve.Error(), http.StatusBadRequest)
	case errors.Is(err, threats.ErrForbidden):
		http.Error(w, "not allowed: that org isn't in your scope", http.StatusForbidden)
	default:
		s.log.Error("threat list failed", "err", err)
		http.Error(w, "internal error; see the hub log", http.StatusInternalServerError)
	}
}

// threatArgs reads a tool's arguments as the REST parameters.
func threatArgs(a map[string]any) func(string) string {
	return func(k string) string {
		switch v := a[k].(type) {
		case string:
			return v
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
		return ""
	}
}

func (s *Server) registerThreatTools() {
	filters := map[string]any{
		"since":     str("How far back: a duration like 24h or 7d (default 7d, at most 30d)"),
		"org":       str("Only failures on this org's hosts (and its zones); default every org you can see"),
		"min_score": map[string]any{"type": "number", "description": "Lowest ban score to include (default 0)"},
		"min_hosts": map[string]any{"type": "integer", "description": "Fewest SSH hosts an address failed on (default 0)"},
		"source":    map[string]any{"type": "string", "enum": []string{"all", "ssh", "web"}, "description": "Which sensor saw it (default all)"},
		"limit":     map[string]any{"type": "integer", "description": "At most this many rows (default 25, at most 100)"},
	}
	netFilters := map[string]any{
		"kind":          map[string]any{"type": "string", "enum": []string{"all", "prefix", "asn"}, "description": "/24 and /48 prefixes, ASNs, or both (default)"},
		"min_addresses": map[string]any{"type": "integer", "description": "Fewest listed addresses a network needs (default 1)"},
	}
	for k, v := range filters {
		netFilters[k] = v
	}
	parse := func(a map[string]any, c caller) (threats.Query, error) {
		q, err := threats.Parse(threatArgs(a), threats.MCPLimits)
		if err != nil {
			return q, err
		}
		q.Scope = c.scope
		return q, nil
	}
	s.add("threats", tool{
		description: "Attacker addresses seen across your hosts (failed SSH logins; Cloudflare web events once wired): " +
			"hosts hit, failures, distinct-username counts, days, network, ban score (as on /bans) and ban status. " +
			"Addresses IP awareness knows in any org are never listed. Listing never bans anything.",
		schema: obj(filters),
		run: func(ctx context.Context, c caller, a map[string]any) (any, error) {
			q, err := parse(a, c)
			if err != nil {
				return nil, err
			}
			res, err := s.threats.Addresses(ctx, q)
			return res, threatErr(err)
		},
	})
	s.add("threat_networks", tool{
		description: "The threat list rolled up by network: each /24 (IPv4) or /48 (IPv6) and each ASN, with " +
			"addresses, failures, web events, hosts hit and the top addresses.",
		schema: obj(netFilters),
		run: func(ctx context.Context, c caller, a map[string]any) (any, error) {
			q, err := parse(a, c)
			if err != nil {
				return nil, err
			}
			res, err := s.threats.Networks(ctx, q)
			return res, threatErr(err)
		},
	})
}

func threatErr(err error) error {
	if errors.Is(err, threats.ErrForbidden) {
		return fmt.Errorf("%w: that org isn't in your scope", errUser)
	}
	return err
}
