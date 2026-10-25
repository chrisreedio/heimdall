// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

// Zone settings and edge certificates for the surface map, both optional:
// a token without the permission gets a "permission" state, not a failed
// sync.
//
// API references (checked Oct 2026):
//   - zone setting: https://developers.cloudflare.com/api/resources/zones/subresources/settings/methods/get/ (Zone Settings Read)
//   - certificate packs: https://developers.cloudflare.com/api/resources/ssl/subresources/certificate_packs/methods/list/ (SSL and Certificates Read)

// SettingNames are the zone settings read: SSL/TLS encryption mode,
// Always Use HTTPS and the minimum TLS version.
var SettingNames = []string{"ssl", "always_use_https", "min_tls_version"}

// ZoneSettings is what the settings endpoints said.
type ZoneSettings struct {
	SSL         string // off, flexible, full, strict
	AlwaysHTTPS string // on, off
	MinTLS      string // 1.0 .. 1.3
}

// ZoneSetting reads one zone setting's value.
func (c *Client) ZoneSetting(ctx context.Context, zoneID, name string) (string, error) {
	if !zoneIDRe(zoneID) {
		return "", fmt.Errorf("bad zone ID %q", zoneID)
	}
	var out struct {
		ID    string          `json:"id"`
		Value json.RawMessage `json:"value"`
	}
	if _, err := c.get(ctx, "/zones/"+zoneID+"/settings/"+url.PathEscape(name), nil, &out); err != nil {
		return "", err
	}
	var v string
	if json.Unmarshal(out.Value, &v) != nil {
		return "", fmt.Errorf("setting %s: unexpected value %.40s", name, out.Value)
	}
	return clip(v), nil
}

// Settings reads a zone's settings. The state is a store.Surface* value:
// permission when the token can read none of them (Zone Settings Read is
// missing); a setting the token can't read on its own, or that the API
// doesn't have for the zone (404), is left "".
func (c *Client) Settings(ctx context.Context, zoneID string) (state, note string, zs ZoneSettings, err error) {
	dst := []*string{&zs.SSL, &zs.AlwaysHTTPS, &zs.MinTLS}
	denied, read := 0, 0
	for i, name := range SettingNames {
		v, err := c.ZoneSetting(ctx, zoneID, name)
		var ae *APIError
		switch {
		case IsPermission(err):
			denied++
		case errors.As(err, &ae) && ae.Status == http.StatusNotFound:
			// not offered for this zone: leave it ""
		case err != nil:
			return store.SurfaceError, clip(err.Error()), ZoneSettings{}, err
		default:
			*dst[i], read = v, read+1
		}
	}
	switch {
	case denied == len(SettingNames):
		return store.SurfacePermission, "the token can't read zone settings (add Zone > Zone Settings > Read)", ZoneSettings{}, nil
	case read == 0:
		return store.SurfaceError, "the API offers none of these settings for this zone", ZoneSettings{}, nil
	}
	return store.SurfaceOK, "", zs, nil
}

// CertExpiry returns the soonest expiry of the zone's active edge
// certificates (zero if none), from its certificate packs.
func (c *Client) CertExpiry(ctx context.Context, zoneID string) (state, note string, soonest time.Time, err error) {
	if !zoneIDRe(zoneID) {
		return store.SurfaceError, "bad zone ID", time.Time{}, fmt.Errorf("bad zone ID %q", zoneID)
	}
	type cert struct {
		Status    string `json:"status"`
		ExpiresOn string `json:"expires_on"`
	}
	for page := 1; page <= maxPages; page++ {
		var packs []struct {
			Status       string `json:"status"`
			Certificates []cert `json:"certificates"`
		}
		info, err := c.get(ctx, "/zones/"+zoneID+"/ssl/certificate_packs", url.Values{"page": {fmt.Sprint(page)}, "per_page": {"50"}}, &packs)
		switch {
		case IsPermission(err):
			return store.SurfacePermission, "the token can't read certificates (add Zone > SSL and Certificates > Read)", time.Time{}, nil
		case err != nil:
			return store.SurfaceError, clip(err.Error()), time.Time{}, err
		}
		for _, p := range packs {
			if p.Status != "" && p.Status != "active" {
				continue
			}
			for _, ct := range p.Certificates {
				if ct.Status != "" && ct.Status != "active" {
					continue
				}
				if t, err := time.Parse(time.RFC3339, ct.ExpiresOn); err == nil && (soonest.IsZero() || t.Before(soonest)) {
					soonest = t.UTC()
				}
			}
		}
		if info == nil || page >= info.TotalPages || len(packs) == 0 {
			return store.SurfaceOK, "", soonest, nil
		}
	}
	return store.SurfaceError, "too many pages", soonest, fmt.Errorf("certificate_packs: too many pages")
}
