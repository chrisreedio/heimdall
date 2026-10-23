// SPDX-License-Identifier: AGPL-3.0-or-later

package entra

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
)

type rsaKey struct{ pub *rsa.PublicKey }

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidToken, fmt.Sprintf(format, a...))
}

// validate checks the ID token's signature and claims and returns the
// identity it asserts.
func (c *Client) validate(ctx context.Context, meta *metadata, token, nonce string) (Identity, error) {
	if len(token) > maxToken {
		return Identity{}, invalid("token larger than %d bytes", maxToken)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Identity{}, invalid("not a JWS compact token")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Identity{}, invalid("header is not base64url")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return Identity{}, invalid("header is not JSON")
	}
	if header.Alg != "RS256" { // rejects none, HS*, ES* and anything else
		return Identity{}, invalid("unsupported alg %q", truncate(header.Alg, 16))
	}
	if header.Kid == "" || len(header.Kid) > 128 {
		return Identity{}, invalid("missing kid")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Identity{}, invalid("signature is not base64url")
	}
	key, err := c.key(ctx, meta, header.Kid)
	if err != nil {
		return Identity{}, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key.pub, crypto.SHA256, digest[:], sig); err != nil {
		return Identity{}, invalid("bad signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Identity{}, invalid("payload is not base64url")
	}
	var claims struct {
		Ver               string          `json:"ver"`
		Iss               string          `json:"iss"`
		Aud               json.RawMessage `json:"aud"`
		Exp               *json.Number    `json:"exp"`
		Nbf               *json.Number    `json:"nbf"`
		Iat               *json.Number    `json:"iat"`
		Nonce             string          `json:"nonce"`
		Tid               string          `json:"tid"`
		Oid               string          `json:"oid"`
		Email             string          `json:"email"`
		PreferredUsername string          `json:"preferred_username"`
		Name              string          `json:"name"`
		Roles             []string        `json:"roles"`
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil {
		return Identity{}, invalid("payload is not JSON")
	}

	if claims.Ver != "2.0" {
		return Identity{}, invalid("token version %q, want 2.0", truncate(claims.Ver, 8))
	}
	if !idRe.MatchString(claims.Tid) {
		return Identity{}, invalid("missing or malformed tid")
	}
	if !idRe.MatchString(claims.Oid) {
		return Identity{}, invalid("missing or malformed oid")
	}
	if !slices.ContainsFunc(c.cfg.AllowedTenants, func(t string) bool { return strings.EqualFold(t, claims.Tid) }) {
		return Identity{}, invalid("tenant %s is not allowed", claims.Tid)
	}
	if want := strings.ReplaceAll(meta.Issuer, "{tenantid}", claims.Tid); claims.Iss != want {
		return Identity{}, invalid("issuer %q, want %q", truncate(claims.Iss, 100), want)
	}
	if !audienceIs(claims.Aud, c.cfg.ClientID) {
		return Identity{}, invalid("audience is not this application")
	}

	now := c.cfg.Now()
	exp, err := unixClaim(claims.Exp)
	if err != nil || claims.Exp == nil {
		return Identity{}, invalid("missing or malformed exp")
	}
	if !now.Before(exp.Add(clockSkew)) {
		return Identity{}, invalid("token expired at %s", exp.UTC().Format(time.RFC3339))
	}
	iat, err := unixClaim(claims.Iat)
	if err != nil || claims.Iat == nil {
		return Identity{}, invalid("missing or malformed iat")
	}
	if iat.After(now.Add(clockSkew)) {
		return Identity{}, invalid("token issued in the future")
	}
	if claims.Nbf != nil {
		nbf, err := unixClaim(claims.Nbf)
		if err != nil {
			return Identity{}, invalid("malformed nbf")
		}
		if nbf.After(now.Add(clockSkew)) {
			return Identity{}, invalid("token not valid yet")
		}
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return Identity{}, invalid("nonce mismatch")
	}

	id := Identity{
		TenantID: strings.ToLower(claims.Tid),
		ObjectID: strings.ToLower(claims.Oid),
		Email:    truncate(claims.Email, 254),
		Name:     truncate(claims.Name, 200),
	}
	if id.Email == "" {
		id.Email = truncate(claims.PreferredUsername, 254)
	}
	for _, r := range claims.Roles {
		if len(id.Roles) == 100 {
			break
		}
		if r != "" && len(r) <= 200 {
			id.Roles = append(id.Roles, r)
		}
	}
	return id, nil
}

// audienceIs accepts aud as a string, or an array whose only member is want.
func audienceIs(raw json.RawMessage, want string) bool {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == want
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return len(list) == 1 && list[0] == want
	}
	return false
}

func unixClaim(n *json.Number) (time.Time, error) {
	if n == nil {
		return time.Time{}, nil
	}
	f, err := n.Float64()
	if err != nil || f < 0 || f > 1e11 {
		return time.Time{}, fmt.Errorf("bad timestamp")
	}
	return time.Unix(int64(f), 0), nil
}

// key returns the signing key for kid, fetching the JWKS when the key is
// unknown, but at most once per keyRefetchGap so a flood of bogus kids
// can't hammer Entra.
func (c *Client) key(ctx context.Context, meta *metadata, kid string) (*rsaKey, error) {
	c.mu.Lock()
	k, ok := c.keys[kid]
	canFetch := c.keys == nil || c.cfg.Now().Sub(c.keysFetched) >= keyRefetchGap
	if !ok && canFetch {
		c.keysFetched = c.cfg.Now() // claim the fetch slot before releasing the lock
	}
	c.mu.Unlock()
	if ok {
		return k, nil
	}
	if !canFetch {
		return nil, invalid("unknown kid %q (key refresh rate-limited)", truncate(kid, 64))
	}
	keys, err := c.fetchKeys(ctx, meta)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.keys = keys
	k, ok = keys[kid]
	c.mu.Unlock()
	if !ok {
		return nil, invalid("unknown kid %q", truncate(kid, 64))
	}
	return k, nil
}

func (c *Client) fetchKeys(ctx context.Context, meta *metadata) (map[string]*rsaKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := c.cfg.HTTP.GetJSON(ctx, meta.JWKSURI, maxJSON, &set); err != nil {
		return nil, fmt.Errorf("entra: fetching signing keys: %w", err)
	}
	keys := map[string]*rsaKey{}
	for i, jk := range set.Keys {
		if i == 100 {
			break
		}
		if jk.Kty != "RSA" || (jk.Use != "" && jk.Use != "sig") || jk.Kid == "" {
			continue
		}
		nb, err1 := base64.RawURLEncoding.DecodeString(jk.N)
		eb, err2 := base64.RawURLEncoding.DecodeString(jk.E)
		if err1 != nil || err2 != nil || len(eb) == 0 || len(eb) > 4 {
			continue
		}
		e := int(new(big.Int).SetBytes(eb).Int64())
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
		if pub.N.BitLen() < 2048 || e < 3 || e%2 == 0 {
			continue
		}
		keys[jk.Kid] = &rsaKey{pub: pub}
	}
	return keys, nil
}
