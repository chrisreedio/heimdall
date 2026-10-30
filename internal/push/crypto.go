// SPDX-License-Identifier: AGPL-3.0-or-later

// Package push sends Web Push notifications to the installed app
// (docs/mobile.md#notifications). The hub talks to the browsers' push
// services itself: outbound HTTPS only, to a fixed set of push services,
// with no relay and no app-store account. Every message is encrypted for
// the one browser that subscribed (RFC 8291), so the push service sees
// only ciphertext, and it's signed with the hub's own VAPID key (RFC 8292).
//
// A notification carries at most an event's kind, a host's name and a
// count, or with "Hidden" lock-screen detail only a generic line. Never
// package names, addresses or usernames: the Notice type has no field
// that could hold them.
package push

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// b64 is the base64 the Push API and JWTs use: URL-safe, unpadded.
var b64 = base64.RawURLEncoding

// recordSize is the aes128gcm record size the hub declares (RFC 8188). A
// message is a single record, so it must be smaller than this.
const recordSize = 4096

// maxPlaintext keeps a message well inside what every push service takes
// (4096 bytes of body, header included).
const maxPlaintext = 3000

// Encrypt encrypts plaintext for one subscription: p256dh is the browser's
// public key (65 bytes, uncompressed P-256) and auth its 16-byte secret.
// The result is the request body, with Content-Encoding: aes128gcm.
func Encrypt(plaintext, p256dh, auth []byte) ([]byte, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return encrypt(plaintext, p256dh, auth, priv, salt)
}

// encrypt is RFC 8291 section 3 with the sender's key pair and salt given,
// so the RFC's worked example (Appendix A) can be checked.
func encrypt(plaintext, p256dh, auth []byte, asPriv *ecdh.PrivateKey, salt []byte) ([]byte, error) {
	if len(plaintext) > maxPlaintext {
		return nil, fmt.Errorf("push: message of %d bytes is too large", len(plaintext))
	}
	if len(auth) != 16 || len(salt) != 16 {
		return nil, errors.New("push: auth secret and salt must be 16 bytes")
	}
	uaPub, err := ecdh.P256().NewPublicKey(p256dh)
	if err != nil {
		return nil, fmt.Errorf("push: bad subscription key: %w", err)
	}
	secret, err := asPriv.ECDH(uaPub)
	if err != nil {
		return nil, err
	}
	asPub := asPriv.PublicKey().Bytes()
	// IKM = HKDF(auth, ecdh_secret, "WebPush: info" || 0x00 || ua_public || as_public, 32)
	keyInfo := "WebPush: info\x00" + string(p256dh) + string(asPub)
	ikm, err := hkdf.Key(sha256.New, secret, auth, keyInfo, 32)
	if err != nil {
		return nil, err
	}
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, err
	}
	cek, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// The header: salt, record size, the sender's public key as key ID.
	out := make([]byte, 0, 16+4+1+len(asPub)+len(plaintext)+1+gcm.Overhead())
	out = append(out, salt...)
	out = binary.BigEndian.AppendUint32(out, recordSize)
	out = append(out, byte(len(asPub)))
	out = append(out, asPub...)
	// One record, the last: plaintext, then the 0x02 delimiter, no padding.
	record := append(append(make([]byte, 0, len(plaintext)+1), plaintext...), 0x02)
	return gcm.Seal(out, nonce, record, nil), nil
}

// VAPID is the hub's application server key (RFC 8292). Push services
// tie each subscription to its public half, and take messages for it only
// when they're signed with the private half.
type VAPID struct {
	priv *ecdsa.PrivateKey
	pub  []byte // uncompressed point, 65 bytes
}

// NewVAPIDKey makes a private key, as stored (32 bytes).
func NewVAPIDKey() ([]byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return k.Bytes()
}

// ParseVAPID loads a stored private key.
func ParseVAPID(raw []byte) (*VAPID, error) {
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return nil, fmt.Errorf("push: VAPID key: %w", err)
	}
	pub, err := k.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	return &VAPID{priv: k, pub: pub}, nil
}

// PublicKey is the key browsers subscribe with (applicationServerKey).
func (v *VAPID) PublicKey() string { return b64.EncodeToString(v.pub) }

// jwtTTL is how long a signature is good for; RFC 8292 caps it at 24 hours.
const jwtTTL = 12 * time.Hour

// Authorization is the header for a message to endpoint: "vapid t=<JWT>,
// k=<public key>". sub is a contact for the push service: an https URL or
// a mailto: address.
func (v *VAPID) Authorization(endpoint, sub string, now time.Time) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "", errors.New("push: bad endpoint")
	}
	header := b64.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))
	claims, err := json.Marshal(struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Sub string `json:"sub"`
	}{u.Scheme + "://" + u.Host, now.Add(jwtTTL).Unix(), sub})
	if err != nil {
		return "", err
	}
	signing := header + "." + b64.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, v.priv, sum[:])
	if err != nil {
		return "", err
	}
	// JWS ES256: r and s, 32 bytes each (RFC 7518 section 3.4), not ASN.1.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return "vapid t=" + signing + "." + b64.EncodeToString(sig) + ", k=" + v.PublicKey(), nil
}
