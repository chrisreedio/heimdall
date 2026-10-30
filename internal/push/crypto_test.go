// SPDX-License-Identifier: AGPL-3.0-or-later

package push

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

// RFC 8291 Appendix A: the worked example, with its fixed keys and salt.
func TestEncryptRFC8291Example(t *testing.T) {
	t.Parallel()
	plaintext := []byte("When I grow up, I want to be a watermelon")
	asPriv, err := ecdh.P256().NewPrivateKey(unb64(t, "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"))
	if err != nil {
		t.Fatal(err)
	}
	if got := b64.EncodeToString(asPriv.PublicKey().Bytes()); got != "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8" {
		t.Fatalf("as_public = %s", got)
	}
	uaPublic := unb64(t, "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4")
	auth := unb64(t, "BTBZMqHH6r4Tts7J_aSIgg")
	salt := unb64(t, "DGv6ra1nlYgDCS1FRnbzlw")
	got, err := encrypt(plaintext, uaPublic, auth, asPriv, salt)
	if err != nil {
		t.Fatal(err)
	}
	want := "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
	if b64.EncodeToString(got) != want {
		t.Fatalf("body =\n%s\nwant\n%s", b64.EncodeToString(got), want)
	}
	// And the receiver's side of the same example decrypts it.
	uaPriv := unb64(t, "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")
	if pt := decryptForTest(t, got, uaPriv, auth); string(pt) != string(plaintext) {
		t.Fatalf("decrypted %q", pt)
	}
}

// decryptForTest is the browser's side of RFC 8291, for round trips.
func decryptForTest(t *testing.T, body, uaPrivRaw, auth []byte) []byte {
	t.Helper()
	uaPriv, err := ecdh.P256().NewPrivateKey(uaPrivRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 21 {
		t.Fatal("short body")
	}
	salt, rs, idlen := body[:16], binary.BigEndian.Uint32(body[16:20]), int(body[20])
	if rs != recordSize || idlen != 65 {
		t.Fatalf("rs %d idlen %d", rs, idlen)
	}
	asPubRaw := body[21 : 21+idlen]
	asPub, err := ecdh.P256().NewPublicKey(asPubRaw)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := uaPriv.ECDH(asPub)
	if err != nil {
		t.Fatal(err)
	}
	ikm, _ := hkdf.Key(sha256.New, secret, auth, "WebPush: info\x00"+string(uaPriv.PublicKey().Bytes())+string(asPubRaw), 32)
	prk, _ := hkdf.Extract(sha256.New, ikm, salt)
	cek, _ := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	nonce, _ := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	pt, err := gcm.Open(nil, nonce, body[21+idlen:], nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(pt) == 0 || pt[len(pt)-1] != 0x02 {
		t.Fatal("missing last-record delimiter")
	}
	return pt[:len(pt)-1]
}

// testBrowser is a subscription's keys, as a browser makes them.
type testBrowser struct {
	priv   *ecdh.PrivateKey
	p256dh []byte
	auth   []byte
}

func newTestBrowser(t *testing.T) testBrowser {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	rand.Read(auth)
	return testBrowser{priv: k, p256dh: k.PublicKey().Bytes(), auth: auth}
}

func (b testBrowser) open(t *testing.T, body []byte) []byte {
	return decryptForTest(t, body, b.priv.Bytes(), b.auth)
}

func TestEncryptRoundTripFreshKeys(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	msg := []byte(`{"title":"Known-exploited finding on web-01"}`)
	one, err := Encrypt(msg, b.p256dh, b.auth)
	if err != nil {
		t.Fatal(err)
	}
	two, _ := Encrypt(msg, b.p256dh, b.auth)
	if bytes.Equal(one, two) {
		t.Fatal("two encryptions of one message are identical: salt or key reused")
	}
	if got := b.open(t, one); !bytes.Equal(got, msg) {
		t.Fatalf("round trip: %q", got)
	}
	if _, err := Encrypt(make([]byte, maxPlaintext+1), b.p256dh, b.auth); err == nil {
		t.Fatal("oversized message accepted")
	}
	if _, err := Encrypt(msg, b.p256dh[:64], b.auth); err == nil {
		t.Fatal("bad key accepted")
	}
	if _, err := Encrypt(msg, b.p256dh, b.auth[:8]); err == nil {
		t.Fatal("short auth secret accepted")
	}
}

func TestVAPIDAuthorization(t *testing.T) {
	t.Parallel()
	raw, err := NewVAPIDKey()
	if err != nil || len(raw) != 32 {
		t.Fatalf("key %d bytes, %v", len(raw), err)
	}
	v, err := ParseVAPID(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pub := unb64(t, v.PublicKey()); len(pub) != 65 || pub[0] != 0x04 {
		t.Fatalf("public key %x", pub)
	}
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	h, err := v.Authorization("https://fcm.googleapis.com/fcm/send/abc:def", "https://hub.example-tailnet.ts.net", now)
	if err != nil {
		t.Fatal(err)
	}
	rest, ok := strings.CutPrefix(h, "vapid t=")
	if !ok {
		t.Fatalf("header %q", h)
	}
	jwt, k, ok := strings.Cut(rest, ", k=")
	if !ok || k != v.PublicKey() {
		t.Fatalf("k= %q", k)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts", len(parts))
	}
	var head struct{ Typ, Alg string }
	if err := json.Unmarshal(unb64(t, parts[0]), &head); err != nil || head.Alg != "ES256" || head.Typ != "JWT" {
		t.Fatalf("header %s", unb64(t, parts[0]))
	}
	var claims struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(unb64(t, parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Aud != "https://fcm.googleapis.com" || claims.Sub != "https://hub.example-tailnet.ts.net" {
		t.Fatalf("claims %+v", claims)
	}
	if exp := time.Unix(claims.Exp, 0); exp.Sub(now) > 24*time.Hour || !exp.After(now) {
		t.Fatalf("exp %v: must be within 24h (RFC 8292)", exp)
	}
	sig := unb64(t, parts[2])
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want raw r||s (64)", len(sig))
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), unb64(t, v.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, sum[:], r, s) {
		t.Fatal("signature doesn't verify with the public key")
	}
	if _, err := ParseVAPID(raw[:31]); err == nil {
		t.Fatal("short key accepted")
	}
}
