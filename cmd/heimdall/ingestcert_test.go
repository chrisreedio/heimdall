// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T, dir, name, host string) (certPath, keyPath string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	certPath, keyPath = dir+"/"+name+".pem", dir+"/"+name+".key"
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	return
}

func TestIngestCert(t *testing.T) {
	dir := t.TempDir()
	stub(t, &caddyDir, dir)
	stub(t, &isRoot, func() bool { return true })
	reloads := 0
	stub(t, &reloadCaddy, func(*app) error { reloads++; return nil })
	caddyfile := "# Written by Heimdall\ningest.example.com {\n\t@ingest path /api/v1/ingest\n\treverse_proxy @ingest 127.0.0.1:8443\n\trespond 404\n}\n"
	os.WriteFile(dir+"/Caddyfile", []byte(caddyfile), 0o644)
	cert, key := testCert(t, dir, "good", "ingest.example.com")
	_, otherKey := testCert(t, dir, "other", "ingest.example.com")
	wrongCert, wrongKey := testCert(t, dir, "wrong", "elsewhere.example.com")

	runIt := func(c, k string) error {
		var out, errb bytes.Buffer
		return run(t.Context(), []string{"ingest", "cert", "--host", "ingest.example.com", "--cert-file", c, "--key-file", k}, &out, &errb)
	}
	if err := runIt(cert, otherKey); err == nil || !strings.Contains(err.Error(), "valid pair") {
		t.Errorf("mismatched key: %v", err)
	}
	if err := runIt(wrongCert, wrongKey); err == nil || !strings.Contains(err.Error(), "doesn't cover") {
		t.Errorf("wrong host: %v", err)
	}
	if reloads != 0 {
		t.Fatal("reloaded after a rejected pair")
	}
	for range 2 { // twice: the tls line is replaced, not duplicated
		if err := runIt(cert, key); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(dir + "/Caddyfile")
	if strings.Count(string(b), "\ttls ") != 1 || !strings.Contains(string(b), "ingest.example.com {\n\ttls "+dir+"/heimdall-origin.pem "+dir+"/heimdall-origin.key\n") {
		t.Errorf("Caddyfile:\n%s", b)
	}
	if fi, _ := os.Stat(dir + "/heimdall-origin.key"); fi.Mode().Perm()&0o007 != 0 {
		t.Errorf("key mode %v", fi.Mode().Perm())
	}
	if reloads != 2 {
		t.Errorf("reloads = %d", reloads)
	}
}

func TestReadBlock(t *testing.T) {
	done := func(l string) bool { return strings.TrimSpace(l) == "-----END X-----" }
	if _, err := readBlock(bufioReader("a\nb\n"), done); err == nil {
		t.Error("missing END accepted")
	}
	if s, err := readBlock(bufioReader("-----BEGIN X-----\nabc\n-----END X-----\ntrailing"), done); err != nil || strings.Contains(s, "trailing") {
		t.Errorf("got %q %v", s, err)
	}
}

func bufioReader(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s)) }
