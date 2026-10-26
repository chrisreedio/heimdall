// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/realmwatch/heimdall/internal/netx"
)

// Every release's SHA256SUMS carries a Sigstore signature made by this
// repo's release workflow for a v* tag. `heimdall upgrade` checks it before
// it runs the new release's installer, which checks it again (as do
// install.sh and `heimdall-collect upgrade`). cosign does the checking: a
// pinned build, fetched once into cosignDir and checked against these
// hashes each time it's used. Keep these in sync with the copies in
// collector/collect.sh, collector/install.sh, deploy/install-hub.sh and
// collector/install-windows.ps1 (TestSignaturePinsMatch).
const (
	cosignVersion = "v3.1.4"
	// releaseSigner is the certificate identity a release must be signed
	// by. The old repo name stays until no installs older than the move
	// remain.
	releaseSigner = `^https://github.com/(chrisreedio|realmwatch)/heimdall/\.github/workflows/release\.yml@refs/tags/v`
	releaseIssuer = "https://token.actions.githubusercontent.com"
)

// cosignSHA256 are the pinned builds' hashes, by GOARCH (from cosign's
// cosign_checksums.txt for cosignVersion).
var cosignSHA256 = map[string]string{
	"amd64": "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa",
	"arm64": "ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2",
}

// Seams for tests.
var (
	cosignDir  = "/usr/local/lib/heimdall"
	cosignBase = "https://github.com/sigstore/cosign/releases/download/"
	cosignArch = runtime.GOARCH
	runCosign  = func(ctx context.Context, bin, home string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = append(os.Environ(), "HOME="+home)
		return cmd.CombinedOutput()
	}
)

// cosignMaxBytes bounds the cosign download (the builds are ~140 MB).
const cosignMaxBytes = 512 << 20

// verifyReleaseSums checks that sums is the SHA256SUMS the release
// workflow signed, with bundle (SHA256SUMS.sigstore.json).
func verifyReleaseSums(a *app, hc *netx.Client, sums, bundle []byte) error {
	bin, err := pinnedCosign(a, hc)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "heimdall-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	sumsPath, bundlePath := filepath.Join(dir, "SHA256SUMS"), filepath.Join(dir, "SHA256SUMS.sigstore.json")
	if err := os.WriteFile(sumsPath, sums, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		return err
	}
	out, err := runCosign(a.ctx, bin, dir, "verify-blob", sumsPath, "--bundle", bundlePath,
		"--certificate-identity-regexp", releaseSigner, "--certificate-oidc-issuer", releaseIssuer)
	if err != nil {
		return fmt.Errorf("the release's SHA256SUMS signature verification FAILED; not upgrading: %s", lastLine(out))
	}
	fmt.Fprintln(a.stderr, "Sigstore signature verified")
	return nil
}

// pinnedCosign returns the path of the pinned cosign build, fetching it
// first if it's missing or doesn't match its hash.
func pinnedCosign(a *app, hc *netx.Client) (string, error) {
	want, ok := cosignSHA256[cosignArch]
	if !ok {
		return "", fmt.Errorf("no pinned cosign for %s to check the release signature; pass --skip-signature-check to upgrade without it", cosignArch)
	}
	bin := filepath.Join(cosignDir, "cosign-"+cosignVersion+"-"+cosignArch)
	if got, err := fileSHA256(bin); err == nil && got == want {
		return bin, nil
	}
	fmt.Fprintf(a.stderr, "Fetching cosign %s (once) to check the release signature\n", cosignVersion)
	if err := os.MkdirAll(cosignDir, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(cosignDir, ".cosign-")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	got, err := download(a.ctx, hc, cosignBase+cosignVersion+"/cosign-linux-"+cosignArch, tmp)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("fetching cosign: %w", err)
	}
	if got != want {
		return "", errors.New("the cosign download doesn't match its pinned hash; not using it")
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), bin); err != nil {
		return "", err
	}
	return bin, nil
}

// download streams url into w and returns its SHA-256.
func download(ctx context.Context, hc *netx.Client, url string, w io.Writer) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.HTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &netx.StatusError{URL: url, Status: resp.StatusCode}
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, cosignMaxBytes+1))
	if err != nil {
		return "", err
	}
	if n > cosignMaxBytes {
		return "", fmt.Errorf("GET %s: larger than %d bytes", url, cosignMaxBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func lastLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return s
}
