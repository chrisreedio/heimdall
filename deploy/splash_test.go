// SPDX-License-Identifier: AGPL-3.0-or-later

// Package deploy holds checks for the files install-hub.sh installs.
package deploy

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestSplashCSP keeps the CSP hash in install-hub.sh's Caddyfile in step
// with splash.html's <style> block, and checks the page stays inert.
func TestSplashCSP(t *testing.T) {
	page, err := os.ReadFile("splash.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile("install-hub.sh")
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	if len(page) > 4096 {
		t.Errorf("splash.html is %d bytes; keep it under 4 KB", len(page))
	}

	styles := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindAllStringSubmatch(html, -1)
	if len(styles) != 1 {
		t.Fatalf("splash.html has %d <style> blocks; want exactly 1", len(styles))
	}
	sum := sha256.Sum256([]byte(styles[0][1]))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	got := regexp.MustCompile(`style-src ('sha256-[^']+')`).FindStringSubmatch(string(script))
	if got == nil {
		t.Fatal("install-hub.sh has no style-src 'sha256-…' in splash_csp")
	}
	if got[1] != want {
		t.Errorf("install-hub.sh pins style-src %s, but splash.html's <style> hashes to %s; update splash_csp", got[1], want)
	}

	lower := strings.ToLower(html)
	// The SVG namespace URI is an identifier, not a fetch.
	stripped := strings.ReplaceAll(lower, `xmlns="http://www.w3.org/2000/svg"`, "")
	for _, bad := range []string{"<script", " style=", "javascript:", "http://", "https://", "//", "<link", "<img", "@import"} {
		if strings.Contains(stripped, bad) {
			t.Errorf("splash.html contains %q", bad)
		}
	}
	if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(html) {
		t.Error("splash.html has an inline event handler")
	}

	// No visible text: strip <style>, <title> and every tag, and nothing
	// but whitespace may remain.
	text := regexp.MustCompile(`(?s)<style>.*?</style>|<title>.*?</title>|<[^>]*>`).ReplaceAllString(html, "")
	if strings.TrimSpace(text) != "" {
		t.Errorf("splash.html shows text: %q", strings.TrimSpace(text))
	}
	if strings.Contains(lower, "heimdall") {
		t.Error("splash.html names the product")
	}
}
