// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"regexp"
	"strings"
	"testing"
)

// An unclosed block (a merge that drops a "}") silently turns every rule
// after it into a phone-only @media rule, so check the braces balance.
func TestCSSBracesBalance(t *testing.T) {
	b, err := staticFS.ReadFile("static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(string(b), "")
	depth := 0
	for i, line := range strings.Split(css, "\n") {
		for _, c := range line {
			switch c {
			case '{':
				depth++
			case '}':
				if depth--; depth < 0 {
					t.Fatalf("app.css: extra } on line %d", i+1)
				}
			}
		}
	}
	if depth != 0 {
		t.Fatalf("app.css: %d unclosed block(s)", depth)
	}
}
