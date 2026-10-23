// SPDX-License-Identifier: AGPL-3.0-or-later

package secret

import "testing"

func TestNewToken(t *testing.T) {
	a, ha := NewToken(IngestPrefix)
	b, hb := NewToken(IngestPrefix)
	if a == b || ha == hb {
		t.Fatal("tokens must be unique")
	}
	if Hash(a) != ha {
		t.Fatal("hash mismatch")
	}
	if !LooksLike(a, IngestPrefix) {
		t.Fatalf("generated token %q not recognized", a)
	}
}

func TestLooksLike(t *testing.T) {
	tok, _ := NewToken(IngestPrefix)
	for _, s := range []string{"", IngestPrefix, "hmd_other_" + tok[len(IngestPrefix):], tok + "x", tok[:len(tok)-1] + "!"} {
		if LooksLike(s, IngestPrefix) {
			t.Errorf("LooksLike(%q) = true", s)
		}
	}
}
