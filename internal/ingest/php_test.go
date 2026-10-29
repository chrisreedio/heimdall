// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"slices"
	"testing"
)

func TestParsePHP(t *testing.T) {
	for _, c := range []struct {
		in  string
		cli string
		fpm []string
		ok  bool
	}{
		{"v1 cli=8.4 fpm=8.3,8.4", "8.4", []string{"8.3", "8.4"}, true},
		{"v1 cli=- fpm=-", "", []string{}, true},
		{"v1 cli=8.10 fpm=8.10", "8.10", []string{"8.10"}, true},
		{"v2 cli=8.4 fpm=-", "", nil, false},
		{"v1 cli=8.4", "", nil, false},
		{"v1 cli=8.4; fpm=-", "", nil, false},
		{"v1 cli=8 fpm=-", "", nil, false},
		{"v1 cli=8.4 fpm=8.3,x", "", nil, false},
		{"v1 cli=8.4 fpm=8.3 extra", "", nil, false},
	} {
		cli, fpm, ok := parsePHP(c.in)
		if ok != c.ok || cli != c.cli || (ok && !slices.Equal(fpm, c.fpm)) {
			t.Errorf("parsePHP(%q) = %q %q %v, want %q %q %v", c.in, cli, fpm, ok, c.cli, c.fpm, c.ok)
		}
	}
}
