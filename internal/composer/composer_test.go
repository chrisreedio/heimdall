// SPDX-License-Identifier: AGPL-3.0-or-later

package composer

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	valid := []string{
		"^8.2", "~8.1.0", ">=8.1 <9.0", "8.1.*", "^7.4 || ^8.0", "8.2", ">=8.1,<8.4", "*",
		"^7.4|^8.0", ">= 8.1", "1.0 - 2.0", "1.0.0 - 2.0.3", "!=8.0.1", "<>8.0", "==8.1", "=8.1",
		"^8.2@stable", "dev-main", "8.x", "v1.2.3", "^1.2.3-beta2", ">=8.1, <8.4", "x",
	}
	for _, s := range valid {
		if _, err := Parse(s); err != nil {
			t.Errorf("Parse(%q): %v", s, err)
		}
	}
	invalid := []string{
		"", "   ", "^", "~", ">=", "abc", "^8.2 ||", "|| ^8.2", ">=8.1,,<9", "~>1.2", "1.0 -", "- 1.0",
		">=8.1<9", "^8.*", "8.1-2.0", "@dev", ">dev-main", "8.1.2.3.4", "^1.2.x-dev",
		strings.Repeat("1", MaxLength+1), "1.0 - dev-main",
	}
	for _, s := range invalid {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) should fail", s)
		}
	}
}

func TestAllows(t *testing.T) {
	tests := []struct {
		constraint, version string
		want                bool
	}{
		// caret
		{"^8.2", "8.2.0", true},
		{"^8.2", "8.3.12", true},
		{"^8.2", "8.1.99", false},
		{"^8.2", "9.0.0", false},
		{"^8.2", "9.0.0-RC1", false},
		{"^8.2", "8.2.0-RC1", true},
		{"^0.3", "0.3.5", true},
		{"^0.3", "0.4.0", false},
		{"^0.0.3", "0.0.3", true},
		{"^0.0.3", "0.0.4", false},
		{"^0", "0.9.9", true},
		{"^0", "1.0.0", false},
		{"^1.2.3-beta2", "1.2.3-beta1", false},
		{"^1.2.3-beta2", "1.2.3-beta3", true},
		// tilde
		{"~8.1", "8.9.0", true},
		{"~8.1", "9.0.0", false},
		{"~8.1.0", "8.1.27", true},
		{"~8.1.0", "8.2.0", false},
		{"~1", "1.9", true},
		{"~1", "2.0", false},
		{"~1.2.3.4", "1.2.3.9", true},
		{"~1.2.3.4", "1.2.4.0", false},
		// wildcard
		{"8.1.*", "8.1.0", true},
		{"8.1.*", "8.1.31", true},
		{"8.1.*", "8.2.0", false},
		{"8.*", "8.4.1", true},
		{"8.*", "9.0", false},
		{"*", "1.0", true},
		{"*", "dev-main", false},
		// operators
		{">=8.1 <9.0", "8.4.2", true},
		{">=8.1 <9.0", "9.0.0", false},
		{">=8.1 <9.0", "8.0.30", false},
		{">=8.1,<8.4", "8.3.99", true},
		{">=8.1,<8.4", "8.4.0", false},
		{"<8.4", "8.4.0-RC1", false},
		{">=8.4", "8.4.0-RC1", true},
		{">8.1", "8.1.0", false},
		{">8.1", "8.1.1", true},
		{"<=8.1", "8.1.0", true},
		{"<=8.1", "8.1.1", false},
		{"!=8.0.1", "8.0.1", false},
		{"!=8.0.1", "8.0.2", true},
		{"<>8.0", "8.0.0", false},
		{"8.2", "8.2.0", true},
		{"8.2", "8.2.5", false},
		{"==8.2", "8.2", true},
		{">= 8.1", "8.1.0", true},
		// OR / AND mixes
		{"^7.4 || ^8.0", "7.4.33", true},
		{"^7.4 || ^8.0", "8.3.0", true},
		{"^7.4 || ^8.0", "7.3.0", false},
		{"^7.4|^8.0", "8.0.0", true},
		{">=7.4 <8.0 || >=8.2", "8.1.0", false},
		{">=7.4 <8.0 || >=8.2", "8.2.1", true},
		// hyphen ranges
		{"1.0 - 2.0", "2.0.9", true},
		{"1.0 - 2.0", "2.1.0", false},
		{"1.0 - 2.0", "1.0.0", true},
		{"1.0.0 - 2.0.3", "2.0.3", true},
		{"1.0.0 - 2.0.3", "2.0.4", false},
		// stability
		{"^8.2@stable", "8.2.1", true},
		{"^11.0", "11.31.0-RC1", true},
		{"^11.0", "v11.31.0", true},
		{"^1.0", "1.0.0-patch1", true},
		{">1.0.0", "1.0.0-patch1", true},
		{"<1.0.0", "1.0.0-alpha", false},
		{"<=1.0.0", "1.0.0-alpha", true},
		// dev branches
		{"dev-main", "dev-main", true},
		{"dev-main", "dev-develop", false},
		{"^1.0", "dev-main", false},
		{"!=1.0", "dev-main", false},
		// invalid versions never match
		{"*", "not-a-version", false},
		{"^8.2", "", false},
	}
	for _, tt := range tests {
		c, err := Parse(tt.constraint)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tt.constraint, err)
		}
		if got := c.Allows(tt.version); got != tt.want {
			t.Errorf("%q.Allows(%q) = %v, want %v", tt.constraint, tt.version, got, tt.want)
		}
	}
}

func TestAllowsMinor(t *testing.T) {
	tests := []struct {
		constraint, minor string
		want              bool
	}{
		{"^8.2", "8.3", true},
		{"^8.2", "8.2", true},
		{"^8.2", "8.1", false},
		{"^8.2", "9.0", false},
		{">=8.3.5", "8.3", true},
		{">=8.3.5", "8.2", false},
		{"<8.3", "8.3", false},
		{"<8.3", "8.2", true},
		{"<8.3.2", "8.3", true},
		{">8.3.99999", "8.3", true},
		{"~8.1.0", "8.1", true},
		{"~8.1.0", "8.2", false},
		{"8.2", "8.2", true},
		{"8.2.5", "8.2", true},
		{"!=8.2.0", "8.2", true},
		{"8.1.*", "8.1", true},
		{"^7.4 || ^8.0", "8.4", true},
		{">=8.1 <8.4", "8.4", false},
		{"*", "5.6", true},
		{"^8.2", "8", false},       // minor required
		{"^8.2", "garbage", false}, // unparsable
		{"^8.2", "8.3.12", true},   // extra parts are fine
	}
	for _, tt := range tests {
		c, err := Parse(tt.constraint)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tt.constraint, err)
		}
		if got := c.AllowsMinor(tt.minor); got != tt.want {
			t.Errorf("%q.AllowsMinor(%q) = %v, want %v", tt.constraint, tt.minor, got, tt.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	// Each version sorts strictly before the next.
	ordered := []string{
		"garbage",
		"dev-feature",
		"dev-main",
		"1.0.0-dev",
		"1.0.0-alpha1",
		"1.0.0-alpha2",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-RC1",
		"1.0.0",
		"1.0.0-patch1",
		"1.0.1",
		"1.2",
		"v1.10.0",
		"2.0.0",
		"11.31.0",
	}
	for i := range ordered {
		for j := range ordered {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := CompareVersions(ordered[i], ordered[j]); got != want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	equal := [][2]string{{"1.0", "1.0.0"}, {"v1.2.3", "1.2.3"}, {"1.0.0-RC1", "1.0.0rc1"}, {"1.0.0-b2", "1.0.0-beta2"}, {"1.0.0-pl1", "1.0.0-p1"}}
	for _, p := range equal {
		if got := CompareVersions(p[0], p[1]); got != 0 {
			t.Errorf("CompareVersions(%q, %q) = %d, want 0", p[0], p[1], got)
		}
	}
}

func TestString(t *testing.T) {
	c, err := Parse("  ^8.2 || ^8.3 ")
	if err != nil {
		t.Fatal(err)
	}
	if c.String() != "^8.2 || ^8.3" {
		t.Errorf("String() = %q", c.String())
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"^8.2", "~1.2.3", ">=8.1 <9.0 || 7.4.*", "1.0 - 2.0", "dev-main", "8.2@stable"} {
		f.Add(s, "8.3.1")
	}
	f.Fuzz(func(t *testing.T, constraint, ver string) {
		c, err := Parse(constraint)
		if err != nil {
			return
		}
		a, b := c.Allows(ver), c.Allows(ver)
		if a != b {
			t.Fatalf("Allows not deterministic for %q %q", constraint, ver)
		}
		c.AllowsMinor(ver)
		if CompareVersions(ver, ver) != 0 {
			t.Fatalf("CompareVersions(%q, itself) != 0", ver)
		}
	})
}
