// SPDX-License-Identifier: AGPL-3.0-or-later

package cvss

import (
	"strings"
	"testing"
)

func TestScore(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
		note   string
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "typical unauthenticated RCE"},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "same, v3.0"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Log4Shell CVE-2021-44228, xz CVE-2024-3094"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "reflected XSS"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "Heartbleed CVE-2014-0160"},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "regreSSHion CVE-2024-6387"},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "PwnKit CVE-2021-4034"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "network DoS"},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, "authenticated RCE"},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "scope change, low privileges"},
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1, "scope change, high privileges"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, "user interaction"},
		{"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8, "adjacent network"},
		{"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.4, "local, no privileges"},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "high complexity info leak"},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "physical, minimal impact"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "no impact"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C", 9.8, "temporal metrics ignored"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/MAV:L", 9.8, "environmental metrics ignored"},
		{"CVSS:3.1/S:U/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H", 9.8, "metric order doesn't matter"},
	}
	for _, tt := range tests {
		got, err := Score(tt.vector)
		if err != nil {
			t.Errorf("%s (%s): %v", tt.vector, tt.note, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%s (%s) = %.1f, want %.1f", tt.vector, tt.note, got, tt.want)
		}
	}
}

func TestScoreErrors(t *testing.T) {
	for _, v := range []string{
		"",
		"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // no prefix
		"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", // v2
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", // v4
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",                        // missing A
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/A:L",                // duplicate
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                    // bad value
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:1",               // unknown metric
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:Q",                // bad temporal value
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/",                   // trailing slash
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A",                      // no value
		"CVSS:3.1/" + strings.Repeat("AV:N/", 1000),
	} {
		if s, err := Score(v); err == nil {
			t.Errorf("Score(%q) = %v, want error", v, s)
		}
	}
}

func TestRoundup31(t *testing.T) {
	// The v3.1 spec's motivating example: naive ceil(x*10)/10 gives 4.1
	// for 4.000000000000001.
	for in, want := range map[float64]float64{4.000000000000001: 4.0, 4.02: 4.1, 4.0: 4.0, 0.0: 0.0, 9.95: 10.0} {
		if got := roundup31(in); got != want {
			t.Errorf("roundup31(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestRating(t *testing.T) {
	for score, want := range map[float64]string{10: "critical", 9.0: "critical", 8.9: "high", 7.0: "high",
		6.9: "medium", 4.0: "medium", 3.9: "low", 0.1: "low", 0: "none"} {
		if got := Rating(score); got != want {
			t.Errorf("Rating(%v) = %q, want %q", score, got, want)
		}
	}
}

func FuzzScore(f *testing.F) {
	f.Add("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
	f.Fuzz(func(t *testing.T, v string) {
		s, err := Score(v)
		if err == nil && (s < 0 || s > 10) {
			t.Fatalf("Score(%q) = %v out of range", v, s)
		}
	})
}
