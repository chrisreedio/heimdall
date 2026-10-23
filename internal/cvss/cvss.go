// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cvss computes CVSS v3.0 and v3.1 base scores from vector strings,
// following the FIRST specifications (https://www.first.org/cvss/v3.1/specification-document).
package cvss

import (
	"fmt"
	"math"
	"strings"
)

var baseMetrics = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"PR": {"N": 0.85, "L": 0.62, "H": 0.27}, // L and H change when scope changes
	"UI": {"N": 0.85, "R": 0.62},
	"S":  {"U": 0, "C": 0},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

// Temporal and environmental metrics may appear in a vector; they don't
// affect the base score and are ignored (but must be well-formed).
var otherMetrics = map[string]string{
	"E": "XUPFH", "RL": "XOTWU", "RC": "XURC",
	"CR": "XLMH", "IR": "XLMH", "AR": "XLMH",
	"MAV": "XNALP", "MAC": "XLH", "MPR": "XNLH", "MUI": "XNR", "MS": "XUC",
	"MC": "XNLH", "MI": "XNLH", "MA": "XNLH",
}

// Score computes the base score of a CVSS v3.0 or v3.1 vector such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" (9.8).
func Score(vector string) (float64, error) {
	ver, rest, ok := strings.Cut(vector, "/")
	if !ok || (ver != "CVSS:3.0" && ver != "CVSS:3.1") {
		return 0, fmt.Errorf("cvss: unsupported vector %q (want CVSS:3.0 or CVSS:3.1)", truncate(vector))
	}
	m := map[string]string{}
	for _, part := range strings.Split(rest, "/") {
		k, v, ok := strings.Cut(part, ":")
		if !ok || k == "" || v == "" {
			return 0, fmt.Errorf("cvss: malformed metric %q", truncate(part))
		}
		if _, dup := m[k]; dup {
			return 0, fmt.Errorf("cvss: duplicate metric %s", k)
		}
		if vals, base := baseMetrics[k]; base {
			if _, ok := vals[v]; !ok {
				return 0, fmt.Errorf("cvss: invalid value %s:%s", k, truncate(v))
			}
		} else if allowed, other := otherMetrics[k]; !other || len(v) != 1 || !strings.Contains(allowed, v) {
			return 0, fmt.Errorf("cvss: unknown metric %s:%s", truncate(k), truncate(v))
		}
		m[k] = v
	}
	for k := range baseMetrics {
		if _, ok := m[k]; !ok {
			return 0, fmt.Errorf("cvss: missing base metric %s", k)
		}
	}

	changed := m["S"] == "C"
	pr := baseMetrics["PR"][m["PR"]]
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	}
	iss := 1 - (1-baseMetrics["C"][m["C"]])*(1-baseMetrics["I"][m["I"]])*(1-baseMetrics["A"][m["A"]])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * baseMetrics["AV"][m["AV"]] * baseMetrics["AC"][m["AC"]] * pr * baseMetrics["UI"][m["UI"]]
	if impact <= 0 {
		return 0, nil
	}
	roundup := roundup31
	if ver == "CVSS:3.0" {
		roundup = roundup30
	}
	if changed {
		return roundup(math.Min(1.08*(impact+exploitability), 10)), nil
	}
	return roundup(math.Min(impact+exploitability, 10)), nil
}

// roundup31 is the v3.1 Roundup: the smallest one-decimal number >= x,
// computed in integers to avoid floating-point surprises (spec appendix A).
func roundup31(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}

// roundup30 is the v3.0 definition: round up to one decimal place.
func roundup30(x float64) float64 { return math.Ceil(x*10) / 10 }

// Rating maps a score to its qualitative severity.
func Rating(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score >= 0.1:
		return "low"
	}
	return "none"
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}
