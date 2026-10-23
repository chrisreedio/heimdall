// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

func sampleReport() *Report {
	yes, no := true, false
	eolDate := time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)
	return &Report{
		GeneratedAt: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC),
		Hosts: []Host{{
			Org: "acme", Name: "web-01", OS: "Ubuntu 22.04", LastSeen: time.Date(2026, 10, 22, 4, 0, 0, 0, time.UTC),
			OSLife: &Lifecycle{Product: "ubuntu", Cycle: "22.04", Known: true},
			Counts: Counts{Total: 2, KEV: 1, High: 1, Critical: 1, Fixable: 2},
			Findings: []Finding{
				{Advisory: "USN-1-1", CVEs: []string{"CVE-2024-1"}, Severity: "critical", CVSS: 9.8, KEV: true,
					Package: "openssl", Version: "3.0.2", Fixed: "3.0.3", FixPending: true, Summary: "<script>alert(1)</script>"},
				{Advisory: "=HYPERLINK(\"http://evil\")", Severity: "high", Package: "@evil/pkg", Version: "1.0",
					Fixed: "1.1", Site: "/home/forge/example.com", EPSS: 0.12345},
			},
			Sites: []Site{{Root: "/home/forge/example.com", ServerNames: []string{"example.com"}, Readable: true,
				PHPFPM: "8.1", PHPLife: &Lifecycle{Product: "php", Cycle: "8.1", Known: true, EOL: true, EOLDate: &eolDate},
				PHPRequirement: "^8.2", PHPSatisfied: &no, Framework: "laravel", FrameworkVersion: "11.31.0",
				Counts: Counts{Total: 1, Fixable: 1}}},
		}, {
			Org: "acme", Name: "db-01", OS: "Rocky Linux 9", Sites: []Site{{Root: "/srv/app", PHPSatisfied: &yes}},
		}},
	}
}

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want header + 2", len(rows))
	}
	if strings.Join(rows[0], ",") != strings.Join(csvHeader, ",") {
		t.Errorf("header = %v", rows[0])
	}
	os := rows[1]
	if os[1] != "web-01" || os[3] != "" || os[5] != "CVE-2024-1" || os[7] != "9.8" || os[9] != "true" || os[14] != "true" {
		t.Errorf("OS row = %v", os)
	}
	site := rows[2]
	if site[3] != "/home/forge/example.com" || site[8] != "0.12345" {
		t.Errorf("site row = %v", site)
	}
	// Formula injection is neutralized.
	if site[4] != `'=HYPERLINK("http://evil")` || site[11] != "'@evil/pkg" {
		t.Errorf("injection not neutralized: %q %q", site[4], site[11])
	}
}

func TestWriteHTML(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleReport(), "Acme <patch> report"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(strings.ToLower(out), "<script") {
		t.Fatal("report must contain no script, even from hostile data")
	}
	for _, want := range []string{
		"&lt;script&gt;alert(1)&lt;/script&gt;", "Acme &lt;patch&gt; report",
		"web-01", "db-01", "/home/forge/example.com", "/srv/app",
		"does not satisfy ^8.2", "END OF LIFE", "KEV", "@media print", "</html>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}
