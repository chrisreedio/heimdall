// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"time"
)

var csvHeader = []string{"org", "host", "os", "site", "advisory", "cves", "severity", "cvss", "epss",
	"kev", "kev_ransomware", "package", "installed", "fixed", "fix_pending", "first_seen"}

// WriteCSV writes one row per open finding (OS packages and sites).
// Cells are neutralized against spreadsheet formula injection.
func WriteCSV(w io.Writer, r *Report) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, h := range r.Hosts {
		for _, f := range h.Findings {
			cvss, epss := "", ""
			if f.CVSS > 0 {
				cvss = strconv.FormatFloat(f.CVSS, 'f', 1, 64)
			}
			if f.EPSS > 0 {
				epss = strconv.FormatFloat(f.EPSS, 'f', 5, 64)
			}
			row := []string{h.Org, h.Name, h.OS, f.Site, f.Advisory, strings.Join(f.CVEs, " "), f.Severity, cvss, epss,
				strconv.FormatBool(f.KEV), strconv.FormatBool(f.KEVRansomware), f.Package, f.Version, f.Fixed,
				strconv.FormatBool(f.FixPending), f.FirstSeen.UTC().Format(time.RFC3339)}
			for i := range row {
				row[i] = csvSafe(row[i])
			}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe stops spreadsheets from treating a cell as a formula.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
