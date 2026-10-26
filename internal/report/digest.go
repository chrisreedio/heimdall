// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"time"

	"github.com/realmwatch/heimdall/internal/notify"
)

// Digest summarizes a report as counts only (see internal/notify).
// since marks findings as new; staleAfter flags quiet hosts.
func Digest(r *Report, org, url string, since time.Time, staleAfter time.Duration, openAnomalies int) notify.Digest {
	d := notify.Digest{Org: org, GeneratedAt: r.GeneratedAt, URL: url, Hosts: len(r.Hosts), OpenAnomalies: openAnomalies}
	for _, h := range r.Hosts {
		if staleAfter > 0 && r.GeneratedAt.Sub(h.LastSeen) > staleAfter {
			d.Stale++
		}
		eol := h.OSLife != nil && h.OSLife.EOL
		for _, rt := range h.Runtimes {
			eol = eol || (rt.Life != nil && rt.Life.EOL)
		}
		if eol {
			d.EOLHosts++
		}
		d.KEV += h.Counts.KEV
		d.Critical += h.Counts.Critical
		d.High += h.Counts.High
		d.Fixable += h.Counts.Fixable
		for _, f := range h.Findings {
			if !since.IsZero() && f.FirstSeen.After(since) {
				d.NewSinceLast++
			}
		}
		for _, s := range h.Sites {
			if (s.PHPLife != nil && s.PHPLife.EOL) || (s.FrameworkLife != nil && s.FrameworkLife.EOL) ||
				(s.PHPSatisfied != nil && !*s.PHPSatisfied) || s.Counts.KEV > 0 || s.Counts.Critical > 0 {
				d.SitesNeedingAttention++
			}
		}
	}
	return d
}
