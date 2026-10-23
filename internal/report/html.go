// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"embed"
	"html/template"
	"io"
	"strings"
	"time"
)

//go:embed templates/report.html
var htmlFS embed.FS

var htmlTmpl = template.Must(template.New("report.html").Funcs(template.FuncMap{
	"date": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return t.UTC().Format("2006-01-02 15:04 UTC")
	},
	"day": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.Format(time.DateOnly)
	},
	"join":  strings.Join,
	"deref": func(b *bool) bool { return b != nil && *b },
	"life": func(l *Lifecycle) string {
		if l == nil {
			return "unknown"
		}
		return l.describe()
	},
}).ParseFS(htmlFS, "templates/report.html"))

type htmlData struct {
	Title  string
	Report *Report
	Totals Counts
	Sites  int
}

// WriteHTML writes a self-contained, printable report with no scripts.
func WriteHTML(w io.Writer, r *Report, title string) error {
	d := htmlData{Title: title, Report: r}
	for _, h := range r.Hosts {
		c := h.Counts
		d.Totals.Total += c.Total
		d.Totals.KEV += c.KEV
		d.Totals.Critical += c.Critical
		d.Totals.High += c.High
		d.Totals.Medium += c.Medium
		d.Totals.Low += c.Low
		d.Totals.Unknown += c.Unknown
		d.Totals.Fixable += c.Fixable
		d.Totals.FixPending += c.FixPending
		d.Totals.NoFix += c.NoFix
		d.Sites += len(h.Sites)
	}
	return htmlTmpl.Execute(w, d)
}
