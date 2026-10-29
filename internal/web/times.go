// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"html"
	"html/template"
	"time"
)

// Times on the pages: the server writes every instant in UTC, and
// app.js rewrites the visible ones into the viewer's time zone, named
// ("2:14 PM CDT"), from a <time data-ts> element. Tooltips stay in UTC.
// Without JavaScript the UTC text stands, labelled. Plain dates (a
// lifecycle's end, stored as midnight UTC) aren't instants and aren't
// converted.

// utcText is an instant as the tooltips show it: "Oct 29, 2026 7:14 PM UTC".
func utcText(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("Jan 2, 2006 3:04 PM") + " UTC"
}

// localTime is text about instant t that app.js redraws in the viewer's
// time zone. kind is how: "datetime" (Oct 29, 2026 2:14 PM CDT), "date"
// (Oct 29, 2026) or "dayago" (dayAgo's wording).
func localTime(t time.Time, kind, text string) template.HTML {
	return template.HTML(`<time datetime="` + t.UTC().Format(time.RFC3339) + `" data-ts="` + kind +
		`" title="` + html.EscapeString(utcText(t)) + `">` + html.EscapeString(text) + `</time>`)
}

// tsHTML is an instant's date and time, in the viewer's time zone.
func tsHTML(t time.Time) template.HTML {
	if t.IsZero() {
		return "never"
	}
	return localTime(t, "datetime", utcText(t))
}

// dateHTML is the day an instant falls on, in the viewer's time zone.
func dateHTML(t time.Time) template.HTML {
	return localTime(t, "date", t.UTC().Format("Jan 2, 2006"))
}

// dayAgoHTML is dayAgo, redrawn in the viewer's time zone (which decides
// what "today" is). Plain dates have no time zone and stay as they are.
func dayAgoHTML(t *time.Time, now time.Time) template.HTML {
	if t == nil {
		return ""
	}
	if isPlainDate(*t) {
		return template.HTML(html.EscapeString(dayAgo(t, now)))
	}
	return localTime(*t, "dayago", dayAgo(t, now))
}
