// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"slices"

	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/version"
)

// supportSoonDays is how close a runtime's end of life must be before the
// host page shows the date: further out, it's only in the tooltip.
const supportSoonDays = 365

// runtimeGroup is one runtime on the host page, with every version of it
// installed, newest first.
type runtimeGroup struct {
	Name     string
	Versions []report.Runtime
	Unused   int // PHP versions nothing uses
}

// runtimeGroups groups a host's runtimes by name, in the order the report
// lists them.
func runtimeGroups(rts []report.Runtime) []runtimeGroup {
	var out []runtimeGroup
	at := map[string]int{}
	for _, rt := range rts {
		i, ok := at[rt.Name]
		if !ok {
			i = len(out)
			at[rt.Name] = i
			out = append(out, runtimeGroup{Name: rt.Name})
		}
		g := &out[i]
		g.Versions = append(g.Versions, rt)
		if rt.Use != nil && rt.Use.Unused {
			g.Unused++
		}
	}
	for i := range out {
		slices.SortStableFunc(out[i].Versions, func(a, b report.Runtime) int {
			return version.CompareDpkg(b.Version, a.Version)
		})
	}
	return out
}

// supportState is lifeState with a wider "soon": a year rather than 90
// days, so a runtime's date shows while there's time to plan the move.
func supportState(l *report.Lifecycle) string {
	s := lifeState(l)
	if s == "ok" && l.EOLDate != nil && l.DaysLeft <= supportSoonDays {
		return "soon"
	}
	return s
}
