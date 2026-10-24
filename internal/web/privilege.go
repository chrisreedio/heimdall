// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"time"

	"github.com/chrisreedio/heimdall/internal/privilege"
)

// privilegeView is the host page's "Privileged access" line. It's nil for
// hosts that never turned the privilege watch on.
type privilegeView struct {
	Counts string     // "3 sudo, 1 root SSH", or "" for none
	Last   *time.Time // newest event, nil if none
	Off    bool       // the watch was on and isn't now
	State  string
	Recent []privilegeEvent // newest first, when the server records who
}

type privilegeEvent struct {
	At   time.Time
	Kind string // "sudo", "root SSH"
	Who  string // "chris from 203.0.113.7"
}

// recentPrivilege is how many events the host page lists.
const recentPrivilege = 8

func (s *server) privilegeFor(ctx context.Context, hostID int64) (*privilegeView, error) {
	sum, err := s.st.PrivilegeSummary(ctx, hostID, s.now().Add(-24*time.Hour))
	if err != nil || (!sum.EverOn && sum.Last.IsZero()) {
		return nil, err
	}
	v := &privilegeView{Counts: privilege.Counts(sum.Counts), State: sum.State,
		Off: sum.EverOn && sum.State != "on"}
	if !sum.Last.IsZero() {
		v.Last = &sum.Last
	}
	evs, err := s.st.RecentPrivilege(ctx, hostID, recentPrivilege)
	if err != nil {
		return nil, err
	}
	for _, ev := range evs {
		if ev.User != "" || ev.Source != "" {
			v.Recent = append(v.Recent, privilegeEvent{At: ev.At, Kind: privilege.KindLabel(ev.Kind), Who: privilege.Who(ev)})
		}
	}
	return v, nil
}
