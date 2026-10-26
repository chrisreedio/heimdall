// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"sync"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

// navPerm is which sidebar items the viewer may see. The pages check
// access themselves; this only hides links that would end in a 403.
type navPerm struct {
	Admin    bool // global admin: Users
	OrgAdmin bool // admin somewhere: IP addresses
	Operator bool // operator somewhere: Bans, Surface, Cloudflare
	AnyRole  bool // a role anywhere: Offenders
}

func navPermOf(v *auth.Viewer) navPerm {
	p := navPerm{Admin: v.IsAdmin, OrgAdmin: v.IsAdmin, Operator: v.IsAdmin, AnyRole: v.IsAdmin}
	for _, r := range v.Scope.Orgs {
		p.AnyRole = true
		p.OrgAdmin = p.OrgAdmin || r.AtLeast(store.RoleAdmin)
		p.Operator = p.Operator || r.AtLeast(store.RoleOperator)
	}
	return p
}

// navCounts are the sidebar's badges.
type navCounts struct {
	Urgent    int // hosts with known-exploited or critical/high fixable findings
	Anomalies int // open anomalies
	High      bool
}

// navTTL is how long a viewer's badges are reused. They're a glance, not a
// live view: counting means building the fleet report, so it happens at
// most once a minute per user, whatever they click.
const navTTL = time.Minute

type navCache struct {
	mu   sync.Mutex
	byID map[int64]navEntry
}

type navEntry struct {
	at time.Time
	c  navCounts
}

// forget drops a user's cached badges, after they change what's counted.
func (c *navCache) forget(userID int64) {
	c.mu.Lock()
	delete(c.byID, userID)
	c.mu.Unlock()
}

func (s *server) navCountsFor(r *http.Request, v *auth.Viewer) navCounts {
	now := s.now()
	s.nav.mu.Lock()
	e, ok := s.nav.byID[v.UserID]
	s.nav.mu.Unlock()
	if ok && now.Sub(e.at) < navTTL {
		return e.c
	}
	var c navCounts
	if hosts, err := s.fleet(r, v, ""); err == nil {
		for _, h := range hosts {
			if h.R.Counts.KEV > 0 || h.R.Counts.FixUrgent > 0 {
				c.Urgent++
			}
		}
	} else {
		s.log.Warn("sidebar counts: hosts", "err", err)
	}
	if as, err := s.st.OpenAnomalies(r.Context(), v.Scope); err == nil {
		c.Anomalies = len(as)
		for _, a := range as {
			c.High = c.High || a.Severity == "high"
		}
	} else {
		s.log.Warn("sidebar counts: anomalies", "err", err)
	}
	s.nav.mu.Lock()
	if s.nav.byID == nil || len(s.nav.byID) > 1000 {
		s.nav.byID = map[int64]navEntry{}
	}
	s.nav.byID[v.UserID] = navEntry{at: now, c: c}
	s.nav.mu.Unlock()
	return c
}
