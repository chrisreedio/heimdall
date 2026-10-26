// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/store"
)

func TestOffendersCommand(t *testing.T) {
	c := newCLI(t)
	c.ok("init")
	c.ok("migrate")
	c.ok("org", "create", "acme")
	c.ok("env", "create", "--org", "acme", "prod")
	c.ok("host", "add", "--org", "acme", "--env", "prod", "web-01")
	c.ok("ip", "label", "add", "--kind", "staff", "--name", "Office", "198.51.100.4")

	cfg, err := config.Load(c.config)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(t.Context(), cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.HostByName(t.Context(), "acme", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	day := store.LoginDay{Day: at.Format(time.DateOnly), Failures: 12, Addresses: 2, Rows: []store.LoginFailure{
		{IP: "203.0.113.9", Failures: 9, Usernames: 4, First: at, Last: at, Succeeded: true},
		{IP: "198.51.100.4", Failures: 3, Usernames: 1, First: at, Last: at},
	}}
	if err := s.RecordLogins(t.Context(), h.ID, store.LoginReport{Source: "journal", Days: []store.LoginDay{day}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	s.Close()

	out := c.ok("offenders")
	if !strings.Contains(out, "203.0.113.9") || !strings.Contains(out, "THEN SUCCEEDED: acme/web-01") || strings.Contains(out, "198.51.100.4") {
		t.Errorf("offenders:\n%s", out)
	}
	var list []offenderJSON
	if err := json.Unmarshal([]byte(c.ok("offenders", "--json", "--since", "7d", "--org", "acme")), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].IP != "203.0.113.9" || list[0].Failures != 9 || list[0].Usernames != 4 ||
		len(list[0].Hosts) != 1 || list[0].Hosts[0] != "acme/web-01" || len(list[0].Succeeded) != 1 {
		t.Errorf("--json = %+v", list)
	}
	for _, bad := range [][]string{{"offenders", "--since", "90d"}, {"offenders", "--since", "soon"}, {"offenders", "--org", "nope"}} {
		if _, _, err := c.run(bad...); err == nil {
			t.Errorf("%v: no error", bad)
		}
	}
}
