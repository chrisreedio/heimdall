// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
	"time"
)

func TestTailscaleConfig(t *testing.T) {
	if d := Default().Tailscale; d.Enabled || d.Tailnet != "-" || d.SyncEvery.Duration != 15*time.Minute {
		t.Errorf("defaults: %+v", d)
	}
	for _, c := range []struct {
		toml, err string
	}{
		{"[tailscale]\nenabled = true\ntailnet = \"tail1234.ts.net\"\n", ""},
		{"[tailscale]\nenabled = true\ntailnet = \"alice@example.com\"\nsync_every = \"1h\"\n", ""},
		{"[tailscale]\ntailnet = \"bad name/../x\"\n", "tailscale.tailnet"},
		{"[tailscale]\nsync_every = \"10s\"\n", "tailscale.sync_every"},
	} {
		cfg, err := parse([]byte(c.toml))
		if err == nil {
			err = cfg.Validate()
		}
		if c.err == "" && err != nil || c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%q: %v", c.toml, err)
		}
	}
	// An older config gets the section, off, from `heimdall config update`.
	secs, err := MissingSections([]byte("database = \"h.db\"\n"))
	if err != nil || !strings.Contains(names(secs), "tailscale") {
		t.Errorf("missing sections: %s %v", names(secs), err)
	}
}
