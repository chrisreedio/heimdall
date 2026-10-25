// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
	"time"
)

func TestBansConfig(t *testing.T) {
	c, err := parse(Template("h.db"))
	if err != nil || c.Validate() != nil {
		t.Fatalf("template: %v %v", err, c.Validate())
	}
	b := c.Bans
	if b.Mode != BansOff || b.On() || b.Writes() || b.Duration.Duration != 7*24*time.Hour || b.MaxDuration.Duration != 90*24*time.Hour ||
		b.MaxPerHour != 20 || b.BlockHosts != 3 || !b.BlockSucceeded || b.Weights.Succeeded != 10 || b.ChallengeList != "heimdall_challenge" {
		t.Errorf("defaults %+v", b)
	}
	c, err = parse([]byte("[bans]\nmode = \"shadow\"\npropose_at = 8.5\n[bans.weights]\nhosts = 3.0\n"))
	if err != nil || c.Validate() != nil || !c.Bans.On() || c.Bans.Writes() || c.Bans.ProposeAt != 8.5 || c.Bans.Weights.Hosts != 3 || c.Bans.Weights.Failures != 1 {
		t.Fatalf("shadow: %+v %v %v", c.Bans, err, c.Validate())
	}
	// Writing modes need Cloudflare's sync for the zones.
	c, _ = parse([]byte("[bans]\nmode = \"propose\"\n"))
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "needs [cloudflare]") {
		t.Errorf("propose without cloudflare: %v", err)
	}
	c, _ = parse([]byte("[cloudflare]\nenabled = true\n[bans]\nmode = \"auto\"\naccount_id = \"0123456789abcdef0123456789abcdef\"\n"))
	if err := c.Validate(); err != nil || !c.Bans.Writes() {
		t.Errorf("auto: %v", err)
	}
	for _, bad := range []string{`mode = "yolo"`, `account_id = "nope"`, `max_per_hour = 0`, `duration = "10m"`,
		`max_duration = "1h"`, `block_list = "heimdall_challenge"`, `challenge_list = "Has-Caps"`, "propose_at = 0.0", "weights.hosts = -1.0"} {
		src := "[bans]\n" + bad + "\n"
		if strings.HasPrefix(bad, "weights.") {
			src = "[bans.weights]\n" + strings.TrimPrefix(bad, "weights.") + "\n"
		}
		c, err := parse([]byte(src))
		if err == nil && c.Validate() == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	// `config update` adds [bans] and its weights, off.
	old := strings.Replace(string(Template("h.db")), bansTemplate, "", 1)
	secs, err := MissingSections([]byte(old))
	if err != nil || len(secs) != 2 || secs[0].Name != "bans" || secs[1].Name != "bans.weights" {
		t.Fatalf("missing sections: %+v %v", secs, err)
	}
	c, err = parse(AppendSections([]byte(old), secs, "test"))
	if err != nil || c.Bans.Mode != BansOff || c.Validate() != nil {
		t.Errorf("updated: %+v %v", c.Bans, err)
	}
}
