// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
	"time"
)

func TestCloudflareConfig(t *testing.T) {
	c, err := parse(Template("h.db"))
	if err != nil || c.Validate() != nil {
		t.Fatalf("template: %v", err)
	}
	cf := c.Cloudflare
	if cf.Enabled || cf.SyncEvery.Duration != time.Hour || !cf.SecurityEvents || !cf.Radar || !cf.ConnectingIP || cf.APIBase != CloudflareAPI || cf.Host() != "api.cloudflare.com" {
		t.Errorf("defaults %+v", cf)
	}
	c, err = parse([]byte("[cloudflare]\nenabled = true\nzones = [\"example.com\", \"0123456789abcdef0123456789abcdef\"]\nsync_every = \"30m\"\n"))
	if err != nil || c.Validate() != nil || len(c.Cloudflare.Zones) != 2 {
		t.Fatalf("valid: %+v %v %v", c.Cloudflare, err, c.Validate())
	}
	for _, bad := range []string{
		"zones = [\"Example.com\"]", "zones = [\"exa mple.com\"]", "sync_every = \"5m\"",
		"api_base = \"http://api.cloudflare.com/client/v4\"", "api_base = \"https://user:pw@api.cloudflare.com\"",
	} {
		c, err := parse([]byte("[cloudflare]\nenabled = true\n" + bad + "\n"))
		if err == nil && c.Validate() == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	// `config update` adds [cloudflare] (off) to an older file.
	old := strings.Replace(string(Template("h.db")), cloudflareTemplate, "", 1)
	secs, err := MissingSections([]byte(old))
	if err != nil || len(secs) != 1 || secs[0].Name != "cloudflare" {
		t.Fatalf("missing sections: %+v %v", secs, err)
	}
	if _, err := parse(AppendSections([]byte(old), secs, "test")); err != nil {
		t.Error(err)
	}
}
