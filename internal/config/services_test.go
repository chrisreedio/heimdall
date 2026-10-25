// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"slices"
	"strings"
	"testing"
)

func TestDeployServicesDefaults(t *testing.T) {
	// Forge and Ploi with no section at all (hubs installed before it).
	cfg, err := parse([]byte("database = \"h.db\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.DeployServices.Services, []string{"forge", "ploi"}) || len(cfg.DeployServices.Custom) != 0 {
		t.Errorf("defaults = %+v", cfg.DeployServices)
	}
	// The template says the same.
	tpl, err := parse(Template("heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tpl.DeployServices.Services, cfg.DeployServices.Services) {
		t.Errorf("template = %v", tpl.DeployServices.Services)
	}
	// A list replaces the default; an empty one turns them all off.
	for src, want := range map[string][]string{
		"[deploy_services]\nservices = [\"forge\", \"buddy-eu\"]\n": {"forge", "buddy-eu"},
		"[deploy_services]\nservices = []\n":                        {},
	} {
		c, err := parse([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(c.DeployServices.Services, want) {
			t.Errorf("%q: %v", src, c.DeployServices.Services)
		}
		if err := c.Validate(); err != nil {
			t.Errorf("%q: %v", src, err)
		}
	}
}

func TestDeployServicesCustom(t *testing.T) {
	c, err := parse([]byte(`
[deploy_services]
services = ["forge"]
[[deploy_services.custom]]
name  = "Acme Deploy"
cidrs = ["203.0.113.10", "198.51.100.0/28", "2001:db8::/48"]
users = ["deploy", "ci_bot"]
[[deploy_services.custom]]
name = "Acme CI"
url  = "https://ci.example.com/ips.txt"
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := c.DeployServices.Custom[0].ID(); got != "custom-acme-deploy" {
		t.Errorf("ID = %q", got)
	}
	if got := (CustomService{Name: "  ACME -- Deploy v2! "}).ID(); got != "custom-acme-deploy-v2" {
		t.Errorf("ID = %q", got)
	}
}

func TestDeployServicesInvalid(t *testing.T) {
	for want, ds := range map[string]DeployServices{
		"isn't a known service": {Services: []string{"heroku"}},
		"listed twice":          {Services: []string{"forge", "forge"}},
		"set cidrs, url":        {Custom: []CustomService{{Name: "x"}}},
		"too broad":             {Custom: []CustomService{{Name: "x", CIDRs: []string{"0.0.0.0/0"}}}},
		"too broad for":         {Custom: []CustomService{{Name: "x", CIDRs: []string{"2000::/3"}}}},
		"isn't an IP":           {Custom: []CustomService{{Name: "x", CIDRs: []string{"forge.example.com"}}}},
		"must be an https":      {Custom: []CustomService{{Name: "x", URL: "http://ci.example.com/ips"}}},
		"isn't a login name":    {Custom: []CustomService{{Name: "x", CIDRs: []string{"203.0.113.1"}, Users: []string{"Root Admin"}}}},
		"1-100 characters":      {Custom: []CustomService{{Name: "!!", CIDRs: []string{"203.0.113.1"}}}},
		"is listed twice":       {Custom: []CustomService{{Name: "A b", CIDRs: []string{"203.0.113.1"}}, {Name: "a-B", CIDRs: []string{"203.0.113.2"}}}},
	} {
		c := Default()
		c.DeployServices = ds
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: want %q, got %v", ds, want, err)
		}
	}
	// /8 is the broadest IPv4 range accepted.
	c := Default()
	c.DeployServices.Custom = []CustomService{{Name: "x", CIDRs: []string{"10.0.0.0/8"}}}
	if err := c.Validate(); err != nil {
		t.Error(err)
	}
}

// `heimdall config update` adds the section to configs written before it.
func TestDeployServicesConfigUpdate(t *testing.T) {
	old := oldTemplate(t, "deploy_services")
	secs, err := MissingSections([]byte(old))
	if err != nil {
		t.Fatal(err)
	}
	if names(secs) != "deploy_services" {
		t.Fatalf("missing = %s", names(secs))
	}
	if strings.Contains(secs[0].Text, "\n[[") {
		t.Error("custom entries must stay commented out")
	}
	cfg, err := parse(AppendSections([]byte(old), secs, "v9.9.9"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.DeployServices.Services, []string{"forge", "ploi"}) {
		t.Errorf("services = %v", cfg.DeployServices.Services)
	}
}
