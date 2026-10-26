// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
)

func TestIPCommands(t *testing.T) {
	c := newCLI(t)
	c.ok("init")
	c.ok("migrate")
	c.ok("org", "create", "acme")

	id := strings.TrimSpace(c.ok("ip", "label", "add", "--kind", "staff", "--name", "Office", "--person", "alice@example.com", "203.0.113.0/24"))
	c.ok("ip", "label", "add", "--all-orgs", "--kind", "automation", "--name", "CI runners", "198.51.100.7")
	if _, _, err := c.run("ip", "label", "add", "--kind", "unknown", "--name", "x", "203.0.113.1"); err == nil {
		t.Error("a label of kind unknown was accepted")
	}
	if _, _, err := c.run("ip", "label", "add", "--kind", "staff", "--name", "x", "not-an-ip"); err == nil {
		t.Error("a bad address was accepted")
	}
	out := c.ok("ip", "label", "list")
	for _, want := range []string{"203.0.113.0/24", "acme", "alice@example.com", "198.51.100.7/32", "(all)", "manual"} {
		if !strings.Contains(out, want) {
			t.Errorf("label list missing %q:\n%s", want, out)
		}
	}
	if out := c.ok("ip", "label", "list", "--org", "acme"); !strings.Contains(out, "CI runners") {
		t.Errorf("an org's list should include every-org labels:\n%s", out)
	}

	out = c.ok("ip", "show", "203.0.113.9")
	for _, want := range []string{"kind     staff", "best     Office (alice@example.com)", "manual", "203.0.113.0/24"} {
		if !strings.Contains(out, want) {
			t.Errorf("ip show missing %q:\n%s", want, out)
		}
	}
	if out := c.ok("ip", "show", "100.100.1.2"); !strings.Contains(out, "kind     tailnet") {
		t.Errorf("ip show tailnet:\n%s", out)
	}
	if out := c.ok("ip", "show", "192.0.2.1"); !strings.Contains(out, "kind     unknown") || !strings.Contains(out, "ip label add") {
		t.Errorf("ip show unknown:\n%s", out)
	}

	c.ok("ip", "label", "rm", id)
	if out := c.ok("ip", "label", "list"); strings.Contains(out, "203.0.113.0/24") {
		t.Errorf("label not removed:\n%s", out)
	}
	if _, _, err := c.run("ip", "label", "rm", id); err == nil {
		t.Error("removing a removed label should fail")
	}

	if out := c.ok("ip", "policy"); !strings.Contains(out, "tailnet-only    off") || !strings.Contains(out, "allow-services  on") {
		t.Errorf("default policy:\n%s", out)
	}
	if out := c.ok("ip", "policy", "--org", "acme", "--tailnet-only", "on"); !strings.Contains(out, "tailnet-only    on") || !strings.Contains(out, "allow-services  on") {
		t.Errorf("policy on:\n%s", out)
	}
	if out := c.ok("ip", "policy", "--allow-services", "off"); !strings.Contains(out, "tailnet-only    on") || !strings.Contains(out, "allow-services  off") {
		t.Errorf("allow-services off:\n%s", out)
	}
	if out := c.ok("ip", "policy"); !strings.Contains(out, "count-services  off") {
		t.Errorf("count-services default:\n%s", out)
	}
	if out := c.ok("ip", "policy", "--count-services", "on"); !strings.Contains(out, "count-services  on") || !strings.Contains(out, "allow-services  off") {
		t.Errorf("count-services on:\n%s", out)
	}
	if _, _, err := c.run("ip", "policy", "--tailnet-only", "maybe"); err == nil {
		t.Error("a bad policy value was accepted")
	}
}
