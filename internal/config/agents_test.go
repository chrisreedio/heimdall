// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
)

func TestAgentsConfig(t *testing.T) {
	if c, err := parse(Template("h.db")); err != nil || len(c.Agents) != 0 {
		t.Fatalf("agents should be off by default: %+v %v", c.Agents, err)
	}
	c, err := parse([]byte(`
[[agents]]
name = "pr-bot"
discord_user_id = "123456789012345678"
destination = "discord:agents"

[[agents]]
name = "other-bot"
discord_user_id = "98765432109876543"
destination = "discord:agents"
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil || len(c.Agents) != 2 || !c.AgentUsesDestination("discord:agents") || c.AgentUsesDestination("discord:alerts") {
		t.Fatalf("agents: %+v %v", c.Agents, err)
	}
	for _, bad := range []Agent{
		{Name: "Pr Bot", DiscordUserID: "123456789012345678", Destination: "discord:agents"},
		{Name: "pr-bot", DiscordUserID: "1234", Destination: "discord:agents"},
		{Name: "pr-bot", DiscordUserID: "<@123456789012345678>", Destination: "discord:agents"},
		{Name: "pr-bot", DiscordUserID: "123456789012345678", Destination: "slack:agents"},
		{Name: "pr-bot", DiscordUserID: "123456789012345678", Destination: "https://discord.com/api/webhooks/1/x"},
	} {
		c := Default()
		c.Agents = []Agent{bad}
		if err := c.Validate(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	c = Default()
	a := Agent{Name: "pr-bot", DiscordUserID: "123456789012345678", Destination: "discord:agents"}
	c.Agents = []Agent{a, a}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate agent: %v", err)
	}
}
