// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/handoff"
	"github.com/realmwatch/heimdall/internal/netx"
	"github.com/realmwatch/heimdall/internal/notify"
)

// handoffRetry keeps a hand-off quick: the operator is waiting on the
// page, so one retry and short waits.
var handoffRetry = notify.Retry{Attempts: 2, Base: time.Second, Max: 5 * time.Second}

// handoffClient is the agents' HTTP client: HTTPS to discord.com only.
// A seam for dev builds (handoff_dev.go) and tests.
var handoffClient = func() *netx.Client { return netx.New(netx.DiscordHosts, "heimdall/"+version) }

// handoffAgents builds the configured [[agents]]. One whose webhook can't
// be read is left out and logged, so it never stops the hub or the others.
func handoffAgents(cfg config.Config, log *slog.Logger) []handoff.Agent {
	var out []handoff.Agent
	for _, a := range cfg.Agents {
		kind, name, _ := config.NotifyDestination(a.Destination)
		cred, _ := destCredential(kind, name)
		raw, _, err := credentialFile(cred, "")
		var u string
		if err == nil {
			u, err = notify.DiscordURL(raw)
		}
		if err != nil {
			log.Error("agent left out: its webhook can't be read", "agent", a.Name, "destination", a.Destination,
				"err", fmt.Errorf("%w (store it with `sudo heimdall notify set-webhook discord %s`)", err, name))
			continue
		}
		out = append(out, handoff.Agent{Name: a.Name, UserID: a.DiscordUserID, Poster: &notify.Discord{
			Label: a.Destination, URL: u, Client: handoffClient().HTTPClient(), Retry: handoffRetry}})
	}
	return out
}
