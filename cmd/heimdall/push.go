// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/push"
	"github.com/realmwatch/heimdall/internal/store"
)

// pushService is what serve hands the UI (set by startPush).
var pushService *push.Notifier

// startPush starts Web Push notifications to the installed app
// (internal/push, docs/mobile.md#notifications). Nothing is sent until a
// user turns them on for a device, and then only to that browser's push
// service (netx.PushHosts).
func startPush(ctx context.Context, cfg config.Config, s *store.Store, log *slog.Logger) *push.Notifier {
	n := &push.Notifier{
		Store:       s,
		Log:         log.With("component", "push"),
		Now:         time.Now,
		HTTP:        push.NewClient("heimdall/" + version).HTTPClient(),
		Subject:     pushSubject(cfg.UI.BaseURL),
		Version:     version,
		SessionIdle: cfg.UI.SessionIdle.Duration,
		Name: func(ctx context.Context) string {
			if b, err := s.Branding(ctx); err == nil && b.Name != "" {
				return b.Name
			}
			if name := cfg.MCP.Name; name != "" && name != config.DefaultConnectorName {
				return name
			}
			return "Heimdall"
		},
	}
	n.Start(ctx)
	return n
}

// pushSubject is the VAPID contact push services may use about this hub's
// messages: its own https address, or the project's when the UI isn't on
// https (where no browser can subscribe anyway).
func pushSubject(baseURL string) string {
	if strings.HasPrefix(baseURL, "https://") {
		return strings.TrimSuffix(baseURL, "/")
	}
	return "https://github.com/realmwatch/heimdall"
}
