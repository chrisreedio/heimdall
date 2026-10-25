// SPDX-License-Identifier: AGPL-3.0-or-later

package ipinfo

import (
	"context"
	"log/slog"
	"time"
)

// Syncer keeps one source's labels current, e.g. by fetching a deploy
// service's published ranges and calling store.ReplaceIPLabels.
type Syncer interface {
	Name() string         // also its labels' source, e.g. "service:forge"
	Every() time.Duration // how often to sync
	Sync(context.Context) error
}

// Run syncs each syncer shortly after start and then on its own schedule,
// each in its own goroutine, until ctx ends. A failing sync is logged and
// retried on schedule; its labels from the last good sync stay.
func Run(ctx context.Context, log *slog.Logger, syncers ...Syncer) {
	for _, s := range syncers {
		go func() {
			first := time.NewTimer(30 * time.Second) // let the hub come up first
			defer first.Stop()
			tick := time.NewTicker(s.Every())
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-first.C:
				case <-tick.C:
				}
				if err := s.Sync(ctx); err != nil {
					log.Warn("IP source sync failed", "source", s.Name(), "err", err)
				} else {
					log.Debug("IP source synced", "source", s.Name())
				}
			}
		}()
	}
}
