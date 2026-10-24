// SPDX-License-Identifier: AGPL-3.0-or-later

package findings

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/chrisreedio/heimdall/internal/feeds/news"
	"github.com/chrisreedio/heimdall/internal/netx"
	"github.com/chrisreedio/heimdall/internal/store"
)

// NewsSyncer fetches the configured threat-news feeds and keeps the
// confirmed matches (incident CVE = open finding) current. A failing
// source keeps its last good copy and never affects other syncs.
type NewsSyncer struct {
	Store   *store.Store
	HTTP    *netx.Client // allowlisted to the sources' hosts
	Sources []string
	Now     func() time.Time
	Log     *slog.Logger
}

// Run fetches every source, records the "news" feed status, prunes old
// closed incidents and recomputes matches for every host.
func (n *NewsSyncer) Run(ctx context.Context) error {
	start := n.Now()
	var errs []error
	if removed, err := n.Store.DeleteNewsExcept(ctx, n.Sources); err != nil {
		errs = append(errs, err)
	} else if removed > 0 {
		n.Log.Info("news from removed sources deleted", "count", removed)
	}
	for _, src := range n.Sources {
		if err := n.syncSource(ctx, src); err != nil {
			n.Log.Warn("news source failed", "source", src, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", src, err))
		}
	}
	if pruned, err := n.Store.PruneNews(ctx, n.Now().Add(-store.NewsRetention)); err != nil {
		errs = append(errs, err)
	} else if pruned > 0 {
		n.Log.Info("old news pruned", "count", pruned)
	}
	if err := n.Store.MatchNews(ctx, 0, n.Now()); err != nil {
		errs = append(errs, err)
	}
	err := errors.Join(errs...)
	if recErr := n.Store.RecordFeedRun(ctx, "news", start, err); recErr != nil {
		err = errors.Join(err, recErr)
	}
	if err == nil {
		n.Log.Info("feed synced", "feed", "news", "took", n.Now().Sub(start).Round(time.Millisecond))
	}
	return err
}

func (n *NewsSyncer) syncSource(ctx context.Context, src string) error {
	etag, lm, err := n.Store.NewsValidators(ctx, src)
	if err != nil {
		return err
	}
	feed, next, err := news.Fetch(ctx, n.HTTP, src, news.Validators{ETag: etag, LastModified: lm})
	if err != nil {
		return err
	}
	if feed == nil {
		return n.Store.TouchNewsSource(ctx, src, n.Now())
	}
	// Closed incidents past retention would only be pruned again.
	cutoff := n.Now().Add(-store.NewsRetention)
	items := make([]store.NewsItem, 0, len(feed.Items))
	for _, it := range feed.Items {
		if it.Status == "closed" && closedAt(it).Before(cutoff) {
			continue
		}
		items = append(items, store.NewsItem{
			Source: src, Slug: it.Slug, Category: it.Category, Title: it.Title, URL: it.URL,
			Severity: it.Severity, PatchStatus: it.PatchStatus, Status: it.Status, Product: it.Product,
			Stacks: it.Stacks, Tags: it.Tags, CVEs: it.CVEs, Affected: it.Affected, Fixed: it.Fixed,
			Summary: it.Summary, StartedAt: it.StartedAt, UpdatedAt: it.UpdatedAt, ClosedAt: it.ClosedAt,
		})
	}
	removed, err := n.Store.ReplaceNews(ctx, src, items, next.ETag, next.LastModified, n.Now())
	if err != nil {
		return err
	}
	n.Log.Info("news fetched", "source", src, "kept", len(items), "removed", removed,
		"dropped", feed.Dropped, "ignored_ids", feed.IgnoredIDs)
	return nil
}

func closedAt(it news.Item) time.Time {
	if it.ClosedAt != nil {
		return *it.ClosedAt
	}
	return it.UpdatedAt
}

// MatchHost recomputes one host's matches after its findings changed.
// A nil syncer (news off) does nothing.
func (n *NewsSyncer) MatchHost(ctx context.Context, hostID int64) error {
	if n == nil {
		return nil
	}
	return n.Store.MatchNews(ctx, hostID, n.Now())
}

// MatchAll recomputes every host's matches (after a full findings sync).
func (n *NewsSyncer) MatchAll(ctx context.Context) error {
	if n == nil {
		return nil
	}
	return n.Store.MatchNews(ctx, 0, n.Now())
}
