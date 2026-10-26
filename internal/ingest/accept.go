// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ingest accepts snapshots from collectors (HTTP push) and from
// `heimdall import`, applying the same validation and tripwires to both.
package ingest

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/realmwatch/heimdall/internal/snapshot"
	"github.com/realmwatch/heimdall/internal/store"
)

const (
	// RetryWindow: a payload seen again within this window is a network
	// retry and gets an idempotent success. Later, it's a replay.
	RetryWindow = 10 * time.Minute
	// MaxSkew is how far collected_at may be from the time received.
	MaxSkew = 15 * time.Minute
)

// Result is the outcome of accepting a snapshot.
type Result struct {
	Status     int // HTTP status code
	Message    string
	SnapshotID int64
	// Unchanged: the inventory matched the host's latest snapshot, so the
	// report was stored as a heartbeat (SnapshotID is that snapshot).
	Unchanged bool
	Snapshot  *snapshot.Snapshot // nil if decoding failed
	Anomalies []store.Anomaly
}

type Accepter struct {
	Store *store.Store
	Now   func() time.Time
}

// Accept validates raw and stores it for host. The returned error is for
// unexpected (server-side) failures only; rejections are reported in Result.
func (a *Accepter) Accept(ctx context.Context, host store.IngestHost, source string, raw []byte) (Result, error) {
	now := a.Now()
	snap, err := snapshot.DecodeBytes(raw)
	if err != nil {
		return Result{Status: http.StatusUnprocessableEntity, Message: err.Error()}, nil
	}
	hash := sha256.Sum256(raw)

	_, prior, found, err := a.Store.SnapshotByPayload(ctx, host.ID, hash)
	if err != nil {
		return Result{}, err
	}
	if found {
		if now.Sub(prior) < RetryWindow {
			return Result{Status: http.StatusOK, Message: "already stored", Snapshot: snap}, nil
		}
		replay := store.Anomaly{
			Rule: "replay", Severity: "high",
			Summary: fmt.Sprintf("A snapshot first received %s was sent again", prior.UTC().Format(time.RFC3339)),
			Detail:  map[string]any{"first_received_at": prior.UTC().Format(time.RFC3339), "source": source},
		}
		if err := a.Store.RecordAnomaly(ctx, host.ID, now, replay); err != nil {
			return Result{}, err
		}
		return Result{Status: http.StatusConflict, Message: "replayed snapshot rejected", Snapshot: snap,
			Anomalies: []store.Anomaly{replay}}, nil
	}

	var anomalies []store.Anomaly
	if skew := clockSkew(snap.CollectedAt, now, source); skew != nil {
		anomalies = append(anomalies, *skew)
	}

	saved, err := a.Store.SaveReport(ctx, store.NewSnapshot{
		Host: host, Source: source, ReceivedAt: now, PayloadSHA256: hash, Snapshot: snap,
	}, anomalies)
	if errors.Is(err, store.ErrExists) { // lost a race with an identical retry
		return Result{Status: http.StatusOK, Message: "already stored", Snapshot: snap}, nil
	}
	if err != nil {
		return Result{}, err
	}
	if saved.Unchanged {
		return Result{Status: http.StatusOK, Message: "unchanged", SnapshotID: saved.SnapshotID, Unchanged: true,
			Snapshot: snap, Anomalies: anomalies}, nil
	}
	return Result{Status: http.StatusCreated, Message: "stored", SnapshotID: saved.SnapshotID, Snapshot: snap, Anomalies: anomalies}, nil
}

// Check validates raw without storing anything (`heimdall import --check`).
func (a *Accepter) Check(raw []byte) (*snapshot.Snapshot, error) {
	return snapshot.DecodeBytes(raw)
}

// clockSkew flags a collected_at that is implausibly far from now. Imports
// are expected to be old, so only future timestamps are flagged for them.
func clockSkew(collected, now time.Time, source string) *store.Anomaly {
	skew := now.Sub(collected) // positive: collected in the past
	future := skew < -MaxSkew
	stale := source == "push" && skew > MaxSkew
	if !future && !stale {
		return nil
	}
	dir := "behind"
	if future {
		dir = "ahead of"
	}
	return &store.Anomaly{
		Rule: "clock_skew", Severity: "medium",
		Summary: fmt.Sprintf("Host clock is %s %s the hub's", skew.Abs().Round(time.Second), dir),
		Detail: map[string]any{
			"collected_at": collected.UTC().Format(time.RFC3339),
			"received_at":  now.UTC().Format(time.RFC3339),
			"skew_seconds": int64(skew.Seconds()),
		},
	}
}
