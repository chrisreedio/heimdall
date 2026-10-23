// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"sync"
	"time"
)

// limiter is a token bucket per key. It holds at most maxKeys buckets and
// forgets all of them when full, so a flood of distinct keys (e.g. spoofed
// source IPs) can't exhaust memory; at worst it briefly resets limits.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	maxKeys int
	now     func() time.Time
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(n int, per time.Duration, maxKeys int, now func() time.Time) *limiter {
	return &limiter{
		rate:    float64(n) / per.Seconds(),
		burst:   float64(n),
		maxKeys: maxKeys,
		now:     now,
		buckets: make(map[string]*bucket),
	}
}

// allow consumes a token for key if one is available.
func (l *limiter) allow(key string) bool { return l.take(key, true) }

// exhausted reports whether key has no tokens left, without consuming one.
func (l *limiter) exhausted(key string) bool { return !l.take(key, false) }

func (l *limiter) take(key string, consume bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= l.maxKeys {
			clear(l.buckets)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	if consume {
		b.tokens--
	}
	return true
}
