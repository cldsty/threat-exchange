// Package ratelimit implements an in-memory, per-key token bucket rate
// limiter.
//
// Each key (client IP or API key ID) gets its own bucket that refills at
// Rate tokens per second up to Burst tokens. Buckets are kept in
// least-recently-used order, so all bookkeeping is O(1) per request even under
// a flood of new keys. Idle buckets are evicted after IdleTTL, and the number
// of tracked keys is capped so that an attacker rotating source addresses
// cannot exhaust memory: when the cap is reached and no bucket is idle, new
// keys share a single overflow bucket.
//
// The state is local to a process. For several replicas behind a load
// balancer a shared store (e.g. Redis) or limiting at the gateway would be
// required; see docs/security.md.
package ratelimit

import (
	"container/list"
	"context"
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Config configures a Limiter.
type Config struct {
	// Rate is the sustained number of requests per second per key.
	Rate float64
	// Burst is the maximum number of requests allowed at once.
	Burst int
	// IdleTTL is how long an unused bucket is kept.
	IdleTTL time.Duration
	// MaxKeys caps the number of tracked keys.
	MaxKeys int
}

const overflowKey = "\x00overflow"

// Limiter is safe for concurrent use.
type Limiter struct {
	cfg     Config
	now     func() time.Time
	mu      sync.Mutex
	buckets map[string]*list.Element
	// lru orders buckets from the most (front) to the least recently used.
	lru *list.List
}

type bucket struct {
	key      string
	lim      *rate.Limiter
	lastSeen time.Time
}

// New creates a Limiter. Zero values in cfg are replaced with defaults.
func New(cfg Config) *Limiter {
	return newWithClock(cfg, time.Now)
}

func newWithClock(cfg Config, now func() time.Time) *Limiter {
	if cfg.Burst <= 0 {
		cfg.Burst = 1
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 10 * time.Minute
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = 100_000
	}
	return &Limiter{cfg: cfg, now: now, buckets: make(map[string]*list.Element), lru: list.New()}
}

// Allow consumes one token for key. When the request is not allowed it
// returns false and how long the client should wait before retrying.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	now := l.now()

	l.mu.Lock()
	b := l.bucketLocked(key, now)
	b.lastSeen = now
	r := b.lim.ReserveN(now, 1)
	l.mu.Unlock()

	if !r.OK() {
		return false, time.Second
	}
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, d
	}
	return true, 0
}

// bucketLocked returns the bucket for key, marking it as the most recently
// used and creating it if needed.
func (l *Limiter) bucketLocked(key string, now time.Time) *bucket {
	if e, ok := l.buckets[key]; ok {
		l.lru.MoveToFront(e)
		b, _ := e.Value.(*bucket)
		return b
	}
	if len(l.buckets) >= l.cfg.MaxKeys {
		// Only the least recently used bucket can be idle, so a single check
		// is enough to know whether there is room.
		l.evictOldestIfIdleLocked(now)
	}
	if len(l.buckets) >= l.cfg.MaxKeys {
		key = overflowKey
		if e, ok := l.buckets[key]; ok {
			l.lru.MoveToFront(e)
			b, _ := e.Value.(*bucket)
			return b
		}
	}
	b := &bucket{key: key, lim: rate.NewLimiter(rate.Limit(l.cfg.Rate), l.cfg.Burst)}
	l.buckets[key] = l.lru.PushFront(b)
	return b
}

// RetryAfterSeconds converts a wait duration to a Retry-After header value
// (whole seconds, at least 1).
func RetryAfterSeconds(d time.Duration) int {
	return max(1, int(math.Ceil(d.Seconds())))
}

// Cleanup removes buckets that have been idle for longer than IdleTTL.
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for l.evictOldestIfIdleLocked(now) {
		continue
	}
}

// Len returns the number of tracked keys.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Run periodically evicts idle buckets until ctx is cancelled.
func (l *Limiter) Run(ctx context.Context) {
	t := time.NewTicker(l.cfg.IdleTTL / 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.Cleanup()
		}
	}
}

func (l *Limiter) evictOldestIfIdleLocked(now time.Time) bool {
	e := l.lru.Back()
	if e == nil {
		return false
	}
	b, _ := e.Value.(*bucket)
	if now.Sub(b.lastSeen) <= l.cfg.IdleTTL {
		return false
	}
	l.lru.Remove(e)
	delete(l.buckets, b.key)
	return true
}
