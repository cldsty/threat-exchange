// Package ratelimit implements an in-memory, per-key token bucket rate
// limiter.
//
// Each key (client IP or API key ID) gets its own bucket that refills at
// Rate tokens per second up to Burst tokens. Idle buckets are evicted after
// IdleTTL, and the number of tracked keys is capped so that an attacker
// rotating source addresses cannot exhaust memory: when the cap is reached,
// new keys share a single overflow bucket.
//
// The state is local to a process. For several replicas behind a load
// balancer a shared store (e.g. Redis) or limiting at the gateway would be
// required; see docs/security.md.
package ratelimit

import (
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
	buckets map[string]*bucket
}

type bucket struct {
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
	return &Limiter{cfg: cfg, now: now, buckets: make(map[string]*bucket)}
}

// Allow consumes one token for key. When the request is not allowed it
// returns false and how long the client should wait before retrying.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	now := l.now()

	l.mu.Lock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.cfg.MaxKeys {
			l.evictLocked(now)
		}
		if len(l.buckets) >= l.cfg.MaxKeys {
			key = overflowKey
			b = l.buckets[key]
		}
		if b == nil {
			b = &bucket{lim: rate.NewLimiter(rate.Limit(l.cfg.Rate), l.cfg.Burst)}
			l.buckets[key] = b
		}
	}
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

// RetryAfterSeconds converts a wait duration to a Retry-After header value
// (whole seconds, at least 1).
func RetryAfterSeconds(d time.Duration) int {
	return max(1, int(math.Ceil(d.Seconds())))
}

// Cleanup removes buckets that have been idle for longer than IdleTTL.
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evictLocked(l.now())
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

func (l *Limiter) evictLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) > l.cfg.IdleTTL {
			delete(l.buckets, k)
		}
	}
}
