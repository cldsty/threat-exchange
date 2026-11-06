package ratelimit

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTest(cfg Config) (*Limiter, *fakeClock) {
	c := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	return newWithClock(cfg, c.Now), c
}

func TestBurstThenRefill(t *testing.T) {
	t.Parallel()
	l, clock := newTest(Config{Rate: 2, Burst: 3})

	for i := range 3 {
		ok, _ := l.Allow("k")
		assert.True(t, ok, "request %d within burst", i)
	}
	ok, wait := l.Allow("k")
	assert.False(t, ok)
	assert.InDelta(t, 500*time.Millisecond, wait, float64(10*time.Millisecond), "one token per 1/rate seconds")
	assert.Equal(t, 1, RetryAfterSeconds(wait))

	// A rejected request must not consume a token.
	clock.Advance(500 * time.Millisecond)
	ok, _ = l.Allow("k")
	assert.True(t, ok)
	ok, _ = l.Allow("k")
	assert.False(t, ok)
}

func TestKeysAreIndependent(t *testing.T) {
	t.Parallel()
	l, _ := newTest(Config{Rate: 1, Burst: 1})
	ok, _ := l.Allow("a")
	assert.True(t, ok)
	ok, _ = l.Allow("a")
	assert.False(t, ok)
	ok, _ = l.Allow("b")
	assert.True(t, ok, "another key has its own bucket")
}

func TestIdleBucketsAreEvicted(t *testing.T) {
	t.Parallel()
	l, clock := newTest(Config{Rate: 1, Burst: 1, IdleTTL: time.Minute})
	l.Allow("a")
	l.Allow("b")
	assert.Equal(t, 2, l.Len())
	clock.Advance(2 * time.Minute)
	l.Cleanup()
	assert.Equal(t, 0, l.Len())
}

func TestMaxKeysUsesOverflowBucket(t *testing.T) {
	t.Parallel()
	l, _ := newTest(Config{Rate: 1, Burst: 1, MaxKeys: 2, IdleTTL: time.Hour})
	l.Allow("a")
	l.Allow("b")

	ok, _ := l.Allow("c")
	assert.True(t, ok, "first overflow request uses the shared bucket")
	ok, _ = l.Allow("d")
	assert.False(t, ok, "overflow keys share one bucket")
	assert.LessOrEqual(t, l.Len(), 3, "memory is bounded")
}

func TestRetryAfterSeconds(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 1, RetryAfterSeconds(0))
	assert.Equal(t, 1, RetryAfterSeconds(time.Millisecond))
	assert.Equal(t, 3, RetryAfterSeconds(2100*time.Millisecond))
}

func TestConcurrentUse(t *testing.T) {
	t.Parallel()
	l := New(Config{Rate: 1000, Burst: 1000})
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				l.Allow(string(rune('a' + i%5)))
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 5, l.Len())
}
