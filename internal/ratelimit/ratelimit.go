// Package ratelimit implements a keyed token-bucket rate limiter.
package ratelimit

import (
	"fmt"
	"sync"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

// now is indirected so tests can drive the clock instead of sleeping.
var now = time.Now

const (
	// sweepThreshold is the bucket count at which idle buckets are reclaimed.
	// Without a sweep a caller could pin unbounded memory simply by sending a
	// fresh key per request, so this is a security control, not a nicety.
	sweepThreshold = 4096
	// idleGrace is how long a fully refilled bucket is kept before eviction.
	idleGrace = 10 * time.Minute
)

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// Limiter is a keyed token-bucket limiter, safe for concurrent use.
type Limiter struct {
	mu      sync.Mutex
	rps     float64
	burst   float64
	buckets map[string]*bucket
}

// New builds a limiter that refills rps tokens per second per key, capped at
// burst. A non-positive rate or a burst below one is a configuration error.
func New(rps float64, burst int) (*Limiter, error) {
	if !(rps > 0) {
		return nil, &httpx.ConfigError{Field: "rate_limit", Value: fmt.Sprint(rps), Err: fmt.Errorf("must be greater than zero")}
	}
	if burst < 1 {
		return nil, &httpx.ConfigError{Field: "rate_burst", Value: fmt.Sprint(burst), Err: fmt.Errorf("must be at least one")}
	}
	return &Limiter{rps: rps, burst: float64(burst), buckets: make(map[string]*bucket)}, nil
}

// Allow consumes one token for key and reports whether the call was admitted.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucketLocked(key)
	l.refillLocked(b)
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// RetryAfter reports how long the caller behind key should wait before a token
// becomes available, or zero when one is available now. It never consumes a
// token, so it is safe to call on the rejection path.
func (l *Limiter) RetryAfter(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucketLocked(key)
	l.refillLocked(b)
	if b.tokens >= 1 {
		return 0
	}
	missing := 1 - b.tokens
	seconds := missing / l.rps
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds * float64(time.Second))
}

// bucketLocked returns the bucket for key, creating it when absent and
// sweeping first if the map has grown past sweepThreshold.
func (l *Limiter) bucketLocked(key string) *bucket {
	// Note: lastSeen is deliberately left alone here. refillLocked measures
	// the elapsed time since it and then advances it; touching it first would
	// zero that interval and the bucket would never refill.
	if b, ok := l.buckets[key]; ok {
		return b
	}
	if len(l.buckets) >= sweepThreshold {
		l.sweepLocked()
	}
	b := &bucket{tokens: l.burst, lastSeen: now()}
	l.buckets[key] = b
	return b
}

// refillLocked adds the tokens earned since the bucket was last touched.
func (l *Limiter) refillLocked(b *bucket) {
	t := now()
	elapsed := t.Sub(b.lastSeen).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rps
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
	}
	b.lastSeen = t
}

// sweepLocked drops buckets that have been idle past idleGrace and that a
// refill would leave full. It only reclaims memory that is provably useless; a
// bucket still short of tokens after crediting the idle refill is kept because
// it is the caller's rate-limit state.
//
// The refill has to be credited here rather than read from b.tokens: a bucket
// is only ever refilled when its key is used again, so an idle bucket still
// holds the token count it was left with. Comparing that stale count against
// burst would make every bucket look permanently depleted and the sweep would
// never free anything.
func (l *Limiter) sweepLocked() {
	t := now()
	for key, b := range l.buckets {
		if len(l.buckets) <= 1 {
			return
		}
		idle := t.Sub(b.lastSeen)
		if idle <= idleGrace {
			continue
		}
		if b.tokens+idle.Seconds()*l.rps >= l.burst {
			delete(l.buckets, key)
		}
	}
}
