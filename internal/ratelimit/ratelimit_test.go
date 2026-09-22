package ratelimit

import (
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

// withFakeClock pins the package clock for the duration of a test and returns
// a function that advances it.
func withFakeClock(t *testing.T, start time.Time) func(time.Duration) {
	t.Helper()
	original := now
	current := start
	now = func() time.Time { return current }
	t.Cleanup(func() { now = original })
	return func(d time.Duration) { current = current.Add(d) }
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name  string
		rps   float64
		burst int
	}{
		{"zero rate", 0, 1},
		{"negative rate", -1, 1},
		{"zero burst", 1, 0},
		{"negative burst", 1, -5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.rps, tc.burst)
			if err == nil {
				t.Fatal("expected a configuration error")
			}
			var cfgErr *httpx.ConfigError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error = %T, want *httpx.ConfigError", err)
			}
		})
	}
}

func TestAllowConsumesBurstThenRefills(t *testing.T) {
	advance := withFakeClock(t, time.Unix(1_700_000_000, 0))
	limiter, err := New(10, 3) // 10 tokens/second, burst 3
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := range 3 {
		if !limiter.Allow("client") {
			t.Fatalf("request %d was rejected inside the burst", i+1)
		}
	}
	if limiter.Allow("client") {
		t.Fatal("request 4 was admitted, want rejection once the burst is spent")
	}

	// 100ms at 10 tokens/second is exactly one token.
	advance(100 * time.Millisecond)
	if !limiter.Allow("client") {
		t.Fatal("request after one refill interval was rejected")
	}
	if limiter.Allow("client") {
		t.Fatal("second request was admitted from a single refilled token")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	withFakeClock(t, time.Unix(1_700_000_000, 0))
	limiter, err := New(1, 1)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !limiter.Allow("a") {
		t.Fatal("first key was rejected")
	}
	if limiter.Allow("a") {
		t.Fatal("first key was admitted twice")
	}
	if !limiter.Allow("b") {
		t.Fatal("second key was rejected by the first key's usage")
	}
}

// TestRetryAfterDoesNotConsume is the contract the middleware relies on: it
// calls RetryAfter on the rejection path, which must not itself spend a token
// or a throttled caller would never recover.
func TestRetryAfterDoesNotConsume(t *testing.T) {
	advance := withFakeClock(t, time.Unix(1_700_000_000, 0))
	limiter, err := New(1, 1)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !limiter.Allow("client") {
		t.Fatal("first request was rejected")
	}
	if got := limiter.RetryAfter("client"); got != time.Second {
		t.Fatalf("RetryAfter = %s, want 1s", got)
	}
	// Calling it repeatedly must not change the answer.
	for i := range 5 {
		if got := limiter.RetryAfter("client"); got != time.Second {
			t.Fatalf("RetryAfter call %d = %s, want 1s", i+2, got)
		}
	}
	// And it must not have blocked the refill.
	advance(time.Second)
	if !limiter.Allow("client") {
		t.Fatal("request after the retry window was rejected")
	}
}

func TestRetryAfterIsZeroWhenTokenAvailable(t *testing.T) {
	withFakeClock(t, time.Unix(1_700_000_000, 0))
	limiter, err := New(5, 2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := limiter.RetryAfter("fresh"); got != 0 {
		t.Fatalf("RetryAfter for an untouched key = %s, want 0", got)
	}
}

// TestRetryAfterIsPositiveForPartialToken covers the fractional case: after
// draining a bucket whose rate is below one token per second, the wait must be
// a positive duration rather than truncating to zero, which would tell the
// client to retry immediately.
func TestRetryAfterIsPositiveForPartialToken(t *testing.T) {
	withFakeClock(t, time.Unix(1_700_000_000, 0))
	limiter, err := New(0.1, 1) // one token every ten seconds
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !limiter.Allow("client") {
		t.Fatal("first request was rejected")
	}
	got := limiter.RetryAfter("client")
	if got <= 0 {
		t.Fatalf("RetryAfter = %s, want a positive duration", got)
	}
	if got > 11*time.Second {
		t.Fatalf("RetryAfter = %s, want roughly 10s", got)
	}
}

// TestEvictionBoundsMemory is the security-relevant property: a caller that
// sends a fresh key on every request must not be able to grow the bucket map
// without bound.
func TestEvictionBoundsMemory(t *testing.T) {
	advance := withFakeClock(t, time.Unix(1_700_000_000, 0))
	limiter, err := New(1, 1)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := range sweepThreshold {
		limiter.Allow("key-" + strconv.Itoa(i))
	}
	// Walk the clock past the idle grace so the full buckets become eligible,
	// then add one more key to trigger the sweep.
	advance(2 * idleGrace)
	limiter.Allow("trigger")

	limiter.mu.Lock()
	size := len(limiter.buckets)
	limiter.mu.Unlock()
	if size > sweepThreshold {
		t.Fatalf("bucket map grew to %d entries, want at most %d", size, sweepThreshold)
	}
}

// TestEvictionKeepsDepletedBuckets guards against the sweep resetting a
// throttled caller's state, which would let them back in early.
//
// The idle window has to be kept short relative to the refill rate: once a
// bucket has been idle long enough to earn its tokens back, evicting it is
// correct because a fresh bucket would grant exactly the same allowance. The
// bucket only has to survive while it is still genuinely short.
func TestEvictionKeepsDepletedBuckets(t *testing.T) {
	advance := withFakeClock(t, time.Unix(1_700_000_000, 0))
	// Refill rate chosen so that the idle grace is not long enough to earn a
	// token back: 0.001 tokens/second over the 10-minute grace is 0.6 tokens,
	// still short of the burst of one. The bucket therefore still carries the
	// caller's throttle state and must survive the sweep.
	limiter, err := New(0.001, 1)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !limiter.Allow("throttled") {
		t.Fatal("first request was rejected")
	}
	// Fill the map and let the buckets idle past the grace, then force a
	// sweep. Evicting here would hand the throttled caller a full burst.
	for i := range sweepThreshold {
		limiter.Allow("filler-" + strconv.Itoa(i))
	}
	advance(idleGrace + 100*time.Second)
	limiter.Allow("trigger")

	if limiter.Allow("throttled") {
		t.Fatal("a throttled key was reset by eviction")
	}
}

// TestEvictionReclaimsRecoveredBuckets is the complement of the test above: a
// bucket idle long enough to refill completely carries no state worth keeping,
// so the sweep must actually free it. Without this the map would only ever grow
// and the memory bound would be vacuous.
func TestEvictionReclaimsRecoveredBuckets(t *testing.T) {
	advance := withFakeClock(t, time.Unix(1_700_000_000, 0))
	limiter, err := New(1, 1)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Drain each bucket by one token, then let them all idle well past a full
	// refill (one token per second, so a few seconds suffice).
	for i := range sweepThreshold {
		limiter.Allow("drained-" + strconv.Itoa(i))
	}
	advance(2 * idleGrace)
	limiter.Allow("trigger")

	limiter.mu.Lock()
	_, kept := limiter.buckets["drained-0"]
	size := len(limiter.buckets)
	limiter.mu.Unlock()
	if kept {
		t.Fatal("a fully recovered idle bucket was retained")
	}
	// The sweep runs while the triggering key is being inserted, so it can only
	// free the entries it reaches after that insert. Go's map iteration starts
	// at an arbitrary point, so "trigger" may be visited at any position and up
	// to one already-visited drained bucket can survive the pass. Anything more
	// than that would mean the sweep is failing to reclaim recovered buckets.
	if size > 2 {
		t.Fatalf("after the sweep %d buckets remain, want at most 2", size)
	}
	if size >= sweepThreshold {
		t.Fatalf("the sweep reclaimed nothing: %d buckets remain", size)
	}
}

func TestConcurrentAllowIsRaceFree(t *testing.T) {
	withFakeClock(t, time.Unix(1_700_000_000, 0))
	const burst = 100
	limiter, err := New(1000, burst)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var allowed int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				if limiter.Allow("shared") {
					atomic.AddInt64(&allowed, 1)
				}
			}
		}()
	}
	wg.Wait()
	// The fake clock never advances, so exactly the burst may be admitted.
	if got := atomic.LoadInt64(&allowed); got != burst {
		t.Fatalf("admitted %d requests, want exactly %d", got, burst)
	}
}
