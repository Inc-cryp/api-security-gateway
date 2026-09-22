package breaker

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func TestConfigDefaults(t *testing.T) {
	got := Config{}.withDefaults()
	if got.FailureThreshold != DefaultFailureThreshold {
		t.Fatalf("FailureThreshold = %d, want %d", got.FailureThreshold, DefaultFailureThreshold)
	}
	if got.OpenTimeout != DefaultOpenTimeout {
		t.Fatalf("OpenTimeout = %s, want %s", got.OpenTimeout, DefaultOpenTimeout)
	}
	if got.HalfOpenSuccesses != DefaultHalfOpenSuccesses {
		t.Fatalf("HalfOpenSuccesses = %d, want %d", got.HalfOpenSuccesses, DefaultHalfOpenSuccesses)
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{Closed, "closed"},
		{Open, "open"},
		{HalfOpen, "half-open"},
		{State(99), "unknown(99)"},
	}
	for _, tc := range tests {
		if got := tc.state.String(); got != tc.want {
			t.Fatalf("State(%d).String() = %q, want %q", tc.state, got, tc.want)
		}
	}
}

func TestBreakerOpensAfterThreshold(t *testing.T) {
	withFakeClock(t, time.Unix(1_700_000_000, 0))
	b := New(Config{FailureThreshold: 3, OpenTimeout: time.Minute, HalfOpenSuccesses: 2})

	for i := range 3 {
		if !b.Allow() {
			t.Fatalf("attempt %d was blocked while closed", i+1)
		}
		b.Record(false)
	}
	if got := b.State(); got != Open {
		t.Fatalf("State() = %s, want open", got)
	}
	if b.Allow() {
		t.Fatal("request was admitted while the circuit is open")
	}
}

func TestSuccessResetsFailureRun(t *testing.T) {
	withFakeClock(t, time.Unix(1_700_000_000, 0))
	b := New(Config{FailureThreshold: 3, OpenTimeout: time.Minute})

	b.Record(false)
	b.Record(false)
	if !b.Allow() {
		t.Fatal("breaker opened before the threshold was reached")
	}
	b.Record(true)
	b.Record(false)
	b.Record(false)
	if got := b.State(); got != Closed {
		t.Fatalf("State() = %s, want closed: a success must reset the failure run", got)
	}
	if !b.Allow() {
		t.Fatal("breaker is blocking while closed")
	}
}

func TestHalfOpenAdmitsExactlyOneProbe(t *testing.T) {
	advance := withFakeClock(t, time.Unix(1_700_000_000, 0))
	b := New(Config{FailureThreshold: 1, OpenTimeout: 30 * time.Second, HalfOpenSuccesses: 1})
	b.Record(false)
	if got := b.State(); got != Open {
		t.Fatalf("State() = %s, want open", got)
	}

	advance(30 * time.Second)
	if !b.Allow() {
		t.Fatal("the first request after OpenTimeout was blocked; it should be the probe")
	}
	if got := b.State(); got != HalfOpen {
		t.Fatalf("State() = %s, want half-open", got)
	}
	if b.Allow() {
		t.Fatal("a second concurrent request was admitted; half-open must admit one probe")
	}
}

func TestHalfOpenClosesAfterEnoughSuccesses(t *testing.T) {
	advance := withFakeClock(t, time.Unix(1_700_000_000, 0))
	b := New(Config{FailureThreshold: 1, OpenTimeout: time.Second, HalfOpenSuccesses: 2})
	b.Record(false)

	advance(time.Second)
	if !b.Allow() {
		t.Fatal("probe was blocked")
	}
	b.Record(true)
	if got := b.State(); got != HalfOpen {
		t.Fatalf("State() = %s, want half-open after one of two successes", got)
	}

	if !b.Allow() {
		t.Fatal("second probe was blocked")
	}
	b.Record(true)
	if got := b.State(); got != Closed {
		t.Fatalf("State() = %s, want closed after the required successes", got)
	}
	if !b.Allow() {
		t.Fatal("breaker is blocking while closed")
	}
}

func TestHalfOpenFailureReopens(t *testing.T) {
	advance := withFakeClock(t, time.Unix(1_700_000_000, 0))
	b := New(Config{FailureThreshold: 1, OpenTimeout: time.Minute})
	b.Record(false)

	advance(time.Minute)
	if !b.Allow() {
		t.Fatal("probe was blocked")
	}
	b.Record(false)
	if got := b.State(); got != Open {
		t.Fatalf("State() = %s, want open after a failed probe", got)
	}
	if b.Allow() {
		t.Fatal("request admitted immediately after a failed probe")
	}
}

func TestStrayRecordDoesNotMoveHalfOpen(t *testing.T) {
	advance := withFakeClock(t, time.Unix(1_700_000_000, 0))
	b := New(Config{FailureThreshold: 1, OpenTimeout: time.Second, HalfOpenSuccesses: 2})
	b.Record(false)

	advance(time.Second)
	if !b.Allow() {
		t.Fatal("probe was blocked")
	}
	if got := b.State(); got != HalfOpen {
		t.Fatalf("State() = %s, want half-open", got)
	}
	b.Record(true) // the probe succeeded; one more success is still needed
	if got := b.State(); got != HalfOpen {
		t.Fatalf("State() = %s, want half-open after one of two successes", got)
	}

	// No probe is in flight now, so an outcome arriving here belongs to a
	// request admitted before the circuit opened. It must be dropped rather
	// than treated as the next probe: a stale failure would otherwise re-open
	// a circuit that is demonstrably recovering, and a stale success would
	// impersonate a probe that never ran.
	b.Record(false)
	if got := b.State(); got != HalfOpen {
		t.Fatalf("State() = %s, want half-open: a stray failure re-opened the circuit", got)
	}
	if !b.Allow() {
		t.Fatal("the next probe was blocked after a stray outcome was dropped")
	}
	if b.Allow() {
		t.Fatal("a second concurrent probe was admitted")
	}
	b.Record(true)
	if got := b.State(); got != Closed {
		t.Fatalf("State() = %s, want closed once the required probes succeeded", got)
	}
}

func TestRecordWhileOpenIsIgnored(t *testing.T) {
	withFakeClock(t, time.Unix(1_700_000_000, 0))
	b := New(Config{FailureThreshold: 1, OpenTimeout: time.Hour})
	b.Record(false)
	if got := b.State(); got != Open {
		t.Fatalf("State() = %s, want open", got)
	}
	b.Record(true)
	if got := b.State(); got != Open {
		t.Fatalf("State() = %s, want open: a success while open must not close the circuit", got)
	}
}

func TestConcurrentProbesAreSerialised(t *testing.T) {
	advance := withFakeClock(t, time.Unix(1_700_000_000, 0))
	b := New(Config{FailureThreshold: 1, OpenTimeout: time.Second, HalfOpenSuccesses: 1})
	b.Record(false)
	advance(time.Second)

	var admitted int64
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.Allow() {
				atomic.AddInt64(&admitted, 1)
			}
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt64(&admitted); got != 1 {
		t.Fatalf("admitted %d probes, want exactly 1", got)
	}
}

func TestRegistryReturnsStableBreakerPerName(t *testing.T) {
	withFakeClock(t, time.Unix(1_700_000_000, 0))
	registry := NewRegistry(Config{FailureThreshold: 1, OpenTimeout: time.Hour})

	account := registry.Get("account")
	transfer := registry.Get("transfer")
	if account == transfer {
		t.Fatal("different service names returned the same breaker")
	}
	if registry.Get("account") != account {
		t.Fatal("the same service name returned a different breaker")
	}

	account.Record(false)
	if got := account.State(); got != Open {
		t.Fatalf("account breaker = %s, want open", got)
	}
	// Tripping one upstream must not take the others down with it.
	if got := transfer.State(); got != Closed {
		t.Fatalf("transfer breaker = %s, want closed", got)
	}
	if !transfer.Allow() {
		t.Fatal("transfer breaker is blocking")
	}
}

func TestRegistryConcurrentGetIsRaceFree(t *testing.T) {
	withFakeClock(t, time.Unix(1_700_000_000, 0))
	registry := NewRegistry(Config{})
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			registry.Get("service-" + strconv.Itoa(i%4))
		}()
	}
	wg.Wait()
	registry.mu.Lock()
	size := len(registry.breakers)
	registry.mu.Unlock()
	if size != 4 {
		t.Fatalf("registry holds %d breakers, want 4", size)
	}
}
