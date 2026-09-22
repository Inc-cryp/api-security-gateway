// Package breaker implements a per-upstream circuit breaker.
package breaker

import (
	"sync"
	"time"
)

// now is indirected so tests can drive the clock deterministically.
var now = time.Now

// State is a circuit breaker state.
type State int

// The three circuit states.
const (
	Closed State = iota
	Open
	HalfOpen
)

// String renders the state for logs and error messages.
func (s State) String() string {
	switch s {
	case Closed:
		return "closed"
	case Open:
		return "open"
	case HalfOpen:
		return "half-open"
	default:
		return "unknown(" + itoa(int(s)) + ")"
	}
}

// Config tunes a breaker. Zero values fall back to the defaults below.
type Config struct {
	FailureThreshold  int
	OpenTimeout       time.Duration
	HalfOpenSuccesses int
}

// Defaults used when a field is left at zero.
const (
	DefaultFailureThreshold  = 5
	DefaultOpenTimeout       = 30 * time.Second
	DefaultHalfOpenSuccesses = 2
)

func (c Config) withDefaults() Config {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = DefaultFailureThreshold
	}
	if c.OpenTimeout <= 0 {
		c.OpenTimeout = DefaultOpenTimeout
	}
	if c.HalfOpenSuccesses <= 0 {
		c.HalfOpenSuccesses = DefaultHalfOpenSuccesses
	}
	return c
}

// Breaker is a three-state circuit breaker, safe for concurrent use.
type Breaker struct {
	cfg Config

	mu          sync.Mutex
	state       State
	failures    int
	successes   int
	openedAt    time.Time
	probeInFlgt bool
}

// New returns a closed breaker.
func New(cfg Config) *Breaker {
	return &Breaker{cfg: cfg.withDefaults(), state: Closed}
}

// Allow reports whether a request may proceed.
//
// While the circuit is open it admits nothing until OpenTimeout has elapsed,
// then admits exactly one probe: the in-flight flag is claimed under the lock
// so a burst of concurrent callers cannot all decide they are the probe.
func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case Closed:
		return true
	case Open:
		if now().Sub(b.openedAt) < b.cfg.OpenTimeout {
			return false
		}
		b.state = HalfOpen
		b.probeInFlgt = true
		return true
	case HalfOpen:
		if b.probeInFlgt {
			return false
		}
		b.probeInFlgt = true
		return true
	default:
		return false
	}
}

// Record feeds the outcome of an admitted attempt back into the breaker.
func (b *Breaker) Record(success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case Closed:
		if success {
			b.failures = 0
			return
		}
		b.failures++
		if b.failures >= b.cfg.FailureThreshold {
			b.openLocked()
		}
	case HalfOpen:
		if !b.probeInFlgt {
			// A stray outcome from a request admitted before the state
			// changed must not move the breaker.
			return
		}
		b.probeInFlgt = false
		if success {
			b.successes++
			if b.successes >= b.cfg.HalfOpenSuccesses {
				b.closeLocked()
			}
			return
		}
		b.openLocked()
	case Open:
		// Outcomes arriving while open belong to requests admitted before the
		// circuit opened; they carry no information about recovery.
	}
}

// State reports the current state.
func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

func (b *Breaker) openLocked() {
	b.state = Open
	b.openedAt = now()
	b.failures = 0
	b.successes = 0
	b.probeInFlgt = false
}

func (b *Breaker) closeLocked() {
	b.state = Closed
	b.failures = 0
	b.successes = 0
	b.probeInFlgt = false
}

// Registry hands out one breaker per upstream name.
type Registry struct {
	cfg Config

	mu       sync.Mutex
	breakers map[string]*Breaker
}

// NewRegistry returns a registry whose members share cfg.
func NewRegistry(cfg Config) *Registry {
	return &Registry{cfg: cfg.withDefaults(), breakers: make(map[string]*Breaker)}
}

// Get returns the breaker for name, creating it on first use.
//
// A nil *Registry disables the breaker entirely and returns a breaker that
// is permanently closed, which is what a caller gets when it does not
// configure one. Without this guard the first request through an
// unconfigured gateway would panic on the map assignment.
func (r *Registry) Get(name string) *Breaker {
	if r == nil {
		return New(Config{})
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if b, ok := r.breakers[name]; ok {
		return b
	}
	b := New(r.cfg)
	r.breakers[name] = b
	return b
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
