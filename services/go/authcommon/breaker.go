package authcommon

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrBreakerOpen is returned by Breaker.Execute when the circuit is open:
// the dependency is known-bad and calls fail fast instead of burning a
// retry ladder against it.
var ErrBreakerOpen = errors.New("circuit breaker open")

// Breaker states.
const (
	BreakerClosed   = "closed"
	BreakerOpen     = "open"
	BreakerHalfOpen = "half-open"
)

const (
	// DefaultFailureThreshold opens the breaker after 5 consecutive failures.
	DefaultFailureThreshold = 5
	// DefaultResetTimeout keeps the breaker open 30s before a half-open
	// trial call is allowed through.
	DefaultResetTimeout = 30 * time.Second
)

// Breaker is a small, dependency-scoped circuit breaker:
// closed -> open after `threshold` consecutive failures;
// open -> half-open after `resetTimeout` (one trial call admitted);
// half-open -> closed on trial success, open on trial failure.
type Breaker struct {
	name          string
	threshold     int
	resetTimeout  time.Duration
	now           func() time.Time // test hook

	mu            sync.Mutex
	state         string
	failures      int
	openedAt      time.Time
	trialInFlight bool
}

// BreakerOption customizes a Breaker.
type BreakerOption func(*Breaker)

// WithFailureThreshold overrides DefaultFailureThreshold.
func WithFailureThreshold(n int) BreakerOption {
	return func(b *Breaker) {
		if n > 0 {
			b.threshold = n
		}
	}
}

// WithResetTimeout overrides DefaultResetTimeout.
func WithResetTimeout(d time.Duration) BreakerOption {
	return func(b *Breaker) {
		if d > 0 {
			b.resetTimeout = d
		}
	}
}

// NewBreaker creates a breaker for one named dependency (e.g. "aml-ml").
func NewBreaker(name string, opts ...BreakerOption) *Breaker {
	b := &Breaker{
		name:         name,
		threshold:    DefaultFailureThreshold,
		resetTimeout: DefaultResetTimeout,
		state:        BreakerClosed,
		now:          time.Now,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// Name returns the dependency name.
func (b *Breaker) Name() string { return b.name }

// State returns the current state (closed/open/half-open).
func (b *Breaker) State() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stateLocked()
}

func (b *Breaker) stateLocked() string {
	if b.state == BreakerOpen && b.now().Sub(b.openedAt) >= b.resetTimeout {
		// Half-open is a transitional state materialized on read so metrics
		// and logs observe it even before the next call arrives.
		b.state = BreakerHalfOpen
		b.trialInFlight = false
	}
	return b.state
}

// Execute runs fn unless the circuit is open. A nil error from fn counts as
// success; any non-nil error counts as a failure. fn must NOT be retried
// internally in a way that defeats the failure accounting.
func (b *Breaker) Execute(fn func() error) error {
	if err := b.beforeCall(); err != nil {
		return err
	}
	callErr := fn()
	b.afterCall(callErr)
	if callErr != nil {
		return fmt.Errorf("%s: %w", b.name, callErr)
	}
	return nil
}

func (b *Breaker) beforeCall() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.stateLocked() {
	case BreakerOpen:
		return fmt.Errorf("%s: %w", b.name, ErrBreakerOpen)
	case BreakerHalfOpen:
		if b.trialInFlight {
			// Only one trial call at a time; concurrent callers fail fast.
			return fmt.Errorf("%s: %w", b.name, ErrBreakerOpen)
		}
		b.trialInFlight = true
	}
	return nil
}

func (b *Breaker) afterCall(callErr error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if callErr == nil {
		b.state = BreakerClosed
		b.failures = 0
		b.trialInFlight = false
		return
	}
	b.failures++
	switch b.state {
	case BreakerHalfOpen:
		// Trial failed: re-open immediately.
		b.state = BreakerOpen
		b.openedAt = b.now()
		b.trialInFlight = false
	case BreakerClosed:
		if b.failures >= b.threshold {
			b.state = BreakerOpen
			b.openedAt = b.now()
		}
	}
}
