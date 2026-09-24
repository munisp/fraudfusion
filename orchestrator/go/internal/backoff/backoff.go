// Package backoff provides a small exponential-backoff retry helper shared by
// the orchestrator middleware clients. Retries are capped (MaxInterval) and
// bounded (MaxAttempts) and abort immediately when the context is cancelled.
package backoff

import (
	"context"
	"time"
)

// Config tunes the retry behaviour of Do.
type Config struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Multiplier      float64
	MaxAttempts     int
}

// Default returns a conservative configuration: 4 attempts starting at 100ms,
// doubling up to a 2s cap.
func Default() Config {
	return Config{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      2.0,
		MaxAttempts:     4,
	}
}

// Do executes op, retrying with capped exponential backoff until op succeeds,
// the attempt budget is exhausted, or ctx is cancelled. The final error is
// returned to the caller; nothing is swallowed.
func Do(ctx context.Context, cfg Config, op func() error) error {
	if cfg.MaxAttempts < 1 {
		cfg.MaxAttempts = 1
	}
	if cfg.InitialInterval <= 0 {
		cfg.InitialInterval = 100 * time.Millisecond
	}
	if cfg.MaxInterval <= 0 {
		cfg.MaxInterval = 2 * time.Second
	}
	if cfg.Multiplier < 1 {
		cfg.Multiplier = 2.0
	}

	delay := cfg.InitialInterval
	var err error
	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		if err = op(); err == nil {
			return nil
		}
		if attempt == cfg.MaxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = time.Duration(float64(delay) * cfg.Multiplier)
		if delay > cfg.MaxInterval {
			delay = cfg.MaxInterval
		}
	}
	return err
}
