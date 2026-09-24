package backoff

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDoSucceedsAfterRetries(t *testing.T) {
	attempts := 0
	err := Do(context.Background(), Config{InitialInterval: time.Millisecond, MaxInterval: 5 * time.Millisecond, Multiplier: 2, MaxAttempts: 4}, func() error {
		attempts++
		if attempts < 3 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestDoReturnsFinalError(t *testing.T) {
	sentinel := errors.New("permanent")
	attempts := 0
	err := Do(context.Background(), Config{InitialInterval: time.Millisecond, MaxInterval: 5 * time.Millisecond, Multiplier: 2, MaxAttempts: 3}, func() error {
		attempts++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Do = %v, want %v", err, sentinel)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestDoRespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Do(ctx, Default(), func() error { return errors.New("x") })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Do = %v, want context.Canceled", err)
	}
}
