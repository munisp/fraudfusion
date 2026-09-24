//go:build !tigerbeetle

package tigerbeetle

import (
	"errors"
	"testing"
)

// TestStubFailsClosed verifies the default build returns ErrUnavailable
// instead of pretending ledger writes succeeded.
func TestStubFailsClosed(t *testing.T) {
	c, err := NewClient([]string{"localhost:3000"}, 1)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.CreateAccount(nil, 1, 1, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CreateAccount = %v, want ErrUnavailable", err)
	}
	if err := c.Health(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Health = %v, want ErrUnavailable", err)
	}
}
