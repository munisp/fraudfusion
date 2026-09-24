package tigerbeetle

import (
	"testing"
)

// TestTransferIDsUnique guards against the previous collision bug where IDs
// were uint64(time.Now().Unix()) — identical for all transfers in a second.
func TestTransferIDsUnique(t *testing.T) {
	seen := map[uint64]struct{}{}
	for i := 0; i < 10000; i++ {
		id, err := NewTransferID()
		if err != nil {
			t.Fatalf("NewTransferID: %v", err)
		}
		if id == 0 {
			t.Fatal("NewTransferID returned reserved ID 0")
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate transfer ID %d", id)
		}
		seen[id] = struct{}{}
	}
}

func TestNewClientRequiresAddress(t *testing.T) {
	if _, err := NewClient(nil, 1); err == nil {
		t.Fatal("NewClient with no addresses must fail")
	}
}
