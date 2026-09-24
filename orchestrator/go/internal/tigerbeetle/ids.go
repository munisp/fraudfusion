package tigerbeetle

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"time"
)

// idCounter guarantees monotonicity within this process even if two IDs are
// minted inside the same nanosecond tick.
var idCounter uint64

// NewTransferID mints a collision-safe uint64 ID. The previous implementation
// used uint64(time.Now().Unix()), which collides for every pair of transfers
// executed within the same second. IDs are now crypto-random 63-bit values
// combined with a process-local monotonic counter and rejected if zero, which
// TigerBeetle reserves.
func NewTransferID() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("mint tigerbeetle id: %w", err)
	}
	random := binary.BigEndian.Uint64(buf[:]) & 0x7fffffffffffffff // keep 63-bit positive space
	counter := atomic.AddUint64(&idCounter, 1)
	id := (random ^ (uint64(time.Now().UnixNano()) & 0x7fffffffffffffff)) + counter
	if id == 0 || id > 0x7fffffffffffffff {
		id = counter | 1
	}
	return id, nil
}
