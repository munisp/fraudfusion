//go:build !tigerbeetle

// Package tigerbeetle provides the orchestrator's TigerBeetle ledger client.
//
// HONEST LIMITATION: the default build ships a stub that returns
// ErrUnavailable for every operation. The real client backed by
// github.com/tigerbeetle/tigerbeetle-go is compiled only with
// `-tags tigerbeetle` (see client_tigerbeetle.go) because tigerbeetle-go
// requires the TigerBeetle native (cgo) library, which is not available in
// every build environment. Build the real client with:
//
//	go build -tags tigerbeetle ./...
//
// The stub keeps the default build hermetic while making the degraded state
// explicit: callers must treat ErrUnavailable as "ledger disabled", never as
// success.
package tigerbeetle

import (
	"context"
	"errors"
	"fmt"
)

// ErrUnavailable is returned by the default-build stub for every TigerBeetle
// operation. Build with `-tags tigerbeetle` to enable the real client.
var ErrUnavailable = errors.New("tigerbeetle client unavailable: build with -tags tigerbeetle to enable the native client")

// Client is the default-build stub. It performs no I/O.
type Client struct {
	addresses []string
	clusterID uint64
}

// NewClient validates configuration and returns the stub client.
func NewClient(addresses []string, clusterID uint64) (*Client, error) {
	if len(addresses) == 0 || addresses[0] == "" {
		return nil, fmt.Errorf("at least one TigerBeetle address is required")
	}
	return &Client{addresses: addresses, clusterID: clusterID}, nil
}

// CreateAccount always fails with ErrUnavailable in the default build.
func (c *Client) CreateAccount(ctx context.Context, id uint64, ledger, code uint32) error {
	return ErrUnavailable
}

// CreateTransfer always fails with ErrUnavailable in the default build.
func (c *Client) CreateTransfer(ctx context.Context, id, debitAccountID, creditAccountID, amount uint64, ledger, code uint32) error {
	return ErrUnavailable
}

// Health reports the stubbed (unavailable) state honestly.
func (c *Client) Health(ctx context.Context) error { return ErrUnavailable }

// Close is a no-op for the stub.
func (c *Client) Close() error { return nil }
