//go:build tigerbeetle

// Real TigerBeetle client backed by github.com/tigerbeetle/tigerbeetle-go.
// This file is only compiled with `-tags tigerbeetle` because tigerbeetle-go
// links against the TigerBeetle native (cgo) static library.
package tigerbeetle

import (
	"context"
	"fmt"

	tb "github.com/tigerbeetle/tigerbeetle-go"
)

// Client wraps the native TigerBeetle client.
type Client struct {
	client tb.Client
}

// NewClient connects to a TigerBeetle cluster.
func NewClient(addresses []string, clusterID uint64) (*Client, error) {
	if len(addresses) == 0 || addresses[0] == "" {
		return nil, fmt.Errorf("at least one TigerBeetle address is required")
	}
	c, err := tb.NewClient(tb.ToUint128(clusterID), addresses)
	if err != nil {
		return nil, fmt.Errorf("connect TigerBeetle cluster: %w", err)
	}
	return &Client{client: c}, nil
}

// CreateAccount creates a ledger account and returns any per-account errors.
func (c *Client) CreateAccount(ctx context.Context, id uint64, ledger, code uint32) error {
	results, err := c.client.CreateAccounts([]tb.Account{
		{ID: tb.ToUint128(id), Ledger: ledger, Code: uint16(code)},
	})
	if err != nil {
		return fmt.Errorf("tigerbeetle CreateAccounts: %w", err)
	}
	for _, r := range results {
		return fmt.Errorf("tigerbeetle account %d rejected: status %d", id, uint32(r.Status))
	}
	return nil
}

// CreateTransfer creates a transfer between two accounts.
func (c *Client) CreateTransfer(ctx context.Context, id, debitAccountID, creditAccountID, amount uint64, ledger, code uint32) error {
	results, err := c.client.CreateTransfers([]tb.Transfer{
		{
			ID:              tb.ToUint128(id),
			DebitAccountID:  tb.ToUint128(debitAccountID),
			CreditAccountID: tb.ToUint128(creditAccountID),
			Amount:          tb.ToUint128(amount),
			Ledger:          ledger,
			Code:            uint16(code),
		},
	})
	if err != nil {
		return fmt.Errorf("tigerbeetle CreateTransfers: %w", err)
	}
	for _, r := range results {
		return fmt.Errorf("tigerbeetle transfer %d rejected: status %d", id, uint32(r.Status))
	}
	return nil
}

// Health performs a cheap Nop request against the cluster.
func (c *Client) Health(ctx context.Context) error {
	if err := c.client.Nop(); err != nil {
		return fmt.Errorf("tigerbeetle health nop: %w", err)
	}
	return nil
}

// Close releases the native client.
func (c *Client) Close() error {
	c.client.Close()
	return nil
}
