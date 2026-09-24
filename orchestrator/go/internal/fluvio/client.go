// Package fluvio is DEPRECATED and no longer referenced by the orchestrator.
//
// Kafka (internal/kafka) is the platform's single real event bus; the Fluvio
// integration was removed rather than left as a fake stub. This package is
// kept only so out-of-tree imports fail loudly with a compile target that
// explains the removal instead of a confusing "package not found". The
// ProduceEvent API now returns ErrRemoved instead of silently succeeding.
package fluvio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/munisp/fraudfusion/orchestrator/go/internal/backoff"
)

// ErrRemoved is returned by ProduceEvent because the Fluvio event bus has
// been removed in favour of the Kafka client (internal/kafka).
var ErrRemoved = errors.New("fluvio event bus removed: publish via internal/kafka instead")

// Client is retained only for API compatibility. Deprecated: use kafka.Client.
type Client struct {
	endpoint string
}

// Event mirrors the legacy event envelope. Deprecated: use kafka.Event.
type Event struct {
	ID   string
	Type string
	Data map[string]interface{}
}

// NewClient validates the endpoint. Deprecated: use kafka.NewClient.
func NewClient(endpoint string) (*Client, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("Fluvio endpoint is required")
	}
	return &Client{endpoint: endpoint}, nil
}

// ProduceEvent always fails: the Fluvio bus was removed and silently dropping
// events is not acceptable. Deprecated: use kafka.Client.PublishEvent.
func (c *Client) ProduceEvent(ctx context.Context, userID string, event Event) error {
	return ErrRemoved
}

// Health performs a real TCP dial of the configured endpoint with retry; it
// exists only so legacy deployments detect the stale configuration.
func (c *Client) Health(ctx context.Context) error {
	return backoff.Do(ctx, backoff.Default(), func() error {
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", c.endpoint)
		if err != nil {
			return fmt.Errorf("dial fluvio endpoint %s: %w", c.endpoint, err)
		}
		_ = conn.Close()
		return nil
	})
}

// Close is a no-op.
func (c *Client) Close() error { return nil }
