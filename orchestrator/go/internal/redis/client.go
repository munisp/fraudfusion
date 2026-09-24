// Package redis implements the orchestrator's Redis cache client on top of
// github.com/redis/go-redis/v9. TLS is enabled via REDIS_TLS=true, and Ping
// backs the /health endpoint so health is never hardcoded.
package redis

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client wraps go-redis with a key prefix and JSON helpers.
type Client struct {
	rdb    *redis.Client
	prefix string
}

// NewClient builds the client. When the REDIS_TLS environment variable is
// "true" the connection negotiates TLS with the broker host as ServerName.
func NewClient(addr, password string, db int, prefix string) (*Client, error) {
	if addr == "" {
		return nil, fmt.Errorf("Redis address is required")
	}
	opts := &redis.Options{Addr: addr, Password: password, DB: db}
	if strings.EqualFold(os.Getenv("REDIS_TLS"), "true") {
		host := addr
		if i := strings.LastIndex(host, ":"); i > 0 {
			host = host[:i]
		}
		opts.TLSConfig = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	return &Client{rdb: redis.NewClient(opts), prefix: prefix}, nil
}

func (c *Client) key(k string) string { return c.prefix + k }

// GetJSON fetches and decodes a cached value. A cache miss returns an error
// (redis.Nil); callers treat any error as "not cached".
func (c *Client) GetJSON(ctx context.Context, key string, out interface{}) error {
	raw, err := c.rdb.Get(ctx, c.key(key)).Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// SetJSON encodes and stores a value with a TTL. Errors are returned so
// callers can log them instead of silently dropping cache writes.
func (c *Client) SetJSON(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode redis value: %w", err)
	}
	return c.rdb.Set(ctx, c.key(key), raw, ttl).Err()
}

// PushOutbox appends a raw payload to the durable outbox list. It is the
// fallback sink for Kafka publishes that exhaust retries: a relayer can drain
// the list and republish without losing the event.
func (c *Client) PushOutbox(ctx context.Context, list string, payload []byte) error {
	return c.rdb.RPush(ctx, c.key(list), payload).Err()
}

// Ping reports whether Redis answers; used by /health.
func (c *Client) Ping(ctx context.Context) error {
	if err := c.rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping: %w", err)
	}
	return nil
}

// IsMiss reports whether err is a cache miss.
func IsMiss(err error) bool { return errors.Is(err, redis.Nil) }

// Close closes the underlying connection pool.
func (c *Client) Close() error { return c.rdb.Close() }
