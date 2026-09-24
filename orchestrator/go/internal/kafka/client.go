// Package kafka implements the orchestrator's real Kafka event bus client on
// top of github.com/segmentio/kafka-go. Publishes retry with capped
// exponential backoff and every error is propagated to the caller.
package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"

	"github.com/munisp/fraudfusion/orchestrator/go/internal/backoff"
)

// Event is the envelope published for journey lifecycle notifications.
type Event struct {
	ID   string                 `json:"id"`
	Type string                 `json:"type"`
	Data map[string]interface{} `json:"data"`
}

// Client wraps a kafka-go writer with retries and a dial-based health check.
type Client struct {
	brokers []string
	topic   string
	writer  *kafka.Writer
	dialer  *kafka.Dialer
}

// NewClient validates configuration and prepares the writer. Brokers must be
// non-empty; the writer itself connects lazily but Health performs a real
// broker dial.
func NewClient(brokers []string, topic string) (*Client, error) {
	if len(brokers) == 0 || brokers[0] == "" {
		return nil, fmt.Errorf("at least one Kafka broker is required")
	}
	if topic == "" {
		return nil, fmt.Errorf("Kafka topic is required")
	}
	return &Client{
		brokers: brokers,
		topic:   topic,
		writer: &kafka.Writer{
			Addr:         kafka.TCP(brokers...),
			Topic:        topic,
			Balancer:     &kafka.LeastBytes{},
			RequiredAcks: kafka.RequireOne,
			MaxAttempts:  3,
			// 10ms batch window: long enough to co-locate the journey
			// lifecycle events in one produce request, short enough to stay
			// inside the journey-execute latency budget.
			BatchTimeout: 10 * time.Millisecond,
			Async:        false,
		},
		dialer: &kafka.Dialer{Timeout: 5 * time.Second},
	}, nil
}

// PublishEvent encodes the event as JSON and writes it with the user ID as
// the partition key. Transient failures are retried with capped exponential
// backoff; the final error is returned (never fire-and-forget).
func (c *Client) PublishEvent(ctx context.Context, key string, event Event) error {
	if event.ID == "" || event.Type == "" {
		return fmt.Errorf("kafka event ID and type are required")
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode kafka event: %w", err)
	}
	msg := kafka.Message{Key: []byte(key), Value: payload, Time: time.Now()}
	if err := backoff.Do(ctx, backoff.Default(), func() error {
		return c.writer.WriteMessages(ctx, msg)
	}); err != nil {
		return fmt.Errorf("publish kafka event %s (%s): %w", event.ID, event.Type, err)
	}
	return nil
}

// PublishEvents encodes and writes several events in a single WriteMessages
// call, so they share one produce round trip within the writer's batch
// window. The final error is returned (never fire-and-forget).
func (c *Client) PublishEvents(ctx context.Context, key string, events ...Event) error {
	if len(events) == 0 {
		return nil
	}
	messages := make([]kafka.Message, 0, len(events))
	for _, event := range events {
		if event.ID == "" || event.Type == "" {
			return fmt.Errorf("kafka event ID and type are required")
		}
		payload, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("encode kafka event: %w", err)
		}
		messages = append(messages, kafka.Message{Key: []byte(key), Value: payload, Time: time.Now()})
	}
	if err := backoff.Do(ctx, backoff.Default(), func() error {
		return c.writer.WriteMessages(ctx, messages...)
	}); err != nil {
		return fmt.Errorf("publish %d kafka events for key %s: %w", len(events), key, err)
	}
	return nil
}

// Health dials the first configured broker to prove connectivity.
func (c *Client) Health(ctx context.Context) error {
	conn, err := c.dialer.DialContext(ctx, "tcp", c.brokers[0])
	if err != nil {
		return fmt.Errorf("dial kafka broker %s: %w", c.brokers[0], err)
	}
	_ = conn.Close()
	return nil
}

// Close flushes and closes the writer.
func (c *Client) Close() error { return c.writer.Close() }
