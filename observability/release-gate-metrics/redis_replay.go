package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const defaultRedisReplayPrefix = "fraudfusion:release-gate:replay:v1:"

type redisReplayStore struct {
	client redis.UniversalClient
	prefix string
	ttl    time.Duration
}

func loadRedisReplayStore(ctx context.Context) (replayStore, error) {
	address := strings.TrimSpace(os.Getenv("REDIS_ADDR"))
	if address == "" {
		return nil, fmt.Errorf("REDIS_ADDR is required for distributed replay protection")
	}
	prefix := os.Getenv("REDIS_REPLAY_KEY_PREFIX")
	if prefix == "" {
		prefix = defaultRedisReplayPrefix
	}
	if len(prefix) > 128 || !strings.HasSuffix(prefix, ":") {
		return nil, fmt.Errorf("REDIS_REPLAY_KEY_PREFIX must be at most 128 characters and end in ':'")
	}
	if os.Getenv("REDIS_TLS") != "true" {
		return nil, fmt.Errorf("REDIS_TLS must be true for distributed replay protection")
	}
	tlsConfig, err := redisTLSConfig()
	if err != nil {
		return nil, err
	}
	options := &redis.UniversalOptions{
		Addrs:        strings.Split(address, ","),
		Username:     os.Getenv("REDIS_USERNAME"),
		Password:     os.Getenv("REDIS_PASSWORD"),
		DB:           0,
		DialTimeout:  replayOpTimeout,
		ReadTimeout:  replayOpTimeout,
		WriteTimeout: replayOpTimeout,
		PoolTimeout:  replayOpTimeout,
		MinIdleConns: 1,
		TLSConfig:    tlsConfig,
	}
	client := redis.NewUniversalClient(options)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping Redis replay store: %w", err)
	}
	return &redisReplayStore{client: client, prefix: prefix, ttl: replayTTL}, nil
}

func (s *redisReplayStore) Claim(ctx context.Context, eventID string) (claimResult, error) {
	if len(eventID) != sha256.Size*2 {
		return claimDuplicate, fmt.Errorf("invalid replay event identity")
	}
	claimCtx, cancel := context.WithTimeout(ctx, replayOpTimeout)
	defer cancel()
	claimed, err := s.client.SetNX(claimCtx, s.key(eventID), "1", s.ttl).Result()
	if err != nil {
		return claimDuplicate, fmt.Errorf("claim distributed replay key: %w", err)
	}
	if !claimed {
		return claimDuplicate, nil
	}
	return claimAccepted, nil
}

func (s *redisReplayStore) Health(ctx context.Context) error {
	healthCtx, cancel := context.WithTimeout(ctx, replayOpTimeout)
	defer cancel()
	if err := s.client.Ping(healthCtx).Err(); err != nil {
		return fmt.Errorf("ping distributed replay store: %w", err)
	}
	return nil
}

func (s *redisReplayStore) Close() error { return s.client.Close() }

func (s *redisReplayStore) key(eventID string) string { return s.prefix + eventID }

func replayKeyForTest(prefix string, event ingestEvent) string {
	identity := event.Event + ":" + event.RunID + ":" + event.Gate + ":" + event.Scenario
	sum := sha256.Sum256([]byte(identity))
	return prefix + hex.EncodeToString(sum[:])
}
