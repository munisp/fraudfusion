package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	defaultRedisReplayPrefix = "fraudfusion:release-gate:replay:v1:"
	defaultRedisRatePrefix   = "fraudfusion:release-gate:rate:v1:"
	defaultRateLimit         = 600
	defaultRateWindow        = time.Minute
)

var redisClaimAndRateLimitScript = redis.NewScript(redisClaimAndRateLimitLua)

type redisReplayStore struct {
	client     redis.UniversalClient
	prefix     string
	ratePrefix string
	ttl        time.Duration
	rateLimit  int64
	rateWindow time.Duration
	now        func() time.Time
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
	ratePrefix := os.Getenv("REDIS_RATE_KEY_PREFIX")
	if ratePrefix == "" {
		ratePrefix = defaultRedisRatePrefix
	}
	if len(ratePrefix) > 128 || !strings.HasSuffix(ratePrefix, ":") {
		return nil, fmt.Errorf("REDIS_RATE_KEY_PREFIX must be at most 128 characters and end in ':'")
	}
	rateLimit, err := positiveEnvInt64("REDIS_RATE_LIMIT", defaultRateLimit)
	if err != nil {
		return nil, err
	}
	rateWindowSeconds, err := positiveEnvInt64("REDIS_RATE_WINDOW_SECONDS", int64(defaultRateWindow/time.Second))
	if err != nil {
		return nil, err
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
	return &redisReplayStore{
		client:     client,
		prefix:     prefix,
		ratePrefix: ratePrefix,
		ttl:        replayTTL,
		rateLimit:  rateLimit,
		rateWindow: time.Duration(rateWindowSeconds) * time.Second,
	}, nil
}

func positiveEnvInt64(name string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
}

func (s *redisReplayStore) Claim(ctx context.Context, eventID, keyID string) (claimResult, error) {
	if len(eventID) != sha256.Size*2 {
		return claimDuplicate, fmt.Errorf("invalid replay event identity")
	}
	if !validKeyID(keyID) {
		return claimDuplicate, fmt.Errorf("invalid rate-limit key identifier")
	}
	claimCtx, cancel := context.WithTimeout(ctx, replayOpTimeout)
	defer cancel()
	result, err := redisClaimAndRateLimitScript.Run(
		claimCtx,
		s.client,
		[]string{s.key(eventID), s.rateKey(keyID)},
		eventID,
		s.currentTime().UnixMilli(),
		s.rateWindow.Milliseconds(),
		s.rateLimit,
		s.ttl.Milliseconds(),
	).Result()
	if err != nil {
		return claimDuplicate, fmt.Errorf("atomic distributed replay and rate-limit claim: %w", err)
	}
	code, _, err := redisScriptResult(result)
	if err != nil {
		return claimDuplicate, err
	}
	switch code {
	case 0:
		return claimAccepted, nil
	case 1:
		return claimDuplicate, nil
	case 2:
		return claimRateLimited, nil
	default:
		return claimDuplicate, fmt.Errorf("unexpected Redis claim script result %d", code)
	}
}

func redisScriptResult(result interface{}) (int64, int64, error) {
	values, ok := result.([]interface{})
	if !ok || len(values) != 2 {
		return 0, 0, fmt.Errorf("invalid Redis script response")
	}
	code, ok := values[0].(int64)
	if !ok {
		return 0, 0, fmt.Errorf("invalid Redis script result code")
	}
	retryAfter, ok := values[1].(int64)
	if !ok || retryAfter < 0 {
		return 0, 0, fmt.Errorf("invalid Redis script retry interval")
	}
	return code, retryAfter, nil
}

func (s *redisReplayStore) currentTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
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

func (s *redisReplayStore) rateKey(keyID string) string {
	sum := sha256.Sum256([]byte(keyID))
	return s.ratePrefix + hex.EncodeToString(sum[:])
}

func replayKeyForTest(prefix string, event ingestEvent) string {
	identity := event.Event + ":" + event.RunID + ":" + event.Gate + ":" + event.Scenario
	sum := sha256.Sum256([]byte(identity))
	return prefix + hex.EncodeToString(sum[:])
}
