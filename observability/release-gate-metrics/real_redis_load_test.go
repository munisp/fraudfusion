package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestMultiReplicaRealRedisIngestionLoad(t *testing.T) {
	address := os.Getenv("REDIS_LOAD_TEST_ADDR")
	if address == "" {
		t.Skip("set REDIS_LOAD_TEST_ADDR to run against a real Redis server")
	}
	client := redis.NewClient(&redis.Options{Addr: address})
	if err := client.FlushDB(context.Background()).Err(); err != nil {
		t.Fatalf("flush real Redis test database: %v", err)
	}
	base := &redisReplayStore{
		client:     client,
		prefix:     "load:replay:v1:",
		ratePrefix: "load:rate:v1:",
		ttl:        time.Hour,
		rateLimit:  2100,
		rateWindow: time.Minute,
	}
	t.Cleanup(func() { _ = base.Close() })
	runMultiReplicaHTTPBenchmark(t, base, address, 4, 2000, 128)
}
