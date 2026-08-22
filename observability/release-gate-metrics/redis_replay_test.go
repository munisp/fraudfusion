package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newRedisReplayForTest(t *testing.T) (*redisReplayStore, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	store := &redisReplayStore{client: client, prefix: "test:replay:v1:", ttl: time.Hour}
	t.Cleanup(func() { _ = store.Close() })
	return store, server
}

func TestRedisReplayClaimIsAtomicAcrossConcurrentStores(t *testing.T) {
	storeA, server := newRedisReplayForTest(t)
	clientB := redis.NewClient(&redis.Options{Addr: server.Addr()})
	storeB := &redisReplayStore{client: clientB, prefix: storeA.prefix, ttl: time.Hour}
	t.Cleanup(func() { _ = storeB.Close() })

	const attempts = 128
	results := make(chan claimResult, attempts)
	errs := make(chan error, attempts)
	var workers sync.WaitGroup
	for i := 0; i < attempts; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			store := storeA
			if i%2 == 1 {
				store = storeB
			}
			result, err := store.Claim(context.Background(), strings.Repeat("a", 64))
			if err != nil {
				errs <- err
				return
			}
			results <- result
		}(i)
	}
	workers.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	accepted := 0
	for result := range results {
		if result == claimAccepted {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("expected exactly one distributed claim, got %d", accepted)
	}
}

func TestRedisReplayClaimExpiresAndHashesIdentity(t *testing.T) {
	store, server := newRedisReplayForTest(t)
	store.ttl = time.Minute
	event := ingestEvent{Event: "ci_gate", Gate: "go-race", Result: "success", RunID: "test-run-redis-0001"}
	id := replayEventID(event)
	if strings.Contains(store.key(id), event.RunID) {
		t.Fatal("replay key must not reveal run ID")
	}
	if result, err := store.Claim(context.Background(), id); err != nil || result != claimAccepted {
		t.Fatalf("expected initial claim, result=%v err=%v", result, err)
	}
	if ttl := server.TTL(store.key(id)); ttl != time.Minute {
		t.Fatalf("expected one-minute TTL, got %s", ttl)
	}
	server.FastForward(time.Minute)
	if result, err := store.Claim(context.Background(), id); err != nil || result != claimAccepted {
		t.Fatalf("expected accepted claim after TTL expiry, result=%v err=%v", result, err)
	}
}

func TestRedisReplayRejectsInvalidIdentityAndFailsClosed(t *testing.T) {
	store, server := newRedisReplayForTest(t)
	if _, err := store.Claim(context.Background(), "short"); err == nil {
		t.Fatal("expected invalid identity rejection")
	}
	server.Close()
	if _, err := store.Claim(context.Background(), strings.Repeat("b", 64)); err == nil {
		t.Fatal("expected unavailable Redis failure")
	}
}

func TestLoadRedisReplayStoreRequiresSecureConfiguration(t *testing.T) {
	t.Setenv("REDIS_ADDR", "")
	if _, err := loadRedisReplayStore(context.Background()); err == nil {
		t.Fatal("expected missing REDIS_ADDR error")
	}
	t.Setenv("REDIS_ADDR", "127.0.0.1:1")
	t.Setenv("REDIS_TLS", "")
	if _, err := loadRedisReplayStore(context.Background()); err == nil || !strings.Contains(err.Error(), "REDIS_TLS") {
		t.Fatalf("expected mandatory TLS rejection, got %v", err)
	}
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_SERVER_NAME", "")
	if _, err := loadRedisReplayStore(context.Background()); err == nil || !strings.Contains(err.Error(), "REDIS_TLS_SERVER_NAME") {
		t.Fatalf("expected mandatory TLS server name rejection, got %v", err)
	}
	t.Setenv("REDIS_TLS_SERVER_NAME", "localhost")
	if _, err := loadRedisReplayStore(context.Background()); err == nil || !strings.Contains(err.Error(), "ping Redis") {
		t.Fatalf("expected Redis ping failure, got %v", err)
	}
}

func TestRedisPartitionFailsClosedWithoutMetricEmission(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	replay, server := newRedisReplayForTest(t)
	store := newMetricsStore(replay)
	handler := store.ingestHandler(keyring{"current": key})
	server.Close() // Simulates a network partition after a producer replica is already running.

	body := `{"event":"ci_gate","gate":"dependency-security","result":"failure","run_id":"test-run-partition-0001"}`
	request := signedRequest(t, key, "current", time.Now().UTC().Format(time.RFC3339), body, "application/json")
	response := httptest.NewRecorder()
	handler(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected fail-closed 503 during Redis partition, got %d", response.Code)
	}
	if got := store.releaseGateFailure["dependency-security"].Load(); got != 0 {
		t.Fatalf("partitioned replay store must not emit a failure metric, got %d", got)
	}

	serverHTTP := newServer(keyring{"current": key}, "staging", replay)
	ready := httptest.NewRecorder()
	serverHTTP.Handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected readiness to fail closed during Redis partition, got %d", ready.Code)
	}
}
