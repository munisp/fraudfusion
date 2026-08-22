package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestMultiReplicaRedisIngestionLoad(t *testing.T) {
	const (
		replicas    = 4
		requests    = 2000
		concurrency = 128
	)
	baseStore, redisServer := newRedisReplayForTest(t)
	baseStore.rateLimit = requests + 100
	baseStore.rateWindow = time.Minute
	runMultiReplicaHTTPBenchmark(t, baseStore, redisServer.Addr(), replicas, requests, concurrency)
}

func runMultiReplicaHTTPBenchmark(t *testing.T, baseStore *redisReplayStore, address string, replicas, requests, concurrency int) {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	oldOutput := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(oldOutput) })

	servers := make([]*httptest.Server, 0, replicas)
	stores := make([]*metricsStore, 0, replicas)
	for replica := 0; replica < replicas; replica++ {
		store := baseStore
		if replica > 0 {
			store = newRedisClientStore(t, address, baseStore)
		}
		metrics := newMetricsStore(store)
		stores = append(stores, metrics)
		servers = append(servers, httptest.NewServer(securityHeaders(metrics.ingestHandler(keyring{"current": key}))))
	}
	for _, server := range servers {
		defer server.Close()
	}

	latencies := make([]time.Duration, requests)
	errs := make(chan error, requests)
	jobs := make(chan int)
	var workers sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			client := &http.Client{Timeout: 5 * time.Second}
			for index := range jobs {
				body := `{"event":"ci_gate","gate":"go-race","result":"failure","run_id":"peak-run-` + fixedWidth(index, 6) + `"}`
				timestamp := time.Now().UTC().Format(time.RFC3339)
				request, err := http.NewRequest(http.MethodPost, servers[index%replicas].URL+"/ingest", strings.NewReader(body))
				if err != nil {
					errs <- err
					continue
				}
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("X-FraudFusion-Timestamp", timestamp)
				request.Header.Set("X-FraudFusion-Key-ID", "current")
				request.Header.Set("X-FraudFusion-Signature", signatureForTest(key, "current", timestamp, body))
				started := time.Now()
				response, err := client.Do(request)
				latencies[index] = time.Since(started)
				if err != nil {
					errs <- err
					continue
				}
				_ = response.Body.Close()
				if response.StatusCode != http.StatusAccepted {
					errs <- fmt.Errorf("request %d received HTTP %d", index, response.StatusCode)
				}
			}
		}()
	}
	started := time.Now()
	for request := 0; request < requests; request++ {
		jobs <- request
	}
	close(jobs)
	workers.Wait()
	elapsed := time.Since(started)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}

	accepted := uint64(0)
	for _, store := range stores {
		accepted += store.releaseGateFailure["go-race"].Load()
	}
	if accepted != uint64(requests) {
		t.Fatalf("expected exactly %d globally replay-protected accepted metrics, got %d", requests, accepted)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	t.Logf("multi_replica_load replicas=%d requests=%d concurrency=%d elapsed=%s throughput_rps=%.2f p50=%s p95=%s p99=%s max=%s", replicas, requests, concurrency, elapsed, float64(requests)/elapsed.Seconds(), percentile(latencies, 0.50), percentile(latencies, 0.95), percentile(latencies, 0.99), latencies[len(latencies)-1])
}

func newRedisClientStore(t *testing.T, address string, base *redisReplayStore) *redisReplayStore {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: address})
	store := &redisReplayStore{
		client:     client,
		prefix:     base.prefix,
		ratePrefix: base.ratePrefix,
		ttl:        base.ttl,
		rateLimit:  base.rateLimit,
		rateWindow: base.rateWindow,
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func fixedWidth(value, width int) string {
	text := strconv.Itoa(value)
	for len(text) < width {
		text = "0" + text
	}
	return text
}

func percentile(values []time.Duration, fraction float64) time.Duration {
	index := int(float64(len(values)-1) * fraction)
	return values[index]
}
