package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestRedisMasterLossFailsClosedDuringMultiReplicaLoad(t *testing.T) {
	address := os.Getenv("REDIS_CHAOS_TEST_ADDR")
	if address == "" {
		t.Skip("set REDIS_CHAOS_TEST_ADDR to run the real Redis master-loss scenario")
	}
	const (
		replicas    = 4
		requests    = 1000
		concurrency = 96
	)
	controller := redis.NewClient(&redis.Options{Addr: address})
	if err := controller.FlushDB(context.Background()).Err(); err != nil {
		t.Fatalf("flush Redis before master-loss test: %v", err)
	}
	base := &redisReplayStore{
		client:     controller,
		prefix:     "chaos:replay:v1:",
		ratePrefix: "chaos:rate:v1:",
		ttl:        time.Hour,
		rateLimit:  requests + 100,
		rateWindow: time.Minute,
	}
	defer func() { _ = controller.Close() }()

	oldOutput := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(oldOutput) })
	key := []byte("0123456789abcdef0123456789abcdef")
	servers := make([]*httptest.Server, 0, replicas)
	stores := make([]*metricsStore, 0, replicas)
	for replica := 0; replica < replicas; replica++ {
		store := base
		if replica > 0 {
			store = newRedisClientStore(t, address, base)
		}
		metrics := newMetricsStore(store)
		stores = append(stores, metrics)
		servers = append(servers, httptest.NewServer(securityHeaders(metrics.ingestHandler(keyring{"current": key}))))
	}
	for _, server := range servers {
		defer server.Close()
	}

	var started, accepted, unavailable atomic.Uint64
	jobs := make(chan int)
	errs := make(chan error, requests)
	var workers sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			client := &http.Client{Timeout: 3 * time.Second}
			for index := range jobs {
				body := `{"event":"ci_gate","gate":"go-race","result":"failure","run_id":"master-loss-` + fixedWidth(index, 6) + `"}`
				timestamp := time.Now().UTC().Format(time.RFC3339)
				request := signedRequestForTest(t, servers[index%replicas].URL+"/ingest", key, timestamp, body)
				started.Add(1)
				response, err := client.Do(request)
				if err != nil {
					errs <- err
					continue
				}
				_ = response.Body.Close()
				switch response.StatusCode {
				case http.StatusAccepted:
					accepted.Add(1)
				case http.StatusServiceUnavailable:
					unavailable.Add(1)
				default:
					errs <- statusError(index, response.StatusCode)
				}
			}
		}()
	}
	shutdownDone := make(chan error, 1)
	go func() {
		for started.Load() < 120 {
			time.Sleep(time.Millisecond)
		}
		shutdownDone <- controller.ShutdownNoSave(context.Background()).Err()
	}()
	for request := 0; request < requests; request++ {
		jobs <- request
	}
	close(jobs)
	workers.Wait()
	if err := <-shutdownDone; err != nil && err != redis.Nil {
		// Redis can close the TCP socket before sending a SHUTDOWN reply. Confirming
		// that a subsequent ping fails distinguishes that expected transport reset
		// from a master that remained available.
		if pingErr := controller.Ping(context.Background()).Err(); pingErr == nil {
			t.Fatalf("shutdown Redis master: %v", err)
		}
	}
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	if accepted.Load() == 0 || unavailable.Load() == 0 {
		t.Fatalf("expected accepted traffic before loss and 503 after loss; accepted=%d unavailable=%d", accepted.Load(), unavailable.Load())
	}
	counted := uint64(0)
	for _, store := range stores {
		counted += store.releaseGateFailure["go-race"].Load()
	}
	if counted != accepted.Load() {
		t.Fatalf("metric must be emitted only for accepted events; metric=%d accepted=%d unavailable=%d", counted, accepted.Load(), unavailable.Load())
	}
	t.Logf("redis_master_loss replicas=%d requests=%d concurrency=%d accepted=%d unavailable_503=%d metric_count=%d", replicas, requests, concurrency, accepted.Load(), unavailable.Load(), counted)
}

func signedRequestForTest(t *testing.T, endpoint string, key []byte, timestamp, body string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-FraudFusion-Timestamp", timestamp)
	request.Header.Set("X-FraudFusion-Key-ID", "current")
	request.Header.Set("X-FraudFusion-Signature", signatureForTest(key, "current", timestamp, body))
	return request
}

func statusError(index, status int) error {
	return fmt.Errorf("request %d received HTTP %d", index, status)
}
