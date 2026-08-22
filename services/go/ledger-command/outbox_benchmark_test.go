package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type outboxBenchmarkMetrics struct {
	Benchmark                    string  `json:"benchmark"`
	TenantID                     string  `json:"tenant_id"`
	EventsRequested              int     `json:"events_requested"`
	Workers                      int     `json:"workers"`
	ProviderDelayMilliseconds    int     `json:"provider_delay_milliseconds"`
	TransientFailureModulo       int     `json:"transient_failure_modulo"`
	ElapsedMilliseconds          float64 `json:"elapsed_milliseconds"`
	ThroughputEventsPerSecond    float64 `json:"throughput_events_per_second"`
	PublishedEvents              int     `json:"published_events"`
	FailedEvents                 int     `json:"failed_events"`
	DeadLetterEvents             int     `json:"dead_letter_events"`
	LeasedEvents                 int     `json:"leased_events"`
	TotalDispatchAttempts        int     `json:"total_dispatch_attempts"`
	RetryAttempts                int     `json:"retry_attempts"`
	ProviderRequests             int64   `json:"provider_requests"`
	ProviderTransientFailures    int64   `json:"provider_transient_failures"`
	DuplicateProviderSubmissions int64   `json:"duplicate_provider_submissions"`
	QueueLatencyP50Millis        float64 `json:"queue_latency_p50_milliseconds"`
	QueueLatencyP95Millis        float64 `json:"queue_latency_p95_milliseconds"`
	QueueLatencyP99Millis        float64 `json:"queue_latency_p99_milliseconds"`
	QueueLatencyMaxMillis        float64 `json:"queue_latency_max_milliseconds"`
	StartedAt                    string  `json:"started_at"`
	CompletedAt                  string  `json:"completed_at"`
}

type benchmarkProviderRecorder struct {
	delay         time.Duration
	failureModulo int
	requests      atomic.Int64
	failures      atomic.Int64
	mutex         sync.Mutex
	attempts      map[string]int
}

func TestSettlementOutboxBenchmark(t *testing.T) {
	databaseURL := os.Getenv("LEDGER_OUTBOX_BENCHMARK_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LEDGER_OUTBOX_BENCHMARK_DATABASE_URL not configured")
	}
	config := benchmarkConfigFromEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), config.timeout)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	recorder := &benchmarkProviderRecorder{delay: config.providerDelay, failureModulo: config.failureModulo, attempts: make(map[string]int)}
	providerServer := httptest.NewServer(http.HandlerFunc(recorder.handle))
	defer providerServer.Close()

	testID, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	tenantID := "outbox-benchmark-" + testID
	providerName := "benchmark-provider"
	if err = seedOutboxBenchmark(ctx, pool, tenantID, providerName, config.events); err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now().UTC()
	if _, err = pool.Exec(ctx, `UPDATE ledger_outbox SET created_at=$2,available_at=$2 WHERE tenant_id=$1`, tenantID, startedAt); err != nil {
		t.Fatal(err)
	}

	provider := &settlementProvider{name: providerName, submitURL: providerServer.URL, callbackKey: []byte("01234567890123456789012345678901"), httpClient: providerServer.Client(), maxAttempts: outboxMaxAttempts}
	workers := make([]*settlementDispatcher, 0, config.workers)
	for worker := 0; worker < config.workers; worker++ {
		dispatcher, dispatcherErr := newSettlementDispatcher(pool, provider)
		if dispatcherErr != nil {
			t.Fatal(dispatcherErr)
		}
		workers = append(workers, dispatcher)
	}

	dispatchCtx, stopDispatch := context.WithCancel(ctx)
	defer stopDispatch()
	var workersGroup sync.WaitGroup
	var workerFailure atomic.Value
	for _, dispatcher := range workers {
		workersGroup.Add(1)
		go func(d *settlementDispatcher) {
			defer workersGroup.Done()
			for {
				if dispatchCtx.Err() != nil {
					return
				}
				if dispatchErr := d.dispatchOnce(dispatchCtx); dispatchErr != nil && dispatchCtx.Err() == nil {
					workerFailure.CompareAndSwap(nil, dispatchErr)
					return
				}
				time.Sleep(2 * time.Millisecond)
			}
		}(dispatcher)
	}

	if err = waitForBenchmarkCompletion(ctx, pool, tenantID, config.events); err != nil {
		stopDispatch()
		workersGroup.Wait()
		t.Fatal(err)
	}
	stopDispatch()
	workersGroup.Wait()
	if value := workerFailure.Load(); value != nil {
		t.Fatal(value.(error))
	}
	completedAt := time.Now().UTC()
	metrics, err := collectOutboxBenchmarkMetrics(ctx, pool, tenantID, config, recorder, startedAt, completedAt)
	if err != nil {
		t.Fatal(err)
	}
	if metrics.PublishedEvents != config.events || metrics.FailedEvents != 0 || metrics.DeadLetterEvents != 0 || metrics.LeasedEvents != 0 {
		t.Fatalf("benchmark did not drain safely: %+v", metrics)
	}
	encoded, err := json.Marshal(metrics)
	if err != nil {
		t.Fatal(err)
	}
	if outputPath := os.Getenv("LEDGER_OUTBOX_BENCHMARK_OUTPUT"); outputPath != "" {
		if err = os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(outputPath, append(encoded, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("outbox_benchmark_metrics=%s", encoded)
}

type outboxBenchmarkConfig struct {
	events        int
	workers       int
	providerDelay time.Duration
	failureModulo int
	timeout       time.Duration
}

func benchmarkConfigFromEnv(t *testing.T) outboxBenchmarkConfig {
	t.Helper()
	return outboxBenchmarkConfig{
		events:        positiveBenchmarkEnv(t, "LEDGER_OUTBOX_BENCHMARK_EVENTS", 1000),
		workers:       positiveBenchmarkEnv(t, "LEDGER_OUTBOX_BENCHMARK_WORKERS", 4),
		providerDelay: time.Duration(nonNegativeBenchmarkEnv(t, "LEDGER_OUTBOX_BENCHMARK_PROVIDER_DELAY_MS", 0)) * time.Millisecond,
		failureModulo: nonNegativeBenchmarkEnv(t, "LEDGER_OUTBOX_BENCHMARK_FAILURE_MODULO", 0),
		timeout:       time.Duration(positiveBenchmarkEnv(t, "LEDGER_OUTBOX_BENCHMARK_TIMEOUT_SECONDS", 120)) * time.Second,
	}
}

func positiveBenchmarkEnv(t *testing.T, key string, fallback int) int {
	t.Helper()
	value := nonNegativeBenchmarkEnv(t, key, fallback)
	if value < 1 {
		t.Fatalf("%s must be positive", key)
	}
	return value
}

func nonNegativeBenchmarkEnv(t *testing.T, key string, fallback int) int {
	t.Helper()
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		t.Fatalf("%s must be a non-negative integer", key)
	}
	return parsed
}

func (r *benchmarkProviderRecorder) handle(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.Header.Get("Idempotency-Key") == "" || request.Header.Get("X-FraudFusion-Signature") == "" || request.Header.Get("X-FraudFusion-Timestamp") == "" {
		http.Error(writer, "financial dispatcher omitted required control headers", http.StatusBadRequest)
		return
	}
	idempotencyKey := request.Header.Get("Idempotency-Key")
	r.requests.Add(1)
	r.mutex.Lock()
	r.attempts[idempotencyKey]++
	attempt := r.attempts[idempotencyKey]
	r.mutex.Unlock()
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	sequence, _ := strconv.Atoi(strings.TrimPrefix(idempotencyKey, "benchmark-"))
	if r.failureModulo > 0 && sequence > 0 && sequence%r.failureModulo == 0 && attempt == 1 {
		r.failures.Add(1)
		http.Error(writer, "controlled transient provider failure", http.StatusServiceUnavailable)
		return
	}
	writer.WriteHeader(http.StatusAccepted)
}

func seedOutboxBenchmark(ctx context.Context, pool *pgxpool.Pool, tenantID, providerName string, events int) error {
	debitAccountID, err := randomUUID()
	if err != nil {
		return err
	}
	creditAccountID, err := randomUUID()
	if err != nil {
		return err
	}
	if _, err = pool.Exec(ctx, `INSERT INTO ledger_accounts (id,tenant_id,account_code,account_type,currency) VALUES ($1::uuid,$2,'benchmark-debit','asset','USD'),($3::uuid,$2,'benchmark-credit','liability','USD')`, debitAccountID, tenantID, creditAccountID); err != nil {
		return err
	}
	for sequence := 1; sequence <= events; sequence++ {
		journalID, journalErr := randomUUID()
		if journalErr != nil {
			return journalErr
		}
		debitPostingID, journalErr := randomUUID()
		if journalErr != nil {
			return journalErr
		}
		creditPostingID, journalErr := randomUUID()
		if journalErr != nil {
			return journalErr
		}
		settlementID, journalErr := randomUUID()
		if journalErr != nil {
			return journalErr
		}
		outboxID, journalErr := randomUUID()
		if journalErr != nil {
			return journalErr
		}
		idempotencyKey := fmt.Sprintf("benchmark-%d", sequence)
		commandDigest := fmt.Sprintf("%064x", sequence)
		payload, journalErr := json.Marshal(providerSubmission{SettlementID: settlementID, Provider: providerName, JournalID: journalID, TenantID: tenantID})
		if journalErr != nil {
			return journalErr
		}
		tx, journalErr := pool.Begin(ctx)
		if journalErr != nil {
			return journalErr
		}
		_, journalErr = tx.Exec(ctx, `INSERT INTO ledger_journals (id,tenant_id,idempotency_key,command_sha256,journal_type,actor_id,external_reference) VALUES ($1::uuid,$2,$3,$4,'settlement','outbox-benchmark',$5)`, journalID, tenantID, idempotencyKey, commandDigest, idempotencyKey)
		if journalErr == nil {
			_, journalErr = tx.Exec(ctx, `INSERT INTO ledger_postings (id,tenant_id,journal_id,account_id,direction,amount,currency) VALUES ($1::uuid,$2,$3::uuid,$4::uuid,'D',1.000000,'USD'),($5::uuid,$2,$3::uuid,$6::uuid,'C',1.000000,'USD')`, debitPostingID, tenantID, journalID, debitAccountID, creditPostingID, creditAccountID)
		}
		if journalErr == nil {
			_, journalErr = tx.Exec(ctx, `INSERT INTO settlement_items (id,tenant_id,journal_id,provider,provider_reference,direction,amount,currency,status) VALUES ($1::uuid,$2,$3::uuid,$4,$5,'outbound',1.000000,'USD','pending')`, settlementID, tenantID, journalID, providerName, "benchmark-reference-"+idempotencyKey)
		}
		if journalErr == nil {
			_, journalErr = tx.Exec(ctx, `INSERT INTO ledger_outbox (id,tenant_id,journal_id,event_type,idempotency_key,payload) VALUES ($1::uuid,$2,$3::uuid,'settlement.submit',$4,$5::jsonb)`, outboxID, tenantID, journalID, idempotencyKey, string(payload))
		}
		if journalErr != nil {
			_ = tx.Rollback(ctx)
			return journalErr
		}
		if journalErr = tx.Commit(ctx); journalErr != nil {
			return journalErr
		}
	}
	return nil
}

func waitForBenchmarkCompletion(ctx context.Context, pool *pgxpool.Pool, tenantID string, expected int) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var published, deadLetter int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FILTER (WHERE status='published'),COUNT(*) FILTER (WHERE status='dead_letter') FROM ledger_outbox WHERE tenant_id=$1`, tenantID).Scan(&published, &deadLetter); err != nil {
			return err
		}
		if deadLetter > 0 {
			return fmt.Errorf("benchmark observed %d dead-lettered outbox events", deadLetter)
		}
		if published == expected {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("benchmark timeout after %s: published=%d expected=%d", ctx.Err(), published, expected)
		case <-ticker.C:
		}
	}
}

func collectOutboxBenchmarkMetrics(ctx context.Context, pool *pgxpool.Pool, tenantID string, config outboxBenchmarkConfig, recorder *benchmarkProviderRecorder, startedAt, completedAt time.Time) (outboxBenchmarkMetrics, error) {
	metrics := outboxBenchmarkMetrics{Benchmark: "settlement_outbox_dispatcher", TenantID: tenantID, EventsRequested: config.events, Workers: config.workers, ProviderDelayMilliseconds: int(config.providerDelay / time.Millisecond), TransientFailureModulo: config.failureModulo, StartedAt: startedAt.Format(time.RFC3339Nano), CompletedAt: completedAt.Format(time.RFC3339Nano)}
	metrics.ElapsedMilliseconds = float64(completedAt.Sub(startedAt)) / float64(time.Millisecond)
	metrics.ThroughputEventsPerSecond = float64(config.events) / completedAt.Sub(startedAt).Seconds()
	var totalAttempts int64
	err := pool.QueryRow(ctx, `
SELECT COUNT(*) FILTER (WHERE status='published'),
       COUNT(*) FILTER (WHERE status='failed'),
       COUNT(*) FILTER (WHERE status='dead_letter'),
       COUNT(*) FILTER (WHERE status='leased'),
       COALESCE(SUM(attempts),0),
       COALESCE(percentile_cont(0.50) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (published_at-created_at))*1000) FILTER (WHERE status='published'),0),
       COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (published_at-created_at))*1000) FILTER (WHERE status='published'),0),
       COALESCE(percentile_cont(0.99) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (published_at-created_at))*1000) FILTER (WHERE status='published'),0),
       COALESCE(MAX(EXTRACT(EPOCH FROM (published_at-created_at))*1000) FILTER (WHERE status='published'),0)
  FROM ledger_outbox
 WHERE tenant_id=$1`, tenantID).Scan(&metrics.PublishedEvents, &metrics.FailedEvents, &metrics.DeadLetterEvents, &metrics.LeasedEvents, &totalAttempts, &metrics.QueueLatencyP50Millis, &metrics.QueueLatencyP95Millis, &metrics.QueueLatencyP99Millis, &metrics.QueueLatencyMaxMillis)
	if err != nil {
		return outboxBenchmarkMetrics{}, err
	}
	metrics.TotalDispatchAttempts = int(totalAttempts)
	metrics.RetryAttempts = metrics.TotalDispatchAttempts - metrics.EventsRequested
	metrics.ProviderRequests = recorder.requests.Load()
	metrics.ProviderTransientFailures = recorder.failures.Load()
	metrics.DuplicateProviderSubmissions = metrics.ProviderRequests - int64(metrics.PublishedEvents)
	return metrics, nil
}
