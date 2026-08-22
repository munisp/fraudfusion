package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryReplayStore struct {
	mu     sync.Mutex
	claims map[string]struct{}
	err    error
}

func newMemoryReplayStore() *memoryReplayStore {
	return &memoryReplayStore{claims: make(map[string]struct{})}
}

func (s *memoryReplayStore) Claim(_ context.Context, eventID string) (claimResult, error) {
	if s.err != nil {
		return claimDuplicate, s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, found := s.claims[eventID]; found {
		return claimDuplicate, nil
	}
	s.claims[eventID] = struct{}{}
	return claimAccepted, nil
}

func (s *memoryReplayStore) Health(_ context.Context) error { return s.err }

func (s *memoryReplayStore) Close() error { return nil }

func signatureForTest(key []byte, keyID, timestamp, body string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(keyID))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

func newTestStore() *metricsStore { return newMetricsStore(newMemoryReplayStore()) }

func signedRequest(t *testing.T, key []byte, keyID, timestamp, body, contentType string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-FraudFusion-Timestamp", timestamp)
	req.Header.Set("X-FraudFusion-Key-ID", keyID)
	req.Header.Set("X-FraudFusion-Signature", signatureForTest(key, keyID, timestamp, body))
	return req
}

func TestIngestAcceptsKeyIDBoundSignatureAndRejectsTampering(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	store := newTestStore()
	handler := store.ingestHandler(keyring{"current": key})
	body := `{"event":"ci_gate","gate":"dependency-security","result":"failure","run_id":"test-run-0001"}`
	timestamp := time.Now().UTC().Format(time.RFC3339)

	accepted := httptest.NewRecorder()
	handler(accepted, signedRequest(t, key, "current", timestamp, body, "application/json; charset=utf-8"))
	if accepted.Code != http.StatusAccepted || store.releaseGateFailure["dependency-security"].Load() != 1 {
		t.Fatalf("expected accepted single metric, status=%d count=%d", accepted.Code, store.releaseGateFailure["dependency-security"].Load())
	}

	altered := signedRequest(t, key, "current", timestamp, body+" ", "application/json")
	altered.Header.Set("X-FraudFusion-Signature", signatureForTest(key, "current", timestamp, body))
	denied := httptest.NewRecorder()
	handler(denied, altered)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("expected tampered request rejection, got %d", denied.Code)
	}
}

func TestIngestIsReplaySafeAndFailsClosedOnReplayStoreError(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	replay := newMemoryReplayStore()
	store := newMetricsStore(replay)
	handler := store.ingestHandler(keyring{"current": key})
	body := `{"event":"e2e_scenario","scenario":"kyc-session-create","result":"success","run_id":"test-run-0002"}`
	timestamp := time.Now().UTC().Format(time.RFC3339)
	for i := 0; i < 2; i++ {
		response := httptest.NewRecorder()
		handler(response, signedRequest(t, key, "current", timestamp, body, "application/json"))
		if response.Code != http.StatusAccepted {
			t.Fatalf("expected idempotent accepted response, got %d", response.Code)
		}
	}
	if got := store.e2eScenario["kyc-session-create"]["success"].Load(); got != 1 {
		t.Fatalf("expected one replay-safe event, got %d", got)
	}
	replay.err = errors.New("redis unavailable")
	failure := httptest.NewRecorder()
	body = `{"event":"ci_gate","gate":"go-race","result":"success","run_id":"test-run-0003"}`
	handler(failure, signedRequest(t, key, "current", timestamp, body, "application/json"))
	if failure.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected fail-closed replay dependency error, got %d", failure.Code)
	}
}

func TestIngestRejectsMalformedRequests(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	handler := newTestStore().ingestHandler(keyring{"current": key})
	valid := `{"event":"ci_gate","gate":"go-race","result":"success","run_id":"test-run-0004"}`
	cases := []struct {
		name, timestamp, body, contentType, keyID, signature string
		want                                                 int
	}{
		{"media", time.Now().UTC().Format(time.RFC3339), valid, "text/plain", "current", "", http.StatusUnsupportedMediaType},
		{"time", "bad-time", valid, "application/json", "current", "", http.StatusUnauthorized},
		{"unknown-key", time.Now().UTC().Format(time.RFC3339), valid, "application/json", "unknown", "", http.StatusUnauthorized},
		{"bad-json", time.Now().UTC().Format(time.RFC3339), "{", "application/json", "current", "", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := signedRequest(t, key, tc.keyID, tc.timestamp, tc.body, tc.contentType)
			response := httptest.NewRecorder()
			handler(response, request)
			if response.Code != tc.want {
				t.Fatalf("expected %d, got %d", tc.want, response.Code)
			}
		})
	}
	overSize := httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(strings.Repeat("x", maxRequestBytes+1)))
	overSize.Header.Set("Content-Type", "application/json")
	overSize.Header.Set("X-FraudFusion-Timestamp", time.Now().UTC().Format(time.RFC3339))
	response := httptest.NewRecorder()
	handler(response, overSize)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected oversized rejection, got %d", response.Code)
	}
}

func TestKeyringEventValidationAndMetricsOutput(t *testing.T) {
	t.Setenv("RELEASE_GATE_INGEST_HMAC_SECRET", "")
	t.Setenv("RELEASE_GATE_INGEST_HMAC_KEYS_JSON", `{"previous":"0123456789abcdef0123456789abcdef","current":"abcdef0123456789abcdef0123456789"}`)
	keys, err := loadKeyring()
	if err != nil || len(keys) != 2 {
		t.Fatalf("expected key rotation configuration, keys=%v err=%v", len(keys), err)
	}
	if validEvent(ingestEvent{Event: "ci_gate", Gate: "untrusted", Result: "success", RunID: "test-run-0005"}) {
		t.Fatal("expected untrusted gate rejection")
	}
	store := newTestStore()
	store.recordMetric(ingestEvent{Event: "ci_gate", Gate: "go-race", Result: "failure"})
	metrics := httptest.NewRecorder()
	store.writeMetrics(metrics, "staging")
	if !strings.Contains(metrics.Body.String(), `fraudfusion_release_gate_failures_total{environment="staging",gate="go-race"} 1`) {
		t.Fatalf("missing expected metrics: %s", metrics.Body.String())
	}
}

func TestRunWithReplayValidatesStartupAndHealth(t *testing.T) {
	t.Setenv("RELEASE_GATE_INGEST_HMAC_KEYS_JSON", `{"current":"0123456789abcdef0123456789abcdef"}`)
	t.Setenv("RELEASE_GATE_INGEST_HMAC_SECRET", "")
	t.Setenv("ENVIRONMENT", "staging")
	var captured *http.Server
	if err := runWithReplay(func(context.Context) (replayStore, error) { return newMemoryReplayStore(), nil }, func(server *http.Server) error { captured = server; return nil }); err != nil {
		t.Fatalf("unexpected startup error: %v", err)
	}
	response := httptest.NewRecorder()
	captured.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusOK || response.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("expected healthy secured server, got %d %#v", response.Code, response.Header())
	}
	ready := httptest.NewRecorder()
	captured.Handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusOK || ready.Body.String() != `{"status":"ready"}` {
		t.Fatalf("expected ready replay-backed server, got %d %s", ready.Code, ready.Body.String())
	}
	if err := runWithReplay(func(context.Context) (replayStore, error) { return nil, errors.New("unavailable") }, func(*http.Server) error { return nil }); err == nil {
		t.Fatal("expected unavailable replay store to block startup")
	}
}
