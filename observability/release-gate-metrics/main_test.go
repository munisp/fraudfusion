package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func signatureForTest(key []byte, keyID, timestamp, body string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(keyID))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

func newTestStore() *metricsStore {
	return &metricsStore{
		releaseGateFailure: make(map[string]uint64),
		e2eScenario:        make(map[string]map[string]uint64),
		seenEvents:         make(map[string]time.Time),
	}
}

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
	keys := keyring{"current": key}
	store := newTestStore()
	handler := store.ingestHandler(keys)
	body := `{"event":"ci_gate","gate":"dependency-security","result":"failure","run_id":"test-run-0001"}`
	timestamp := time.Now().UTC().Format(time.RFC3339)

	accepted := httptest.NewRecorder()
	handler(accepted, signedRequest(t, key, "current", timestamp, body, "application/json; charset=utf-8"))
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("expected accepted event, got %d", accepted.Code)
	}
	if got := store.releaseGateFailure["dependency-security"]; got != 1 {
		t.Fatalf("expected one failure metric, got %d", got)
	}

	wrongKeyID := signedRequest(t, key, "previous", timestamp, body, "application/json")
	wrongKeyID.Header.Set("X-FraudFusion-Signature", signatureForTest(key, "current", timestamp, body))
	denied := httptest.NewRecorder()
	handler(denied, wrongKeyID)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("expected key-ID tampering rejection, got %d", denied.Code)
	}

	alteredBody := body + " "
	altered := signedRequest(t, key, "current", timestamp, alteredBody, "application/json")
	altered.Header.Set("X-FraudFusion-Signature", signatureForTest(key, "current", timestamp, body))
	denied = httptest.NewRecorder()
	handler(denied, altered)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("expected body tampering rejection, got %d", denied.Code)
	}
}

func TestIngestRejectsReplayAndExpiredTimestamp(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	keys := keyring{"current": key}
	store := newTestStore()
	handler := store.ingestHandler(keys)
	body := `{"event":"e2e_scenario","scenario":"kyc-session-create","result":"success","run_id":"test-run-0002"}`
	timestamp := time.Now().UTC().Format(time.RFC3339)
	req := signedRequest(t, key, "current", timestamp, body, "application/json")

	first := httptest.NewRecorder()
	handler(first, req)
	if first.Code != http.StatusAccepted {
		t.Fatalf("expected first request accepted, got %d", first.Code)
	}
	second := httptest.NewRecorder()
	handler(second, signedRequest(t, key, "current", timestamp, body, "application/json"))
	if second.Code != http.StatusAccepted {
		t.Fatalf("expected replay to be idempotently accepted, got %d", second.Code)
	}
	if got := store.e2eScenario["kyc-session-create"]["success"]; got != 1 {
		t.Fatalf("expected one counted replay-safe event, got %d", got)
	}

	expiredTimestamp := time.Now().Add(-clockSkew - time.Second).UTC().Format(time.RFC3339)
	expired := httptest.NewRecorder()
	handler(expired, signedRequest(t, key, "current", expiredTimestamp, body, "application/json"))
	if expired.Code != http.StatusUnauthorized {
		t.Fatalf("expected expired timestamp rejection, got %d", expired.Code)
	}
}

func TestIngestRejectsUnsupportedMediaType(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	store := newTestStore()
	handler := store.ingestHandler(keyring{"current": key})
	body := `{"event":"ci_gate","gate":"go-race","result":"success","run_id":"test-run-0003"}`
	timestamp := time.Now().UTC().Format(time.RFC3339)
	response := httptest.NewRecorder()
	handler(response, signedRequest(t, key, "current", timestamp, body, "text/plain"))
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected unsupported media type rejection, got %d", response.Code)
	}
}

func TestLoadKeyringSupportsRotationAndRejectsInvalidConfiguration(t *testing.T) {
	t.Setenv("RELEASE_GATE_INGEST_HMAC_SECRET", "")
	t.Setenv("RELEASE_GATE_INGEST_HMAC_KEYS_JSON", `{"previous":"0123456789abcdef0123456789abcdef","current":"abcdef0123456789abcdef0123456789"}`)
	keys, err := loadKeyring()
	if err != nil {
		t.Fatalf("expected rotated keyring to load: %v", err)
	}
	if len(keys) != 2 || string(keys["current"]) != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("unexpected keyring: %#v", keys)
	}

	t.Setenv("RELEASE_GATE_INGEST_HMAC_KEYS_JSON", `{"bad key":"0123456789abcdef0123456789abcdef"}`)
	if _, err := loadKeyring(); err == nil {
		t.Fatal("expected invalid key identifier rejection")
	}

	t.Setenv("RELEASE_GATE_INGEST_HMAC_KEYS_JSON", "{")
	if _, err := loadKeyring(); err == nil {
		t.Fatal("expected invalid JSON rejection")
	}

	t.Setenv("RELEASE_GATE_INGEST_HMAC_KEYS_JSON", "")
	t.Setenv("RELEASE_GATE_INGEST_HMAC_SECRET", "0123456789abcdef0123456789abcdef")
	legacy, err := loadKeyring()
	if err != nil || string(legacy[defaultKeyID]) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("expected legacy key fallback, keys=%#v err=%v", legacy, err)
	}
}

func TestValidKeyID(t *testing.T) {
	for _, keyID := range []string{"current", "key-2026_01", "A1"} {
		if !validKeyID(keyID) {
			t.Fatalf("expected valid key id %q", keyID)
		}
	}
	for _, keyID := range []string{"", "bad key", "newline\n", strings.Repeat("a", 65)} {
		if validKeyID(keyID) {
			t.Fatalf("expected invalid key id %q", keyID)
		}
	}
}

func TestSecurityHeadersAndMetricOutputAreDeterministic(t *testing.T) {
	store := newTestStore()
	store.releaseGateFailure["go-race"] = 2
	store.releaseGateFailure["dependency-security"] = 1
	store.e2eScenario["kyc-session-create"] = map[string]uint64{"success": 2, "failure": 1}

	metrics := httptest.NewRecorder()
	store.writeMetrics(metrics, "staging")
	output := metrics.Body.String()
	if !strings.Contains(output, `fraudfusion_release_gate_failures_total{environment="staging",gate="dependency-security"} 1`) {
		t.Fatalf("missing expected metric output: %s", output)
	}
	if strings.Index(output, `gate="dependency-security"`) > strings.Index(output, `gate="go-race"`) {
		t.Fatalf("expected sorted metric output: %s", output)
	}

	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing security headers: %#v", response.Header())
	}
}

func TestRecordCapacityIsExplicitlyRejected(t *testing.T) {
	store := newTestStore()
	now := time.Now()
	for i := 0; i < maxReplayEntries; i++ {
		store.seenEvents["prior-"+string(rune(i))] = now
	}
	result := store.record(ingestEvent{Event: "ci_gate", Gate: "go-race", Result: "success", RunID: "test-run-capacity"})
	if result != recordCapacityExceeded {
		t.Fatalf("expected capacity rejection, got %d", result)
	}
}

func TestIngestRejectsBadJSONAndInvalidSignatureEncoding(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	store := newTestStore()
	handler := store.ingestHandler(keyring{"current": key})
	timestamp := time.Now().UTC().Format(time.RFC3339)

	badJSON := signedRequest(t, key, "current", timestamp, "{", "application/json")
	response := httptest.NewRecorder()
	handler(response, badJSON)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected bad JSON rejection, got %d", response.Code)
	}

	body := `{"event":"ci_gate","gate":"go-race","result":"success","run_id":"test-run-0004"}`
	badSignature := signedRequest(t, key, "current", timestamp, body, "application/json")
	badSignature.Header.Set("X-FraudFusion-Signature", "not-hex")
	response = httptest.NewRecorder()
	handler(response, badSignature)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected invalid signature encoding rejection, got %d", response.Code)
	}
}

func TestIngestRejectsMalformedFutureOversizedAndUnknownKeyRequests(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	store := newTestStore()
	handler := store.ingestHandler(keyring{"current": key})
	body := `{"event":"ci_gate","gate":"go-race","result":"success","run_id":"test-run-0005"}`

	malformed := signedRequest(t, key, "current", "not-a-timestamp", body, "application/json")
	response := httptest.NewRecorder()
	handler(response, malformed)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected malformed timestamp rejection, got %d", response.Code)
	}

	futureTimestamp := time.Now().Add(clockSkew + time.Second).UTC().Format(time.RFC3339)
	future := signedRequest(t, key, "current", futureTimestamp, body, "application/json")
	response = httptest.NewRecorder()
	handler(response, future)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected future timestamp rejection, got %d", response.Code)
	}

	unknownKey := signedRequest(t, key, "unknown", time.Now().UTC().Format(time.RFC3339), body, "application/json")
	response = httptest.NewRecorder()
	handler(response, unknownKey)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected unknown key rejection, got %d", response.Code)
	}

	overSize := strings.Repeat("x", maxRequestBytes+1)
	overSizeRequest := httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(overSize))
	overSizeRequest.Header.Set("Content-Type", "application/json")
	overSizeRequest.Header.Set("X-FraudFusion-Timestamp", time.Now().UTC().Format(time.RFC3339))
	response = httptest.NewRecorder()
	handler(response, overSizeRequest)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected oversized request rejection, got %d", response.Code)
	}
}

func TestIngestDefaultsCurrentKeyIDAndReturnsCapacityError(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	store := newTestStore()
	for i := 0; i < maxReplayEntries; i++ {
		store.seenEvents[fmt.Sprintf("entry-%d", i)] = time.Now()
	}
	handler := store.ingestHandler(keyring{"current": key})
	body := `{"event":"ci_gate","gate":"go-race","result":"success","run_id":"test-run-0006"}`
	timestamp := time.Now().UTC().Format(time.RFC3339)
	req := signedRequest(t, key, "current", timestamp, body, "application/json")
	req.Header.Del("X-FraudFusion-Key-ID")
	response := httptest.NewRecorder()
	handler(response, req)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected capacity error using default key ID, got %d", response.Code)
	}
}

func TestLoadKeyringAndValidEventDefensiveBranches(t *testing.T) {
	t.Setenv("RELEASE_GATE_INGEST_HMAC_KEYS_JSON", "{}")
	t.Setenv("RELEASE_GATE_INGEST_HMAC_SECRET", "")
	if _, err := loadKeyring(); err == nil {
		t.Fatal("expected empty keyring rejection")
	}
	t.Setenv("RELEASE_GATE_INGEST_HMAC_KEYS_JSON", "")
	t.Setenv("RELEASE_GATE_INGEST_HMAC_SECRET", "short")
	if _, err := loadKeyring(); err == nil {
		t.Fatal("expected short legacy secret rejection")
	}

	invalidEvents := []ingestEvent{
		{Event: "unknown", Result: "success", RunID: "test-run-0007"},
		{Event: "ci_gate", Gate: "not-allowed", Result: "success", RunID: "test-run-0007"},
		{Event: "ci_gate", Gate: "go-race", Result: "other", RunID: "test-run-0007"},
		{Event: "e2e_scenario", Scenario: "not-allowed", Result: "success", RunID: "test-run-0007"},
		{Event: "e2e_scenario", Scenario: "kyc-session-create", Result: "success", Gate: "go-race", RunID: "test-run-0007"},
		{Event: "ci_gate", Gate: "go-race", Result: "success", RunID: "short"},
	}
	for _, event := range invalidEvents {
		if validEvent(event) {
			t.Fatalf("expected invalid event rejection: %#v", event)
		}
	}
}

func TestRecordRemovesExpiredEntries(t *testing.T) {
	store := newTestStore()
	store.seenEvents["expired"] = time.Now().Add(-25 * time.Hour)
	result := store.record(ingestEvent{Event: "ci_gate", Gate: "go-race", Result: "success", RunID: "test-run-0008"})
	if result != recordAccepted {
		t.Fatalf("expected accepted event after expiration cleanup, got %d", result)
	}
	if _, found := store.seenEvents["expired"]; found {
		t.Fatal("expected expired replay entry to be removed")
	}
}

func TestRunBuildsServerWithValidConfiguration(t *testing.T) {
	t.Setenv("RELEASE_GATE_INGEST_HMAC_KEYS_JSON", `{"current":"0123456789abcdef0123456789abcdef"}`)
	t.Setenv("RELEASE_GATE_INGEST_HMAC_SECRET", "")
	t.Setenv("ENVIRONMENT", "staging")
	var captured *http.Server
	if err := run(func(server *http.Server) error {
		captured = server
		return nil
	}); err != nil {
		t.Fatalf("expected valid startup configuration, got %v", err)
	}
	if captured == nil || captured.Addr != ":8080" {
		t.Fatalf("unexpected constructed server: %#v", captured)
	}
	health := httptest.NewRecorder()
	captured.Handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || health.Body.String() != `{"status":"ok"}` {
		t.Fatalf("unexpected health response: code=%d body=%s", health.Code, health.Body.String())
	}
}

func TestRunRejectsMissingEnvironmentAndInvalidKeyring(t *testing.T) {
	t.Setenv("RELEASE_GATE_INGEST_HMAC_KEYS_JSON", `{"current":"0123456789abcdef0123456789abcdef"}`)
	t.Setenv("RELEASE_GATE_INGEST_HMAC_SECRET", "")
	t.Setenv("ENVIRONMENT", "")
	if err := run(func(*http.Server) error { return nil }); err == nil {
		t.Fatal("expected missing environment rejection")
	}

	t.Setenv("RELEASE_GATE_INGEST_HMAC_KEYS_JSON", "{")
	t.Setenv("ENVIRONMENT", "staging")
	if err := run(func(*http.Server) error { return nil }); err == nil {
		t.Fatal("expected invalid keyring rejection")
	}
}
