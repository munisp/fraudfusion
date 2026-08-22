package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

const (
	maxRequestBytes = 16 << 10
	clockSkew       = 5 * time.Minute
	defaultKeyID    = "current"
	replayTTL       = 24 * time.Hour
	replayOpTimeout = 2 * time.Second
)

type ingestEvent struct {
	Event     string `json:"event"`
	Gate      string `json:"gate,omitempty"`
	Scenario  string `json:"scenario,omitempty"`
	Result    string `json:"result"`
	RunID     string `json:"run_id"`
	CommitSHA string `json:"sha,omitempty"`
}

type keyring map[string][]byte

type claimResult uint8

const (
	claimAccepted claimResult = iota
	claimDuplicate
)

type replayStore interface {
	Claim(context.Context, string) (claimResult, error)
	Health(context.Context) error
	Close() error
}

type metricsStore struct {
	replay             replayStore
	releaseGateFailure map[string]*atomic.Uint64
	e2eScenario        map[string]map[string]*atomic.Uint64
}

var allowedGates = map[string]struct{}{
	"mobile-quality":       {},
	"local-contract-smoke": {},
	"go-race":              {},
	"dependency-security":  {},
	"govulncheck":          {},
}

var allowedScenarios = map[string]struct{}{
	"dashboard-authorized":   {},
	"dashboard-unauthorized": {},
	"kyc-session-create":     {},
	"tenant-isolation":       {},
	"token-revocation":       {},
	"document-malware-block": {},
}

func main() {
	if err := run(func(server *http.Server) error { return server.ListenAndServe() }); err != nil {
		log.Fatal(err)
	}
}

func run(listen func(*http.Server) error) error {
	return runWithReplay(loadRedisReplayStore, listen)
}

func runWithReplay(loadReplay func(context.Context) (replayStore, error), listen func(*http.Server) error) error {
	keys, err := loadKeyring()
	if err != nil {
		return err
	}
	environment := os.Getenv("ENVIRONMENT")
	if environment == "" {
		return fmt.Errorf("ENVIRONMENT is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), replayOpTimeout)
	defer cancel()
	replay, err := loadReplay(ctx)
	if err != nil {
		return fmt.Errorf("initialize distributed replay store: %w", err)
	}
	defer replay.Close()
	server := newServer(keys, environment, replay)
	log.Printf("release-gate-metrics started environment=%q key_count=%d replay_store=%q", environment, len(keys), "redis")
	return listen(server)
}

func newServer(keys keyring, environment string, replay replayStore) *http.Server {
	store := newMetricsStore(replay)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), replayOpTimeout)
		defer cancel()
		if err := replay.Health(ctx); err != nil {
			http.Error(w, "replay store unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		store.writeMetrics(w, environment)
	})
	mux.HandleFunc("POST /ingest", store.ingestHandler(keys))
	return &http.Server{
		Addr:              ":8080",
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func newMetricsStore(replay replayStore) *metricsStore {
	store := &metricsStore{
		replay:             replay,
		releaseGateFailure: make(map[string]*atomic.Uint64, len(allowedGates)),
		e2eScenario:        make(map[string]map[string]*atomic.Uint64, len(allowedScenarios)),
	}
	for gate := range allowedGates {
		store.releaseGateFailure[gate] = &atomic.Uint64{}
	}
	for scenario := range allowedScenarios {
		store.e2eScenario[scenario] = map[string]*atomic.Uint64{
			"success": &atomic.Uint64{},
			"failure": &atomic.Uint64{},
		}
	}
	return store
}

func loadKeyring() (keyring, error) {
	if raw := os.Getenv("RELEASE_GATE_INGEST_HMAC_KEYS_JSON"); raw != "" {
		var supplied map[string]string
		if err := json.Unmarshal([]byte(raw), &supplied); err != nil {
			return nil, fmt.Errorf("RELEASE_GATE_INGEST_HMAC_KEYS_JSON must be a JSON object: %w", err)
		}
		keys := make(keyring, len(supplied))
		for keyID, secret := range supplied {
			if !validKeyID(keyID) || len(secret) < 32 {
				return nil, fmt.Errorf("invalid HMAC key identifier or secret length")
			}
			keys[keyID] = []byte(secret)
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("RELEASE_GATE_INGEST_HMAC_KEYS_JSON must contain at least one key")
		}
		return keys, nil
	}
	legacy := os.Getenv("RELEASE_GATE_INGEST_HMAC_SECRET")
	if len(legacy) < 32 {
		return nil, fmt.Errorf("set RELEASE_GATE_INGEST_HMAC_KEYS_JSON or a legacy RELEASE_GATE_INGEST_HMAC_SECRET of at least 32 bytes")
	}
	return keyring{defaultKeyID: []byte(legacy)}, nil
}

func validKeyID(keyID string) bool {
	if len(keyID) < 1 || len(keyID) > 64 {
		return false
	}
	for _, char := range keyID {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *metricsStore) ingestHandler(keys keyring) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || contentType != "application/json" {
			http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		timestampText := r.Header.Get("X-FraudFusion-Timestamp")
		timestamp, err := time.Parse(time.RFC3339, timestampText)
		if err != nil || time.Since(timestamp).Abs() > clockSkew {
			http.Error(w, "invalid request timestamp", http.StatusUnauthorized)
			return
		}
		defer r.Body.Close()
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
		if err != nil {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		keyID := r.Header.Get("X-FraudFusion-Key-ID")
		if keyID == "" {
			keyID = defaultKeyID
		}
		key, found := keys[keyID]
		if !found || !validSignature(key, keyID, timestampText, body, r.Header.Get("X-FraudFusion-Signature")) {
			http.Error(w, "invalid request signature", http.StatusUnauthorized)
			return
		}
		var event ingestEvent
		if err := json.Unmarshal(body, &event); err != nil || !validEvent(event) {
			http.Error(w, "invalid release gate event", http.StatusBadRequest)
			return
		}
		claimCtx, cancel := context.WithTimeout(r.Context(), replayOpTimeout)
		defer cancel()
		claim, err := s.replay.Claim(claimCtx, replayEventID(event))
		if err != nil {
			http.Error(w, "replay store unavailable; retry request", http.StatusServiceUnavailable)
			return
		}
		if claim == claimDuplicate {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		s.recordMetric(event)
		log.Printf("release_gate_event accepted event=%q gate=%q scenario=%q result=%q run_id=%q key_id=%q", event.Event, event.Gate, event.Scenario, event.Result, event.RunID, keyID)
		w.WriteHeader(http.StatusAccepted)
	}
}

func replayEventID(event ingestEvent) string {
	identity := event.Event + ":" + event.RunID + ":" + event.Gate + ":" + event.Scenario
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}

func (s *metricsStore) recordMetric(event ingestEvent) {
	if event.Event == "ci_gate" && event.Result == "failure" {
		s.releaseGateFailure[event.Gate].Add(1)
	}
	if event.Event == "e2e_scenario" {
		s.e2eScenario[event.Scenario][event.Result].Add(1)
	}
}

func validSignature(key []byte, keyID, timestamp string, body []byte, presented string) bool {
	decoded, err := hex.DecodeString(presented)
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(keyID))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write(body)
	return subtle.ConstantTimeCompare(decoded, mac.Sum(nil)) == 1
}

func validEvent(event ingestEvent) bool {
	if len(event.RunID) < 8 || len(event.RunID) > 128 || strings.ContainsAny(event.RunID, "\r\n") {
		return false
	}
	switch event.Event {
	case "ci_gate":
		_, allowed := allowedGates[event.Gate]
		return allowed && (event.Result == "success" || event.Result == "failure") && event.Scenario == ""
	case "e2e_scenario":
		_, allowed := allowedScenarios[event.Scenario]
		return allowed && (event.Result == "success" || event.Result == "failure") && event.Gate == ""
	default:
		return false
	}
}

func (s *metricsStore) writeMetrics(w http.ResponseWriter, environment string) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintln(w, "# HELP fraudfusion_release_gate_failures_total Count of failed release-gate executions received from CI.")
	_, _ = fmt.Fprintln(w, "# TYPE fraudfusion_release_gate_failures_total counter")
	for _, gate := range sortedKeys(s.releaseGateFailure) {
		if count := s.releaseGateFailure[gate].Load(); count > 0 {
			_, _ = fmt.Fprintf(w, "fraudfusion_release_gate_failures_total{environment=%q,gate=%q} %d\n", environment, gate, count)
		}
	}
	_, _ = fmt.Fprintln(w, "# HELP fraudfusion_e2e_scenario_total Count of real E2E scenario outcomes received from the test runner.")
	_, _ = fmt.Fprintln(w, "# TYPE fraudfusion_e2e_scenario_total counter")
	for _, scenario := range sortedNestedKeys(s.e2eScenario) {
		for _, result := range sortedKeys(s.e2eScenario[scenario]) {
			if count := s.e2eScenario[scenario][result].Load(); count > 0 {
				_, _ = fmt.Fprintf(w, "fraudfusion_e2e_scenario_total{environment=%q,scenario=%q,result=%q} %d\n", environment, scenario, result, count)
			}
		}
	}
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedNestedKeys(values map[string]map[string]*atomic.Uint64) []string {
	return sortedKeys(values)
}
