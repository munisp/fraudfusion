package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/munisp/fraudfusion/orchestrator/go/internal/apisix"
	"github.com/munisp/fraudfusion/orchestrator/go/internal/dapr"
	"github.com/munisp/fraudfusion/orchestrator/go/internal/kafka"
	"github.com/munisp/fraudfusion/orchestrator/go/internal/keycloak"
	"github.com/munisp/fraudfusion/orchestrator/go/internal/permify"
	"github.com/munisp/fraudfusion/orchestrator/go/internal/redis"
	"github.com/munisp/fraudfusion/orchestrator/go/internal/temporal"
	"github.com/munisp/fraudfusion/orchestrator/go/internal/tigerbeetle"
)

// Orchestrator manages all middleware clients. The event bus is Kafka; the
// legacy Fluvio integration was removed (see internal/fluvio doc comment).
type Orchestrator struct {
	kafka        *kafka.Client
	dapr         *dapr.Client
	temporal     *temporal.Client
	keycloak     *keycloak.Client
	permify      *permify.Client
	redis        *redis.Client
	apisix       *apisix.Client
	tigerbeetle  *tigerbeetle.Client
	lakehouseURL string
	// apisixRoutes and tbAccounts memoize one-time provisioning work
	// (APISIX route registration, TigerBeetle account creation) so it never
	// repeats per journey execution.
	apisixRoutes sync.Map
	tbAccounts   sync.Map
}

// JourneyRequest represents a journey execution request
type JourneyRequest struct {
	JourneyID string                 `json:"journey_id"`
	UserID    string                 `json:"user_id"`
	TenantID  string                 `json:"tenant_id"`
	Data      map[string]interface{} `json:"data"`
}

// JourneyResponse represents a journey execution response
type JourneyResponse struct {
	Status      string                 `json:"status"`
	JourneyID   string                 `json:"journey_id"`
	ExecutionID string                 `json:"execution_id"`
	Decision    string                 `json:"decision"`
	RiskScore   float64                `json:"risk_score"`
	Duration    string                 `json:"duration"`
	Data        map[string]interface{} `json:"data"`
	Error       string                 `json:"error,omitempty"`
}

// NewOrchestrator creates a new orchestrator with all middleware.
// Secrets are REQUIRED from the environment — there are no insecure defaults
// such as "secret" or "api-key".
func NewOrchestrator(ctx context.Context) (*Orchestrator, error) {
	log.Println("🚀 Initializing FraudFusion GO Orchestrator...")

	// 1. Kafka (the platform event bus)
	log.Println("1️⃣  Initializing Kafka client...")
	kafkaClient, err := kafka.NewClient(
		strings.Split(getEnv("KAFKA_BROKERS", "localhost:9092"), ","),
		getEnv("KAFKA_TOPIC", "fraudfusion-events"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka client: %w", err)
	}

	// 2. Dapr
	log.Println("2️⃣  Initializing Dapr client...")
	daprClient, err := dapr.NewClient(
		getEnv("DAPR_URL", "http://localhost:3500"),
		getEnv("DAPR_APP_ID", "fraudfusion-orchestrator"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Dapr client: %w", err)
	}

	// 3. Temporal
	log.Println("3️⃣  Initializing Temporal client...")
	temporalClient, err := temporal.NewClient(
		getEnv("TEMPORAL_HOST", "localhost:7233"),
		getEnv("TEMPORAL_NAMESPACE", "default"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Temporal client: %w", err)
	}

	// 4. Keycloak — client secret is mandatory, fail fast if missing.
	log.Println("4️⃣  Initializing Keycloak client...")
	keycloakClient, err := keycloak.NewClient(
		getEnv("KEYCLOAK_URL", "http://localhost:8080"),
		getEnv("KEYCLOAK_REALM", "fraudfusion"),
		getEnv("KEYCLOAK_CLIENT_ID", "orchestrator"),
		requiredEnv("KEYCLOAK_CLIENT_SECRET"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Keycloak client: %w", err)
	}

	// 5. Permify — API key is mandatory, fail fast if missing.
	log.Println("5️⃣  Initializing Permify client...")
	permifyClient, err := permify.NewClient(
		getEnv("PERMIFY_URL", "http://localhost:3476"),
		requiredEnv("PERMIFY_API_KEY"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Permify client: %w", err)
	}

	// 6. Redis
	log.Println("6️⃣  Initializing Redis client...")
	redisClient, err := redis.NewClient(
		getEnv("REDIS_ADDR", "localhost:6379"),
		getEnv("REDIS_PASSWORD", ""),
		0,
		"fraudfusion:",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis client: %w", err)
	}

	// 7. APISIX — admin API key is mandatory, fail fast if missing.
	log.Println("7️⃣  Initializing APISIX client...")
	apisixClient, err := apisix.NewClient(
		getEnv("APISIX_ADMIN_URL", "http://localhost:9180"),
		requiredEnv("APISIX_API_KEY"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create APISIX client: %w", err)
	}

	// 8. TigerBeetle
	log.Println("8️⃣  Initializing TigerBeetle client...")
	tigerbeetleClient, err := tigerbeetle.NewClient(
		strings.Split(getEnv("TIGERBEETLE_ADDRESSES", "localhost:3000"), ","),
		1,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create TigerBeetle client: %w", err)
	}

	// 9. Permify bootstrap: write schema + seed relationships so permission
	// checks can actually allow. Fails fast when a bootstrap tenant is
	// configured but bootstrap fails; otherwise warns honestly that
	// authorization will deny every journey.
	if tenant := strings.TrimSpace(os.Getenv("PERMIFY_BOOTSTRAP_TENANT")); tenant != "" {
		bootCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		var journeys []string
		if seeds := strings.TrimSpace(os.Getenv("PERMIFY_SEED_JOURNEYS")); seeds != "" {
			journeys = strings.Split(seeds, ",")
		}
		if err := permifyClient.Bootstrap(bootCtx, tenant, strings.TrimSpace(os.Getenv("PERMIFY_BOOTSTRAP_ADMIN")), journeys); err != nil {
			return nil, fmt.Errorf("failed to bootstrap Permify: %w", err)
		}
		log.Printf("✅ Permify bootstrapped for tenant %s", tenant)
	} else {
		log.Println("⚠️  PERMIFY_BOOTSTRAP_TENANT unset: journey authorization will deny until Permify is provisioned")
	}

	// 10. Lakehouse URL
	lakehouseURL := getEnv("LAKEHOUSE_URL", "http://localhost:8090")
	log.Println("🔟 Lakehouse URL configured:", lakehouseURL)

	log.Println("✅ All middleware components initialized successfully!")

	return &Orchestrator{
		kafka:        kafkaClient,
		dapr:         daprClient,
		temporal:     temporalClient,
		keycloak:     keycloakClient,
		permify:      permifyClient,
		redis:        redisClient,
		apisix:       apisixClient,
		tigerbeetle:  tigerbeetleClient,
		lakehouseURL: lakehouseURL,
	}, nil
}

// journeyResultTTL bounds how long a completed journey result is pollable and
// reusable via the content-addressed cache.
const journeyResultTTL = time.Hour

// journeyCacheKey addresses cached results by the hash of the full request
// payload so changed inputs never return stale results (previously the key
// was only journey+user, which forced stale hits or cache bypasses).
func journeyCacheKey(req *JourneyRequest) string {
	canonical, _ := json.Marshal(struct {
		JourneyID string                 `json:"journey_id"`
		UserID    string                 `json:"user_id"`
		TenantID  string                 `json:"tenant_id"`
		Data      map[string]interface{} `json:"data"`
	}{req.JourneyID, req.UserID, req.TenantID, req.Data})
	sum := sha256.Sum256(canonical)
	return "journey-result:" + hex.EncodeToString(sum[:])
}

// publishWithOutbox publishes to Kafka; when the publish exhausts its retries
// the event is pushed to the Redis outbox list so a relayer can replay it,
// and the error is still propagated to the caller.
func (o *Orchestrator) publishWithOutbox(ctx context.Context, key string, events ...kafka.Event) error {
	err := o.kafka.PublishEvents(ctx, key, events...)
	if err == nil {
		return nil
	}
	for _, event := range events {
		if payload, marshalErr := json.Marshal(event); marshalErr == nil {
			if pushErr := o.redis.PushOutbox(ctx, "kafka-outbox", payload); pushErr != nil {
				log.Printf("kafka publish failed AND outbox fallback failed for event %s (%s): publish=%v outbox=%v", event.ID, event.Type, err, pushErr)
			}
		}
	}
	return err
}

// ensureJourneyRoute registers the APISIX route for a journey at most once
// per process. Route registration is an etcd write — doing it per execution
// put a consensus write on the request hot path.
func (o *Orchestrator) ensureJourneyRoute(ctx context.Context, journeyID string) error {
	if _, ok := o.apisixRoutes.Load(journeyID); ok {
		return nil
	}
	route := apisix.Route{
		ID:          fmt.Sprintf("route-journey-%s", journeyID),
		URI:         fmt.Sprintf("/api/journey/%s/*", journeyID),
		Methods:     []string{"GET"},
		UpstreamURL: "http://journey-service:8080",
	}
	if err := o.apisix.CreateRoute(ctx, route); err != nil {
		return err
	}
	o.apisixRoutes.Store(journeyID, struct{}{})
	return nil
}

// ensureLedgerAccount creates the TigerBeetle settlement account at most once
// per process instead of on every execution.
func (o *Orchestrator) ensureLedgerAccount(ctx context.Context, accountID uint64) error {
	if _, ok := o.tbAccounts.Load(accountID); ok {
		return nil
	}
	if err := o.tigerbeetle.CreateAccount(ctx, accountID, 1, 100); err != nil {
		return err
	}
	o.tbAccounts.Store(accountID, struct{}{})
	return nil
}

// ExecuteJourney validates, authorizes, and starts a journey, then returns
// immediately with a processing response. The workflow result is awaited in a
// background goroutine (the request must not be pinned for minutes) and
// stored in Redis for the poll endpoint GET /api/v1/journey/executions/{id}.
// Event-bus publishes propagate errors after spooling to the Redis outbox;
// auxiliary integrations (APISIX route registration, Dapr invocation,
// TigerBeetle ledger, cache writes) record explicit warnings.
func (o *Orchestrator) ExecuteJourney(ctx context.Context, req *JourneyRequest) (*JourneyResponse, error) {
	startTime := time.Now()
	executionID := fmt.Sprintf("%s-%d", req.JourneyID, time.Now().UnixNano())

	response := &JourneyResponse{
		Status:      "processing",
		JourneyID:   req.JourneyID,
		ExecutionID: executionID,
		Data:        make(map[string]interface{}),
	}
	var warnMu sync.Mutex
	warnings := []string{}
	warn := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		log.Println("⚠️  " + msg)
		warnMu.Lock()
		warnings = append(warnings, msg)
		warnMu.Unlock()
	}

	// Step 1: Keycloak authentication has already been validated by the HTTP handler.
	// Step 2: Permify Authorization (cached ~10s per tenant/user/journey/action)
	allowed, err := o.permify.CheckPermission(ctx, req.TenantID, req.UserID, req.JourneyID, "execute")
	if err != nil || !allowed {
		response.Status = "failed"
		response.Error = "Authorization failed"
		return response, fmt.Errorf("authorization failed: %w", err)
	}

	// Step 3: Redis cache check, keyed by content hash so identical requests
	// reuse the completed result.
	cacheKey := journeyCacheKey(req)
	var cachedResult JourneyResponse
	if cacheErr := o.redis.GetJSON(ctx, cacheKey, &cachedResult); cacheErr == nil && cachedResult.Status == "completed" {
		cachedResult.Duration = time.Since(startTime).String()
		return &cachedResult, nil
	}

	// Step 4: Temporal Workflow start (the only synchronous workflow call).
	workflowID := fmt.Sprintf("workflow-%s", executionID)
	workflowInput := temporal.WorkflowInput{
		JourneyID: req.JourneyID,
		UserID:    req.UserID,
		Data:      req.Data,
	}
	runID, err := o.temporal.StartWorkflow(ctx, workflowID, "JourneyWorkflow", workflowInput)
	if err != nil {
		response.Status = "failed"
		response.Error = fmt.Sprintf("Workflow start failed: %v", err)
		return response, err
	}
	response.Data["workflow_run_id"] = runID

	// Steps 5+6: lifecycle events published in ONE batched write. Errors
	// propagate (after outbox spooling): journeys must not continue silently
	// when the audit event bus is down.
	if err := o.publishWithOutbox(ctx, req.UserID,
		kafka.Event{ID: executionID, Type: "journey.started", Data: map[string]interface{}{"journey_id": req.JourneyID, "user_id": req.UserID}},
		kafka.Event{ID: executionID, Type: "journey.processing", Data: req.Data},
	); err != nil {
		response.Status = "failed"
		response.Error = fmt.Sprintf("Event publish failed: %v", err)
		return response, err
	}

	// Steps 7-9 run concurrently: Dapr enrichment, APISIX route ensure, and
	// the TigerBeetle ledger entry are independent of each other.
	var kycResultData interface{}
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		kycData := map[string]interface{}{"bvn": req.Data["bvn"], "user_id": req.UserID}
		kycResult, err := o.dapr.InvokeService(gctx, "kyc-service", "verify", kycData)
		if err != nil {
			warn("Dapr kyc-service invocation failed: %v", err)
			return nil // best-effort enrichment
		}
		kycResultData = kycResult.Data
		return nil
	})
	g.Go(func() error {
		if err := o.ensureJourneyRoute(gctx, req.JourneyID); err != nil {
			warn("APISIX route registration failed: %v", err)
		}
		return nil
	})
	g.Go(func() error {
		// In the default build the TigerBeetle client is a stub that returns
		// ErrUnavailable — build with `-tags tigerbeetle` for the native client.
		accountID := uint64(12345)
		if err := o.ensureLedgerAccount(gctx, accountID); err != nil {
			warn("TigerBeetle account creation failed: %v", err)
		}
		if amount, ok := req.Data["amount"].(float64); ok && amount > 0 {
			transferID, err := tigerbeetle.NewTransferID()
			if err != nil {
				warn("TigerBeetle transfer ID generation failed: %v", err)
			} else if err := o.tigerbeetle.CreateTransfer(gctx, transferID, accountID, accountID+1, uint64(amount), 1, 200); err != nil {
				warn("TigerBeetle transfer failed: %v", err)
			}
		}
		return nil
	})
	_ = g.Wait()
	if kycResultData != nil {
		response.Data["kyc_result"] = kycResultData
	}

	// Step 10: await the workflow result in the background with its own
	// bounded context, then store the result for the poll endpoint and the
	// content cache, and publish the completion event.
	go o.awaitJourneyResult(req, cacheKey, executionID, workflowID, runID)

	warnMu.Lock()
	if len(warnings) > 0 {
		response.Data["warnings"] = warnings
	}
	warnMu.Unlock()
	response.Duration = time.Since(startTime).String()

	return response, nil
}

// awaitJourneyResult completes the asynchronous half of journey execution.
// Failures are recorded in the result store so pollers see a terminal state
// instead of polling forever.
func (o *Orchestrator) awaitJourneyResult(req *JourneyRequest, cacheKey, executionID, workflowID, runID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	result := &JourneyResponse{
		Status:      "processing",
		JourneyID:   req.JourneyID,
		ExecutionID: executionID,
		Data:        make(map[string]interface{}),
	}

	workflowResult, err := o.temporal.GetWorkflowResult(ctx, workflowID, runID)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("Workflow execution failed: %v", err)
	} else {
		result.Status = workflowResult.Status
		result.Decision = workflowResult.Decision
		result.RiskScore = workflowResult.RiskScore
		result.Data["workflow_result"] = workflowResult.Data
	}

	storeCtx, storeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer storeCancel()
	if err := o.redis.SetJSON(storeCtx, "journey-exec:"+executionID, result, journeyResultTTL); err != nil {
		log.Printf("⚠️  journey result store failed for %s: %v", executionID, err)
	}
	if result.Status == "completed" {
		if err := o.redis.SetJSON(storeCtx, cacheKey, result, journeyResultTTL); err != nil {
			log.Printf("⚠️  journey content cache write failed for %s: %v", executionID, err)
		}
	}

	completionEvent := kafka.Event{
		ID:   executionID,
		Type: "journey.completed",
		Data: map[string]interface{}{
			"journey_id": req.JourneyID,
			"user_id":    req.UserID,
			"decision":   result.Decision,
			"risk_score": result.RiskScore,
		},
	}
	if err := o.publishWithOutbox(storeCtx, req.UserID, completionEvent); err != nil {
		log.Printf("⚠️  completion event publish failed for %s (spooled to outbox): %v", executionID, err)
	}
}

// Close closes all middleware clients
func (o *Orchestrator) Close() {
	log.Println("🔌 Closing all middleware connections...")
	o.kafka.Close()
	o.dapr.Close()
	o.temporal.Close()
	o.keycloak.Close()
	o.permify.Close()
	o.redis.Close()
	o.apisix.Close()
	o.tigerbeetle.Close()
	log.Println("✅ All connections closed")
}

// authenticate validates the bearer token (cached introspection) and returns
// the token subject.
func (o *Orchestrator) authenticate(w http.ResponseWriter, r *http.Request) (string, bool) {
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		http.Error(w, "authorization bearer token is required", http.StatusUnauthorized)
		return "", false
	}
	claims, err := o.keycloak.ValidateToken(r.Context(), strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer ")))
	if err != nil {
		log.Printf("journey authorization failed: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	subject, ok := claims["sub"].(string)
	if !ok || subject == "" {
		http.Error(w, "token subject is required", http.StatusUnauthorized)
		return "", false
	}
	return subject, true
}

// HTTP Handlers
func (o *Orchestrator) handleExecuteJourney(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	subject, ok := o.authenticate(w, r)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	var req JourneyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.UserID != "" && req.UserID != subject {
		http.Error(w, "token subject does not match request user", http.StatusForbidden)
		return
	}
	req.UserID = subject
	if req.JourneyID == "" || req.TenantID == "" {
		http.Error(w, "journey ID and tenant ID are required", http.StatusBadRequest)
		return
	}

	// Bound the accept path: authz + cache check + workflow start + batched
	// publish + side integrations must answer well inside the budget.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	response, err := o.ExecuteJourney(ctx, &req)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case err != nil:
		w.WriteHeader(http.StatusInternalServerError)
	case response.Status == "completed":
		// Content-cache hit: the result is already final.
		w.WriteHeader(http.StatusOK)
	default:
		// Journey accepted; poll GET /api/v1/journey/executions/{id}.
		w.Header().Set("Location", "/api/v1/journey/executions/"+response.ExecutionID)
		w.WriteHeader(http.StatusAccepted)
	}
	json.NewEncoder(w).Encode(response)
}

// handleGetJourneyExecution is the polling endpoint backing the 202 response
// of handleExecuteJourney.
func (o *Orchestrator) handleGetJourneyExecution(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := o.authenticate(w, r); !ok {
		return
	}
	executionID := strings.TrimPrefix(r.URL.Path, "/api/v1/journey/executions/")
	if executionID == "" || strings.Contains(executionID, "/") {
		http.Error(w, "execution ID is required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var result JourneyResponse
	if err := o.redis.GetJSON(ctx, "journey-exec:"+executionID, &result); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "processing", "execution_id": executionID})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if result.Status == "processing" {
		w.WriteHeader(http.StatusAccepted)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(result)
}

// checkWithTimeout runs a health probe with a bounded timeout and returns
// "connected" or the failure detail — never a hardcoded status.
func checkWithTimeout(name string, probe func(context.Context) error, results map[string]string, mu *sync.Mutex, wg *sync.WaitGroup) {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	status := "connected"
	if err := probe(ctx); err != nil {
		status = "unavailable: " + err.Error()
	}
	mu.Lock()
	results[name] = status
	mu.Unlock()
}

func (o *Orchestrator) handleHealth(w http.ResponseWriter, r *http.Request) {
	results := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	probes := []struct {
		name  string
		probe func(context.Context) error
	}{
		{"kafka", o.kafka.Health},
		{"dapr", o.dapr.Health},
		{"temporal", o.temporal.Health},
		{"keycloak", o.keycloak.Health},
		{"permify", o.permify.Health},
		{"redis", o.redis.Ping},
		{"apisix", o.apisix.Health},
		{"tigerbeetle", o.tigerbeetle.Health},
	}
	for _, p := range probes {
		wg.Add(1)
		go checkWithTimeout(p.name, p.probe, results, &mu, &wg)
	}
	wg.Wait()
	results["lakehouse"] = "configured: " + o.lakehouseURL

	overall := "healthy"
	statusCode := http.StatusOK
	for name, status := range results {
		if strings.HasPrefix(status, "unavailable") {
			overall = "degraded"
			statusCode = http.StatusServiceUnavailable
			_ = name
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     overall,
		"middleware": results,
	})
}

func main() {
	log.Println("╔════════════════════════════════════════════════════════════╗")
	log.Println("║   FraudFusion GO Orchestrator with 9 Middleware           ║")
	log.Println("║   Production-Ready Journey Execution Engine                ║")
	log.Println("╚════════════════════════════════════════════════════════════╝")

	runtimeCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	orchestrator, err := NewOrchestrator(runtimeCtx)
	if err != nil {
		log.Fatalf("❌ Failed to initialize orchestrator: %v", err)
	}
	defer orchestrator.Close()

	// Setup HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/journey/execute", orchestrator.handleExecuteJourney)
	mux.HandleFunc("/api/v1/journey/executions/", orchestrator.handleGetJourneyExecution)
	mux.HandleFunc("/health", orchestrator.handleHealth)

	port := getEnv("PORT", "8000")
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	go func() {
		<-runtimeCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("🚀 Orchestrator listening on port %s", port)
	log.Printf("📍 Health check: http://localhost:%s/health", port)
	log.Printf("📍 Execute journey: POST http://localhost:%s/api/v1/journey/execute (202 + poll /api/v1/journey/executions/{id})", port)

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("❌ Server failed: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// requiredEnv fails fast when a security-critical variable is missing.
func requiredEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("missing required environment variable: %s", key)
	}
	return value
}
