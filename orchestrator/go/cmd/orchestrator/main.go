package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

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

// ExecuteJourney executes a journey with the middleware integrations.
// Event-bus publishes propagate errors; auxiliary integrations (APISIX route
// registration, Dapr invocation, TigerBeetle ledger, cache writes) record
// explicit warnings in the response instead of being silently dropped.
func (o *Orchestrator) ExecuteJourney(ctx context.Context, req *JourneyRequest) (*JourneyResponse, error) {
	startTime := time.Now()
	executionID := fmt.Sprintf("%s-%d", req.JourneyID, time.Now().UnixNano())

	log.Printf("🎯 Executing Journey: %s (User: %s)", req.JourneyID, req.UserID)

	response := &JourneyResponse{
		Status:      "processing",
		JourneyID:   req.JourneyID,
		ExecutionID: executionID,
		Data:        make(map[string]interface{}),
	}
	warnings := []string{}
	warn := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		log.Println("⚠️  " + msg)
		warnings = append(warnings, msg)
	}

	// Step 1: Keycloak authentication has already been validated by the HTTP handler.
	// Step 2: Permify Authorization
	log.Println("2️⃣  Checking authorization with Permify...")
	allowed, err := o.permify.CheckPermission(ctx, req.TenantID, req.UserID, req.JourneyID, "execute")
	if err != nil || !allowed {
		response.Status = "failed"
		response.Error = "Authorization failed"
		return response, fmt.Errorf("authorization failed: %w", err)
	}

	// Step 3: Redis Cache Check
	log.Println("3️⃣  Checking Redis cache...")
	cacheKey := fmt.Sprintf("journey:%s:%s", req.JourneyID, req.UserID)
	var cachedResult JourneyResponse
	if cacheErr := o.redis.GetJSON(ctx, cacheKey, &cachedResult); cacheErr == nil && cachedResult.Status == "completed" {
		log.Println("✅ Cache hit! Returning cached result")
		cachedResult.Duration = time.Since(startTime).String()
		return &cachedResult, nil
	}

	// Step 4: Temporal Workflow
	log.Println("4️⃣  Starting Temporal workflow...")
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

	// Step 5: Kafka Event Publishing — errors propagate; journeys must not
	// continue silently when the audit event bus is down.
	log.Println("5️⃣  Publishing event to Kafka...")
	event := kafka.Event{
		ID:   executionID,
		Type: "journey.started",
		Data: map[string]interface{}{
			"journey_id": req.JourneyID,
			"user_id":    req.UserID,
		},
	}
	if err := o.kafka.PublishEvent(ctx, req.UserID, event); err != nil {
		response.Status = "failed"
		response.Error = fmt.Sprintf("Event publish failed: %v", err)
		return response, err
	}

	// Step 6: Real-time processing event — now on Kafka (Fluvio removed).
	log.Println("6️⃣  Streaming processing event to Kafka...")
	processingEvent := kafka.Event{
		ID:   executionID,
		Type: "journey.processing",
		Data: req.Data,
	}
	if err := o.kafka.PublishEvent(ctx, req.UserID, processingEvent); err != nil {
		response.Status = "failed"
		response.Error = fmt.Sprintf("Event publish failed: %v", err)
		return response, err
	}

	// Step 7: Dapr Service Invocation (best-effort enrichment, explicit warning)
	log.Println("7️⃣  Invoking services via Dapr...")
	kycData := map[string]interface{}{"bvn": req.Data["bvn"], "user_id": req.UserID}
	if kycResult, err := o.dapr.InvokeService(ctx, "kyc-service", "verify", kycData); err != nil {
		warn("Dapr kyc-service invocation failed: %v", err)
	} else {
		response.Data["kyc_result"] = kycResult.Data
	}

	// Step 8: APISIX Route Registration (best-effort, explicit warning)
	log.Println("8️⃣  Registering route in APISIX...")
	route := apisix.Route{
		ID:          fmt.Sprintf("route-%s", executionID),
		URI:         fmt.Sprintf("/api/journey/%s", executionID),
		Methods:     []string{"GET"},
		UpstreamURL: "http://journey-service:8080",
	}
	if err := o.apisix.CreateRoute(ctx, route); err != nil {
		warn("APISIX route registration failed: %v", err)
	}

	// Step 9: TigerBeetle Ledger Entry (explicit warning on failure; in the
	// default build the client is a stub that returns ErrUnavailable — build
	// with `-tags tigerbeetle` to enable the native client).
	log.Println("9️⃣  Creating ledger entry in TigerBeetle...")
	accountID := uint64(12345)
	if err := o.tigerbeetle.CreateAccount(ctx, accountID, 1, 100); err != nil {
		warn("TigerBeetle account creation failed: %v", err)
	}
	if amount, ok := req.Data["amount"].(float64); ok && amount > 0 {
		transferID, err := tigerbeetle.NewTransferID()
		if err != nil {
			warn("TigerBeetle transfer ID generation failed: %v", err)
		} else if err := o.tigerbeetle.CreateTransfer(ctx, transferID, accountID, accountID+1, uint64(amount), 1, 200); err != nil {
			warn("TigerBeetle transfer failed: %v", err)
		}
	}

	// Step 10: Get Temporal Workflow Result
	log.Println("🔟 Getting workflow result from Temporal...")
	workflowResult, err := o.temporal.GetWorkflowResult(ctx, workflowID, runID)
	if err != nil {
		response.Status = "failed"
		response.Error = fmt.Sprintf("Workflow execution failed: %v", err)
		return response, err
	}

	// Update response with workflow result
	response.Status = workflowResult.Status
	response.Decision = workflowResult.Decision
	response.RiskScore = workflowResult.RiskScore
	response.Data["workflow_result"] = workflowResult.Data

	// Cache the result (explicitly logged on failure, non-fatal)
	log.Println("💾 Caching result in Redis...")
	if err := o.redis.SetJSON(ctx, cacheKey, response, 1*time.Hour); err != nil {
		warn("Redis cache write failed: %v", err)
	}

	// Publish completion event — errors propagate.
	log.Println("📢 Publishing completion event to Kafka...")
	completionEvent := kafka.Event{
		ID:   executionID,
		Type: "journey.completed",
		Data: map[string]interface{}{
			"journey_id": req.JourneyID,
			"user_id":    req.UserID,
			"decision":   response.Decision,
			"risk_score": response.RiskScore,
		},
	}
	if err := o.kafka.PublishEvent(ctx, req.UserID, completionEvent); err != nil {
		response.Status = "failed"
		response.Error = fmt.Sprintf("Completion event publish failed: %v", err)
		return response, err
	}

	if len(warnings) > 0 {
		response.Data["warnings"] = warnings
	}
	response.Duration = time.Since(startTime).String()
	log.Printf("✅ Journey completed in %s (Decision: %s, Risk: %.2f)", response.Duration, response.Decision, response.RiskScore)

	return response, nil
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

// HTTP Handlers
func (o *Orchestrator) handleExecuteJourney(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		http.Error(w, "authorization bearer token is required", http.StatusUnauthorized)
		return
	}
	claims, err := o.keycloak.ValidateToken(r.Context(), strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer ")))
	if err != nil {
		log.Printf("journey authorization failed: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	subject, ok := claims["sub"].(string)
	if !ok || subject == "" {
		http.Error(w, "token subject is required", http.StatusUnauthorized)
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

	response, err := o.ExecuteJourney(r.Context(), &req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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

	orchestrator, err := NewOrchestrator(context.Background())
	if err != nil {
		log.Fatalf("❌ Failed to initialize orchestrator: %v", err)
	}
	defer orchestrator.Close()

	// Setup HTTP routes
	http.HandleFunc("/api/v1/journey/execute", orchestrator.handleExecuteJourney)
	http.HandleFunc("/health", orchestrator.handleHealth)

	port := getEnv("PORT", "8000")
	log.Printf("🚀 Orchestrator listening on port %s", port)
	log.Printf("📍 Health check: http://localhost:%s/health", port)
	log.Printf("📍 Execute journey: POST http://localhost:%s/api/v1/journey/execute", port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
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
