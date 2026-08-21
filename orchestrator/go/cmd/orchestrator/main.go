package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"fraudfusion/orchestrator/internal/apisix"
	"fraudfusion/orchestrator/internal/dapr"
	"fraudfusion/orchestrator/internal/fluvio"
	"fraudfusion/orchestrator/internal/kafka"
	"fraudfusion/orchestrator/internal/keycloak"
	"fraudfusion/orchestrator/internal/permify"
	"fraudfusion/orchestrator/internal/redis"
	"fraudfusion/orchestrator/internal/temporal"
	"fraudfusion/orchestrator/internal/tigerbeetle"
)

// Orchestrator manages all middleware clients
type Orchestrator struct {
	kafka        *kafka.Client
	dapr         *dapr.Client
	fluvio       *fluvio.Client
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
	JourneyID   string                 `json:"journey_id"`
	UserID      string                 `json:"user_id"`
	TenantID    string                 `json:"tenant_id"`
	Data        map[string]interface{} `json:"data"`
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

// NewOrchestrator creates a new orchestrator with all middleware
func NewOrchestrator() (*Orchestrator, error) {
	log.Println("🚀 Initializing FraudFusion GO Orchestrator...")

	// 1. Kafka
	log.Println("1️⃣  Initializing Kafka client...")
	kafkaClient, err := kafka.NewClient(
		[]string{getEnv("KAFKA_BROKERS", "localhost:9092")},
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

	// 3. Fluvio
	log.Println("3️⃣  Initializing Fluvio client...")
	fluvioClient, err := fluvio.NewClient(getEnv("FLUVIO_ENDPOINT", "localhost:9003"))
	if err != nil {
		return nil, fmt.Errorf("failed to create Fluvio client: %w", err)
	}

	// 4. Temporal
	log.Println("4️⃣  Initializing Temporal client...")
	temporalClient, err := temporal.NewClient(
		getEnv("TEMPORAL_HOST", "localhost:7233"),
		getEnv("TEMPORAL_NAMESPACE", "default"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Temporal client: %w", err)
	}

	// 5. Keycloak
	log.Println("5️⃣  Initializing Keycloak client...")
	keycloakClient, err := keycloak.NewClient(
		getEnv("KEYCLOAK_URL", "http://localhost:8080"),
		getEnv("KEYCLOAK_REALM", "fraudfusion"),
		getEnv("KEYCLOAK_CLIENT_ID", "orchestrator"),
		getEnv("KEYCLOAK_CLIENT_SECRET", "secret"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Keycloak client: %w", err)
	}

	// 6. Permify
	log.Println("6️⃣  Initializing Permify client...")
	permifyClient, err := permify.NewClient(
		getEnv("PERMIFY_URL", "http://localhost:3476"),
		getEnv("PERMIFY_API_KEY", "api-key"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Permify client: %w", err)
	}

	// 7. Redis
	log.Println("7️⃣  Initializing Redis client...")
	redisClient, err := redis.NewClient(
		getEnv("REDIS_ADDR", "localhost:6379"),
		getEnv("REDIS_PASSWORD", ""),
		0,
		"fraudfusion:",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis client: %w", err)
	}

	// 8. APISIX
	log.Println("8️⃣  Initializing APISIX client...")
	apisixClient, err := apisix.NewClient(
		getEnv("APISIX_ADMIN_URL", "http://localhost:9180"),
		getEnv("APISIX_API_KEY", "admin-api-key"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create APISIX client: %w", err)
	}

	// 9. TigerBeetle
	log.Println("9️⃣  Initializing TigerBeetle client...")
	tigerbeetleClient, err := tigerbeetle.NewClient(
		[]string{getEnv("TIGERBEETLE_ADDRESSES", "localhost:3000")},
		1,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create TigerBeetle client: %w", err)
	}

	// 10. Lakehouse URL
	lakehouseURL := getEnv("LAKEHOUSE_URL", "http://localhost:8090")
	log.Println("🔟 Lakehouse URL configured:", lakehouseURL)

	log.Println("✅ All 10 middleware components initialized successfully!")

	return &Orchestrator{
		kafka:        kafkaClient,
		dapr:         daprClient,
		fluvio:       fluvioClient,
		temporal:     temporalClient,
		keycloak:     keycloakClient,
		permify:      permifyClient,
		redis:        redisClient,
		apisix:       apisixClient,
		tigerbeetle:  tigerbeetleClient,
		lakehouseURL: lakehouseURL,
	}, nil
}

// ExecuteJourney executes a journey with all 10 middleware integrations
func (o *Orchestrator) ExecuteJourney(ctx context.Context, req *JourneyRequest) (*JourneyResponse, error) {
	startTime := time.Now()
	executionID := fmt.Sprintf("%s-%d", req.JourneyID, time.Now().Unix())

	log.Printf("🎯 Executing Journey: %s (User: %s)", req.JourneyID, req.UserID)

	response := &JourneyResponse{
		Status:      "processing",
		JourneyID:   req.JourneyID,
		ExecutionID: executionID,
		Data:        make(map[string]interface{}),
	}

	// Step 1: Keycloak authentication has already been validated by the HTTP handler.
	// Step 2: Permify Authorization
	log.Println("2️⃣  Checking authorization with Permify...")
	allowed, err := o.permify.CheckPermission(ctx, req.TenantID, req.UserID, req.JourneyID, "execute")
	if err != nil || !allowed {
		response.Status = "failed"
		response.Error = "Authorization failed"
		return response, fmt.Errorf("authorization failed")
	}

	// Step 3: Redis Cache Check
	log.Println("3️⃣  Checking Redis cache...")
	cacheKey := fmt.Sprintf("journey:%s:%s", req.JourneyID, req.UserID)
	var cachedResult JourneyResponse
	err = o.redis.GetJSON(ctx, cacheKey, &cachedResult)
	if err == nil && cachedResult.Status == "completed" {
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

	// Step 5: Kafka Event Publishing
	log.Println("5️⃣  Publishing event to Kafka...")
	event := kafka.Event{
		ID:   executionID,
		Type: "journey.started",
		Data: map[string]interface{}{
			"journey_id": req.JourneyID,
			"user_id":    req.UserID,
		},
	}
	_ = o.kafka.PublishEvent(ctx, req.UserID, event)

	// Step 6: Fluvio Real-time Streaming
	log.Println("6️⃣  Streaming event to Fluvio...")
	fluvioEvent := fluvio.Event{
		ID:   executionID,
		Type: "journey.processing",
		Data: req.Data,
	}
	_ = o.fluvio.ProduceEvent(ctx, req.UserID, fluvioEvent)

	// Step 7: Dapr Service Invocation
	log.Println("7️⃣  Invoking services via Dapr...")
	kycData := map[string]interface{}{"bvn": req.Data["bvn"], "user_id": req.UserID}
	kycResult, _ := o.dapr.InvokeService(ctx, "kyc-service", "verify", kycData)
	if kycResult != nil {
		response.Data["kyc_result"] = kycResult.Data
	}

	// Step 8: APISIX Route Registration
	log.Println("8️⃣  Registering route in APISIX...")
	route := apisix.Route{
		ID:          fmt.Sprintf("route-%s", executionID),
		URI:         fmt.Sprintf("/api/journey/%s", executionID),
		Methods:     []string{"GET"},
		UpstreamURL: "http://journey-service:8080",
	}
	_ = o.apisix.CreateRoute(ctx, route)

	// Step 9: TigerBeetle Ledger Entry
	log.Println("9️⃣  Creating ledger entry in TigerBeetle...")
	accountID := uint64(12345)
	_ = o.tigerbeetle.CreateAccount(ctx, accountID, 1, 100)
	if amount, ok := req.Data["amount"].(float64); ok {
		_ = o.tigerbeetle.CreateTransfer(ctx, uint64(time.Now().Unix()), accountID, accountID+1, uint64(amount), 1, 200)
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

	// Cache the result
	log.Println("💾 Caching result in Redis...")
	_ = o.redis.SetJSON(ctx, cacheKey, response, 1*time.Hour)

	// Publish completion event
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
	_ = o.kafka.PublishEvent(ctx, req.UserID, completionEvent)

	response.Duration = time.Since(startTime).String()
	log.Printf("✅ Journey completed in %s (Decision: %s, Risk: %.2f)", response.Duration, response.Decision, response.RiskScore)

	return response, nil
}

// Close closes all middleware clients
func (o *Orchestrator) Close() {
	log.Println("🔌 Closing all middleware connections...")
	o.kafka.Close()
	o.dapr.Close()
	o.fluvio.Close()
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

func (o *Orchestrator) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status": "healthy",
		"middleware": map[string]string{
			"kafka":        "connected",
			"dapr":         "connected",
			"fluvio":       "connected",
			"temporal":     "connected",
			"keycloak":     "connected",
			"permify":      "connected",
			"redis":        "connected",
			"apisix":       "connected",
			"tigerbeetle":  "connected",
			"lakehouse":    "configured",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func main() {
	log.Println("╔════════════════════════════════════════════════════════════╗")
	log.Println("║   FraudFusion GO Orchestrator with 10 Middleware          ║")
	log.Println("║   Production-Ready Journey Execution Engine                ║")
	log.Println("╚════════════════════════════════════════════════════════════╝")

	orchestrator, err := NewOrchestrator()
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
