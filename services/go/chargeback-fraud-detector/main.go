package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	serviceName        = "chargeback-fraud-detector"
	defaultTimeout     = 10 * time.Second
	maxRequestBody     = 1 << 20
	highValueThreshold = 100000.0
)

type transactionRequest struct {
	TenantID      string  `json:"tenant_id" binding:"required"`
	TransactionID string  `json:"transaction_id" binding:"required"`
	CustomerID    string  `json:"customer_id" binding:"required"`
	MerchantID    string  `json:"merchant_id" binding:"required"`
	Amount        float64 `json:"amount" binding:"gt=0"`
	Currency      string  `json:"currency" binding:"required"`
	Timestamp     string  `json:"timestamp"`
	PaymentMethod string  `json:"payment_method"`
}

type disputeRequest struct {
	TenantID      string `json:"tenant_id" binding:"required"`
	DisputeID     string `json:"dispute_id" binding:"required"`
	TransactionID string `json:"transaction_id" binding:"required"`
	CustomerID    string `json:"customer_id" binding:"required"`
	Reason        string `json:"reason" binding:"required"`
	Description   string `json:"description"`
}

type abuseRequest struct {
	TenantID   string `json:"tenant_id" binding:"required"`
	CustomerID string `json:"customer_id" binding:"required"`
	TimeWindow int    `json:"time_window_days" binding:"gte=1,lte=3650"`
}

type keycloakClient struct {
	serverURL    string
	realm        string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	roles        map[string]struct{}
}

type app struct {
	db        *pgxpool.Pool
	keycloak  *keycloakClient
	serverURL string
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	databaseURL := requiredEnv("DATABASE_URL")
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		log.Fatalf("invalid DATABASE_URL: %v", err)
	}
	poolConfig.MaxConns = int32(intEnv("DB_MAX_CONNS", 20))
	poolConfig.MinConns = int32(intEnv("DB_MIN_CONNS", 2))
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		log.Fatalf("connect to PostgreSQL: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("ping PostgreSQL: %v", err)
	}

	keycloak, err := newKeycloakClient()
	if err != nil {
		log.Fatalf("configure Keycloak client: %v", err)
	}
	application := &app{db: pool, keycloak: keycloak, serverURL: ":8091"}
	if value := os.Getenv("LISTEN_ADDR"); value != "" {
		application.serverURL = value
	}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery(), maxBodyMiddleware(maxRequestBody))
	router.GET("/api/v1/chargeback/health", application.healthCheck)

	api := router.Group("/api/v1/chargeback")
	api.Use(application.authenticate())
	api.POST("/analyze-transaction", application.analyzeTransaction)
	api.POST("/detect-friendly-fraud", application.detectFriendlyFraud)
	api.POST("/detect-chargeback-abuse", application.detectChargebackAbuse)
	api.POST("/predict-chargeback", application.predictChargeback)
	api.POST("/analyze-dispute", application.analyzeDispute)
	api.GET("/customer-risk-score/:customer_id", application.getCustomerRiskScore)
	api.GET("/merchant-risk-score/:merchant_id", application.getMerchantRiskScore)

	server := &http.Server{
		Addr:              application.serverURL,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("%s listening on %s", serviceName, application.serverURL)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve HTTP: %v", err)
	}
}

func (a *app) healthCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	if err := a.db.Ping(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy", "service": serviceName})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "healthy", "service": serviceName, "timestamp": time.Now().UTC().Format(time.RFC3339)})
}

func (a *app) analyzeTransaction(c *gin.Context) {
	var req transactionRequest
	if !bindJSON(c, &req) || !a.tenantMatches(c, req.TenantID) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), defaultTimeout)
	defer cancel()
	if err := a.persistTransaction(ctx, req); err != nil {
		internalError(c, err)
		return
	}
	customerHistory, merchantHistory, err := a.lookupHistory(ctx, req.TenantID, req.CustomerID, req.MerchantID)
	if err != nil {
		internalError(c, err)
		return
	}

	score, factors := calculateTransactionRisk(req, customerHistory, merchantHistory)
	response := gin.H{
		"transaction_id":       req.TransactionID,
		"risk_score":           score,
		"risk_level":           calculateRiskLevel(score),
		"risk_factors":         factors,
		"customer_chargebacks": customerHistory,
		"merchant_chargebacks": merchantHistory,
		"evaluated_at":         time.Now().UTC().Format(time.RFC3339),
	}
	if err := a.persistDecision(ctx, req.TenantID, req.TransactionID, "transaction_risk", float64(score), response, actor(c)); err != nil {
		internalError(c, err)
		return
	}
	c.JSON(http.StatusOK, response)
}

func (a *app) detectFriendlyFraud(c *gin.Context) {
	var req transactionRequest
	if !bindJSON(c, &req) || !a.tenantMatches(c, req.TenantID) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), defaultTimeout)
	defer cancel()
	if err := a.persistTransaction(ctx, req); err != nil {
		internalError(c, err)
		return
	}

	var chargebackCount int
	var priorCases int
	err := a.db.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM dispute_records WHERE tenant_id=$1 AND customer_id=$2 AND created_at >= NOW() - INTERVAL '365 days'),
			(SELECT COUNT(*) FROM friendly_fraud_cases WHERE tenant_id=$1 AND customer_id=$2 AND created_at >= NOW() - INTERVAL '365 days')`,
		req.TenantID, req.CustomerID).Scan(&chargebackCount, &priorCases)
	if err != nil {
		internalError(c, err)
		return
	}

	indicators := make([]string, 0, 3)
	confidence := 0.05
	if chargebackCount > 0 {
		indicators = append(indicators, "prior_chargeback_activity")
		confidence += math.Min(0.45, float64(chargebackCount)*0.12)
	}
	if priorCases > 0 {
		indicators = append(indicators, "prior_friendly_fraud_case")
		confidence += math.Min(0.35, float64(priorCases)*0.18)
	}
	if req.Amount >= highValueThreshold {
		indicators = append(indicators, "high_value_transaction")
		confidence += 0.15
	}
	if req.Currency != "NGN" {
		indicators = append(indicators, "cross_currency_transaction")
		confidence += 0.05
	}
	confidence = math.Min(confidence, 0.99)
	isFriendlyFraud := confidence >= 0.55

	if _, err := a.db.Exec(ctx, `INSERT INTO friendly_fraud_cases (tenant_id, transaction_id, customer_id, indicators, confidence) VALUES ($1,$2,$3,$4,$5)`, req.TenantID, req.TransactionID, req.CustomerID, indicators, confidence); err != nil {
		internalError(c, err)
		return
	}
	response := gin.H{
		"transaction_id":             req.TransactionID,
		"is_friendly_fraud":          isFriendlyFraud,
		"confidence":                 confidence,
		"indicators":                 indicators,
		"prior_chargebacks":          chargebackCount,
		"prior_friendly_fraud_cases": priorCases,
		"evaluated_at":               time.Now().UTC().Format(time.RFC3339),
	}
	if err := a.persistDecision(ctx, req.TenantID, req.TransactionID, "friendly_fraud", confidence*100, response, actor(c)); err != nil {
		internalError(c, err)
		return
	}
	c.JSON(http.StatusOK, response)
}

func (a *app) detectChargebackAbuse(c *gin.Context) {
	var req abuseRequest
	if !bindJSON(c, &req) || !a.tenantMatches(c, req.TenantID) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), defaultTimeout)
	defer cancel()

	var count int
	interval := fmt.Sprintf("%d days", req.TimeWindow)
	if err := a.db.QueryRow(ctx, `SELECT COUNT(*) FROM dispute_records WHERE tenant_id=$1 AND customer_id=$2 AND created_at >= NOW() - $3::interval`, req.TenantID, req.CustomerID, interval).Scan(&count); err != nil {
		internalError(c, err)
		return
	}
	threshold := abuseThreshold(req.TimeWindow)
	abuseDetected := count >= threshold
	if _, err := a.db.Exec(ctx, `INSERT INTO chargeback_abuse_patterns (tenant_id, customer_id, chargeback_count, time_window) VALUES ($1,$2,$3,$4)`, req.TenantID, req.CustomerID, count, req.TimeWindow); err != nil {
		internalError(c, err)
		return
	}
	response := gin.H{"customer_id": req.CustomerID, "abuse_detected": abuseDetected, "chargeback_count": count, "time_window_days": req.TimeWindow, "abuse_threshold": threshold, "evaluated_at": time.Now().UTC().Format(time.RFC3339)}
	if err := a.persistDecision(ctx, req.TenantID, req.CustomerID, "chargeback_abuse", ratioScore(count, threshold), response, actor(c)); err != nil {
		internalError(c, err)
		return
	}
	c.JSON(http.StatusOK, response)
}

func (a *app) predictChargeback(c *gin.Context) {
	var req transactionRequest
	if !bindJSON(c, &req) || !a.tenantMatches(c, req.TenantID) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), defaultTimeout)
	defer cancel()
	if err := a.persistTransaction(ctx, req); err != nil {
		internalError(c, err)
		return
	}
	customerHistory, merchantHistory, err := a.lookupHistory(ctx, req.TenantID, req.CustomerID, req.MerchantID)
	if err != nil {
		internalError(c, err)
		return
	}
	baseScore, factors := calculateTransactionRisk(req, customerHistory, merchantHistory)
	probability := math.Min(0.98, math.Max(0.01, float64(baseScore)/100.0))
	recommendation := "approve"
	if probability >= 0.70 {
		recommendation = "decline_or_manual_review"
	} else if probability >= 0.35 {
		recommendation = "step_up_verification"
	}
	response := gin.H{"transaction_id": req.TransactionID, "chargeback_probability": probability, "risk_level": calculateRiskLevel(baseScore), "risk_factors": factors, "recommendation": recommendation, "evaluated_at": time.Now().UTC().Format(time.RFC3339)}
	if err := a.persistDecision(ctx, req.TenantID, req.TransactionID, "chargeback_prediction", float64(baseScore), response, actor(c)); err != nil {
		internalError(c, err)
		return
	}
	c.JSON(http.StatusOK, response)
}

func (a *app) analyzeDispute(c *gin.Context) {
	var req disputeRequest
	if !bindJSON(c, &req) || !a.tenantMatches(c, req.TenantID) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), defaultTimeout)
	defer cancel()

	var transactionExists bool
	if err := a.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM chargeback_transactions WHERE tenant_id=$1 AND transaction_id=$2 AND customer_id=$3)`, req.TenantID, req.TransactionID, req.CustomerID).Scan(&transactionExists); err != nil {
		internalError(c, err)
		return
	}
	if !transactionExists {
		c.JSON(http.StatusNotFound, gin.H{"error": "transaction not found for tenant and customer"})
		return
	}
	var priorDisputes int
	if err := a.db.QueryRow(ctx, `SELECT COUNT(*) FROM dispute_records WHERE tenant_id=$1 AND customer_id=$2 AND created_at >= NOW() - INTERVAL '365 days'`, req.TenantID, req.CustomerID).Scan(&priorDisputes); err != nil {
		internalError(c, err)
		return
	}
	fraudLikelihood := math.Min(0.95, 0.10+float64(priorDisputes)*0.12)
	if len(strings.TrimSpace(req.Description)) < 20 {
		fraudLikelihood = math.Min(0.95, fraudLikelihood+0.10)
	}
	status := "under_review"
	if fraudLikelihood >= 0.70 {
		status = "high_risk_review"
	}
	if _, err := a.db.Exec(ctx, `INSERT INTO dispute_records (tenant_id, dispute_id, transaction_id, customer_id, reason, description, status) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id, dispute_id) DO UPDATE SET reason=EXCLUDED.reason, description=EXCLUDED.description, status=EXCLUDED.status`, req.TenantID, req.DisputeID, req.TransactionID, req.CustomerID, req.Reason, req.Description, status); err != nil {
		internalError(c, err)
		return
	}
	response := gin.H{"dispute_id": req.DisputeID, "transaction_id": req.TransactionID, "status": status, "fraud_likelihood": fraudLikelihood, "prior_disputes": priorDisputes, "recommendation": disputeRecommendation(fraudLikelihood), "evaluated_at": time.Now().UTC().Format(time.RFC3339)}
	if err := a.persistDecision(ctx, req.TenantID, req.DisputeID, "dispute_analysis", fraudLikelihood*100, response, actor(c)); err != nil {
		internalError(c, err)
		return
	}
	c.JSON(http.StatusOK, response)
}

func (a *app) getCustomerRiskScore(c *gin.Context) {
	tenantID, ok := tenantFromHeader(c)
	if !ok {
		return
	}
	customerID := c.Param("customer_id")
	ctx, cancel := context.WithTimeout(c.Request.Context(), defaultTimeout)
	defer cancel()
	var disputeCount int
	var averageScore float64
	if err := a.db.QueryRow(ctx, `SELECT COUNT(*), COALESCE(AVG(score),0) FROM chargeback_risk_decisions WHERE tenant_id=$1 AND subject_id=$2 AND created_at >= NOW() - INTERVAL '365 days'`, tenantID, customerID).Scan(&disputeCount, &averageScore); err != nil {
		internalError(c, err)
		return
	}
	score := int(math.Round(math.Min(100, averageScore+float64(disputeCount)*5)))
	c.JSON(http.StatusOK, gin.H{"customer_id": customerID, "risk_score": score, "risk_level": calculateRiskLevel(score), "chargeback_history": disputeCount, "evaluated_at": time.Now().UTC().Format(time.RFC3339)})
}

func (a *app) getMerchantRiskScore(c *gin.Context) {
	tenantID, ok := tenantFromHeader(c)
	if !ok {
		return
	}
	merchantID := c.Param("merchant_id")
	ctx, cancel := context.WithTimeout(c.Request.Context(), defaultTimeout)
	defer cancel()
	var transactionCount int
	var disputeCount int
	if err := a.db.QueryRow(ctx, `SELECT COUNT(*), (SELECT COUNT(*) FROM dispute_records d JOIN chargeback_transactions t ON t.tenant_id=d.tenant_id AND t.transaction_id=d.transaction_id WHERE t.tenant_id=$1 AND t.merchant_id=$2) FROM chargeback_transactions WHERE tenant_id=$1 AND merchant_id=$2`, tenantID, merchantID).Scan(&transactionCount, &disputeCount); err != nil {
		internalError(c, err)
		return
	}
	rate := 0.0
	if transactionCount > 0 {
		rate = float64(disputeCount) / float64(transactionCount)
	}
	score := int(math.Round(math.Min(100, rate*100)))
	c.JSON(http.StatusOK, gin.H{"merchant_id": merchantID, "risk_score": score, "risk_level": calculateRiskLevel(score), "chargeback_rate": rate, "transaction_count": transactionCount, "evaluated_at": time.Now().UTC().Format(time.RFC3339)})
}

func (a *app) persistTransaction(ctx context.Context, req transactionRequest) error {
	var customerID, merchantID, currency string
	var amount float64
	err := a.db.QueryRow(ctx, `INSERT INTO chargeback_transactions (tenant_id, transaction_id, customer_id, merchant_id, amount, currency, created_at) VALUES ($1,$2,$3,$4,$5,$6,NOW()) ON CONFLICT (tenant_id, transaction_id) DO NOTHING RETURNING customer_id, merchant_id, amount, currency`, req.TenantID, req.TransactionID, req.CustomerID, req.MerchantID, req.Amount, req.Currency).Scan(&customerID, &merchantID, &amount, &currency)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err := a.db.QueryRow(ctx, `SELECT customer_id, merchant_id, amount, currency FROM chargeback_transactions WHERE tenant_id=$1 AND transaction_id=$2`, req.TenantID, req.TransactionID).Scan(&customerID, &merchantID, &amount, &currency); err != nil {
		return err
	}
	if customerID != req.CustomerID || merchantID != req.MerchantID || amount != req.Amount || currency != req.Currency {
		return fmt.Errorf("transaction idempotency conflict for tenant transaction")
	}
	return nil
}

func (a *app) persistDecision(ctx context.Context, tenantID, subjectID, decisionType string, score float64, payload gin.H, actorID string) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = a.db.Exec(ctx, `INSERT INTO chargeback_risk_decisions (tenant_id, subject_id, decision_type, score, payload, actor_id) VALUES ($1,$2,$3,$4,$5,$6)`, tenantID, subjectID, decisionType, score, encoded, actorID)
	return err
}

func (a *app) lookupHistory(ctx context.Context, tenantID, customerID, merchantID string) (int, int, error) {
	var customerCount int
	var merchantCount int
	err := a.db.QueryRow(ctx, `SELECT (SELECT COUNT(*) FROM dispute_records WHERE tenant_id=$1 AND customer_id=$2 AND created_at >= NOW() - INTERVAL '365 days'), (SELECT COUNT(*) FROM dispute_records d JOIN chargeback_transactions t ON t.tenant_id=d.tenant_id AND t.transaction_id=d.transaction_id WHERE t.tenant_id=$1 AND t.merchant_id=$3 AND d.created_at >= NOW() - INTERVAL '365 days')`, tenantID, customerID, merchantID).Scan(&customerCount, &merchantCount)
	return customerCount, merchantCount, err
}

func (a *app) authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "bearer token required"})
			return
		}
		claims, err := a.keycloak.introspect(c.Request.Context(), strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer ")))
		if err != nil {
			log.Printf("chargeback token validation failed: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		subject, ok := claims["sub"].(string)
		if !ok || subject == "" || !a.keycloak.authorized(claims) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient role"})
			return
		}
		tenantID, ok := tenantFromClaims(claims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tenant claim required"})
			return
		}
		c.Set("subject", subject)
		c.Set("tenant", tenantID)
		c.Next()
	}
}

func newKeycloakClient() (*keycloakClient, error) {
	client := &keycloakClient{
		serverURL:    strings.TrimRight(requiredEnv("KEYCLOAK_URL"), "/"),
		realm:        requiredEnv("KEYCLOAK_REALM"),
		clientID:     requiredEnv("KEYCLOAK_CLIENT_ID"),
		clientSecret: requiredEnv("KEYCLOAK_CLIENT_SECRET"),
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		roles:        map[string]struct{}{},
	}
	for _, role := range strings.Split(envOr("KEYCLOAK_REQUIRED_ROLES", "fraud_analyst,fraud_operator,admin"), ",") {
		role = strings.TrimSpace(role)
		if role != "" {
			client.roles[role] = struct{}{}
		}
	}
	if client.serverURL == "" || client.realm == "" || client.clientID == "" || client.clientSecret == "" {
		return nil, fmt.Errorf("incomplete Keycloak configuration")
	}
	return client, nil
}

func (k *keycloakClient) introspect(ctx context.Context, token string) (map[string]interface{}, error) {
	if token == "" {
		return nil, fmt.Errorf("empty access token")
	}
	form := url.Values{"token": {token}, "client_id": {k.clientID}, "client_secret": {k.clientSecret}}
	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", k.serverURL, url.PathEscape(k.realm))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection status %d", resp.StatusCode)
	}
	claims := make(map[string]interface{})
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, err
	}
	active, ok := claims["active"].(bool)
	if !ok || !active {
		return nil, fmt.Errorf("inactive token")
	}
	return claims, nil
}

func (k *keycloakClient) authorized(claims map[string]interface{}) bool {
	if len(k.roles) == 0 {
		return false
	}
	collectRoles := func(value interface{}) []string {
		roles := []string{}
		switch v := value.(type) {
		case []interface{}:
			for _, role := range v {
				if value, ok := role.(string); ok {
					roles = append(roles, value)
				}
			}
		case []string:
			roles = append(roles, v...)
		}
		return roles
	}
	for _, role := range collectRoles(claims["roles"]) {
		if _, ok := k.roles[role]; ok {
			return true
		}
	}
	if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
		for _, role := range collectRoles(realmAccess["roles"]) {
			if _, ok := k.roles[role]; ok {
				return true
			}
		}
	}
	return false
}

func maxBodyMiddleware(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

func bindJSON(c *gin.Context, target interface{}) bool {
	if err := c.ShouldBindJSON(target); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "detail": err.Error()})
		return false
	}
	return true
}

func tenantFromClaims(claims map[string]interface{}) (string, bool) {
	for _, claim := range []string{"tenant_id", "tenant"} {
		if value, ok := claims[claim].(string); ok {
			if tenantID := strings.TrimSpace(value); tenantID != "" {
				return tenantID, true
			}
		}
	}
	return "", false
}

func tenantFromHeader(c *gin.Context) (string, bool) {
	value, ok := c.Get("tenant")
	tenantID, valid := value.(string)
	if !ok || !valid || strings.TrimSpace(tenantID) == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "authenticated tenant claim required"})
		return "", false
	}
	if supplied := strings.TrimSpace(c.GetHeader("X-Tenant-ID")); supplied != "" && supplied != tenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "X-Tenant-ID does not match authenticated tenant"})
		return "", false
	}
	return tenantID, true
}

func (a *app) tenantMatches(c *gin.Context, tenantID string) bool {
	headerTenant, ok := tenantFromHeader(c)
	if !ok {
		return false
	}
	if tenantID != headerTenant {
		c.JSON(http.StatusForbidden, gin.H{"error": "tenant ID does not match authenticated request context"})
		return false
	}
	return true
}

func actor(c *gin.Context) string {
	value, _ := c.Get("subject")
	subject, _ := value.(string)
	return subject
}

func calculateTransactionRisk(req transactionRequest, customerHistory, merchantHistory int) (int, []string) {
	score := 0
	factors := make([]string, 0, 5)
	if req.Amount >= highValueThreshold {
		score += 25
		factors = append(factors, "high_value_transaction")
	}
	if req.Currency != "NGN" {
		score += 15
		factors = append(factors, "cross_currency_transaction")
	}
	if customerHistory > 0 {
		score += min(35, customerHistory*10)
		factors = append(factors, "customer_dispute_history")
	}
	if merchantHistory > 0 {
		score += min(25, merchantHistory*5)
		factors = append(factors, "merchant_dispute_history")
	}
	return min(100, score), factors
}

func abuseThreshold(window int) int {
	if window <= 30 {
		return 3
	}
	if window <= 180 {
		return 5
	}
	return 8
}

func ratioScore(actual, threshold int) float64 {
	if threshold <= 0 {
		return 0
	}
	return math.Min(100, float64(actual)*100/float64(threshold))
}

func disputeRecommendation(fraudLikelihood float64) string {
	switch {
	case fraudLikelihood >= 0.70:
		return "escalate_for_fraud_review"
	case fraudLikelihood >= 0.35:
		return "request_additional_evidence"
	default:
		return "continue_standard_dispute_review"
	}
}

func calculateRiskLevel(score int) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

func internalError(c *gin.Context, err error) {
	log.Printf("%s internal error: %v", serviceName, err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
}

func requiredEnv(key string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		log.Fatalf("%s must be configured", key)
	}
	return value
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func intEnv(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		log.Fatalf("%s must be a positive integer", key)
	}
	return parsed
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
