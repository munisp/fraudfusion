package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	_ "github.com/lib/pq"
)

var (
	db            *sql.DB
	redisClient   *redis.Client
	telcoVerifier *telcoVerificationClient
	ctx           = context.Background()
)

// SIMSwapEvent represents a SIM card change event
type telcoVerificationClient struct {
	endpoint   string
	apiKey     string
	httpClient *http.Client
}

type telcoVerificationResponse struct {
	Verified  bool   `json:"verified"`
	Status    string `json:"status"`
	Reference string `json:"reference"`
}

// SIMSwapEvent represents a SIM card change event.
type SIMSwapEvent struct {
	EventID       string    `json:"event_id"`
	TenantID      string    `json:"tenant_id"`
	UserID        string    `json:"user_id"`
	PhoneNumber   string    `json:"phone_number"`
	OldSIMID      string    `json:"old_sim_id"`
	NewSIMID      string    `json:"new_sim_id"`
	Telco         string    `json:"telco"` // MTN, Airtel, Glo, 9mobile
	SwapTimestamp time.Time `json:"swap_timestamp"`
	Location      string    `json:"location"`
}

// DeviceInfo represents device fingerprint information
type DeviceInfo struct {
	DeviceID    string    `json:"device_id"`
	TenantID    string    `json:"tenant_id"`
	UserID      string    `json:"user_id"`
	DeviceModel string    `json:"device_model"`
	OS          string    `json:"os"`
	OSVersion   string    `json:"os_version"`
	IPAddress   string    `json:"ip_address"`
	Location    string    `json:"location"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

// AccountAccessLog represents account access attempt
type AccountAccessLog struct {
	AccessID   string    `json:"access_id"`
	TenantID   string    `json:"tenant_id"`
	UserID     string    `json:"user_id"`
	DeviceID   string    `json:"device_id"`
	AccessType string    `json:"access_type"` // login, otp_request, settings_change, transfer
	Success    bool      `json:"success"`
	IPAddress  string    `json:"ip_address"`
	Location   string    `json:"location"`
	Timestamp  time.Time `json:"timestamp"`
}

// RiskAnalysis represents SIM swap fraud risk analysis
type RiskAnalysis struct {
	EventID        string   `json:"event_id"`
	UserID         string   `json:"user_id"`
	RiskScore      int      `json:"risk_score"`
	RiskLevel      string   `json:"risk_level"`
	IsSIMSwapFraud bool     `json:"is_sim_swap_fraud"`
	RedFlags       []string `json:"red_flags"`
	Recommendation string   `json:"recommendation"`
	ShouldBlock    bool     `json:"should_block"`
}

func main() {
	// Initialize database
	initDB()
	defer db.Close()

	// Initialize Redis
	initRedis()
	defer redisClient.Close()

	// Telco verification is mandatory: an unavailable provider must block a fraud decision.
	initTelcoVerifier()

	// Setup Gin router
	router := gin.Default()

	// All routes require a valid Keycloak token (fail-closed introspection);
	// destructive actions additionally require fraud_analyst/admin.
	router.Use(authMiddleware())

	// API routes
	v1 := router.Group("/api/v1/sim-swap")
	{
		v1.POST("/detect", detectSIMSwap)
		v1.POST("/verify-sim-change", verifySIMChange)
		v1.POST("/analyze-device", analyzeDevice)
		v1.POST("/check-location-anomaly", checkLocationAnomaly)
		v1.POST("/monitor-account-access", monitorAccountAccess)
		v1.GET("/risk/:user_id", getUserRisk)
		v1.GET("/alerts", getAlerts)
		v1.GET("/reports/daily", getDailyReport)
		v1.POST("/block-account", requireRole("fraud_analyst", "admin"), blockAccount)
		v1.GET("/health", healthCheck)
	}

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8088"
	}

	log.Printf("SIM Swap Detector starting on port %s", port)
		server := &http.Server{
		Addr:              ":" + port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal("Failed to start server:", err)
	}

}

func initDB() {
	sslMode := getEnv("DB_SSLMODE", "require")
	if sslMode == "disable" && !strings.EqualFold(os.Getenv("DB_ALLOW_INSECURE"), "true") {
		log.Fatal("DB_SSLMODE=disable requires DB_ALLOW_INSECURE=true (local development only)")
	}
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_USER", "postgres"),
		getEnv("DB_PASSWORD", ""),
		getEnv("DB_NAME", "fraudfusion"),
		sslMode,
	)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Bound the pool: unlimited connections can exhaust PG max_connections,
	// and the default of 2 idle connections forces a TLS handshake per query.
	db.SetMaxOpenConns(getEnvInt("DB_MAX_OPEN_CONNS", 25))
	db.SetMaxIdleConns(getEnvInt("DB_MAX_IDLE_CONNS", 25))
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	if err = withBackoff(func() error { return db.Ping() }); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	log.Println("Database connected successfully")
}

func initRedis() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", getEnv("REDIS_HOST", "localhost"), getEnv("REDIS_PORT", "6379")),
		Password: getEnv("REDIS_PASSWORD", ""),
		DB:       0,
	})

	if err := withBackoff(func() error { return redisClient.Ping(ctx).Err() }); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}

	log.Println("Redis connected successfully")
}

func detectSIMSwap(c *gin.Context) {
	var event SIMSwapEvent
	if err := c.ShouldBindJSON(&event); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	event.TenantID = requestTenant(c, event.TenantID)

	// Perform comprehensive analysis. Helper/database failures are fail-closed:
	// the event routes to manual review instead of getting a silently-zero score.
	analysis, err := performSIMSwapAnalysis(c.Request.Context(), event)
	if err != nil {
		log.Printf("SIM swap analysis failed for user %s: %v", event.UserID, err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":       "SIM swap analysis unavailable",
			"disposition": "manual_review",
		})
		return
	}

	// Store event and analysis
	if err := storeSIMSwapEvent(event, analysis); err != nil {
		log.Printf("Error storing SIM swap event: %v", err)
	}

	// If high risk, create alert and potentially block account
	if analysis.RiskScore >= 70 {
		createAlert(event, analysis)

		if analysis.ShouldBlock {
			blockUserAccount(event.TenantID, event.UserID, "Suspected SIM swap fraud")
		}
	}

	c.JSON(http.StatusOK, analysis)
}

func performSIMSwapAnalysis(requestContext context.Context, event SIMSwapEvent) (RiskAnalysis, error) {
	riskScore := 0
	redFlags := []string{}

	// Base risk for any SIM swap
	riskScore += 20

	// Each helper is fail-closed: a database error aborts the analysis and the
	// caller routes the event to manual review instead of silently scoring 0.
	signals := []struct {
		flag    string
		points  int
		evaluate func() (bool, error)
	}{
		{"Login attempt within 5 minutes of SIM swap", 40, func() (bool, error) {
			return hasImmediateLoginAfterSwap(event.TenantID, event.UserID, event.SwapTimestamp)
		}},
		{"New device detected after SIM swap", 35, func() (bool, error) {
			return hasNewDeviceAfterSwap(event.TenantID, event.UserID, event.SwapTimestamp)
		}},
		{"SIM swap in different location than usual", 30, func() (bool, error) {
			return hasLocationAnomaly(event.TenantID, event.UserID, event.Location)
		}},
		{"Multiple failed OTP attempts before SIM swap", 25, func() (bool, error) {
			return hasMultipleFailedOTP(event.TenantID, event.UserID, event.SwapTimestamp)
		}},
		{"Account settings changed after SIM swap", 30, func() (bool, error) {
			return hasSettingsChangesAfterSwap(event.TenantID, event.UserID, event.SwapTimestamp)
		}},
		{"Money transfer attempted after SIM swap", 45, func() (bool, error) {
			return hasTransferAttemptsAfterSwap(event.TenantID, event.UserID, event.SwapTimestamp)
		}},
		{"Multiple SIM swaps in short period", 20, func() (bool, error) {
			return hasFrequentSIMSwaps(event.TenantID, event.UserID)
		}},
	}
	for _, signal := range signals {
		hit, err := signal.evaluate()
		if err != nil {
			return RiskAnalysis{}, err
		}
		if hit {
			riskScore += signal.points
			redFlags = append(redFlags, signal.flag)
		}
	}

	// Check if telco verification failed
	verified, err := verifyWithTelco(requestContext, event.Telco, event.PhoneNumber, event.UserID)
	if err != nil {
		return RiskAnalysis{}, err
	}
	if !verified {
		riskScore += 35
		redFlags = append(redFlags, "telco_verification_rejected")
	}

	// Cap the score first so the stored/displayed score and the blocking
	// decision are computed from the same number (previously shouldBlock and
	// risk level used the uncapped score while the API returned min(,100)).
	finalScore := min(riskScore, 100)

	// Determine risk level
	riskLevel := getRiskLevel(finalScore)

	// Determine if should block
	shouldBlock := finalScore >= 80

	// Generate recommendation
	recommendation := generateRecommendation(finalScore, shouldBlock)

	return RiskAnalysis{
		EventID:        event.EventID,
		UserID:         event.UserID,
		RiskScore:      finalScore,
		RiskLevel:      riskLevel,
		IsSIMSwapFraud: finalScore >= 60,
		RedFlags:       redFlags,
		Recommendation: recommendation,
		ShouldBlock:    shouldBlock,
	}, nil
}

// requestTenant resolves the tenant for a request: the authenticated
// principal's tenant wins; a body-supplied tenant is only honored when the
// token carries no tenant claim (internal callers). Defaults to "default".
func requestTenant(c *gin.Context, payloadTenant string) string {
	if value, ok := c.Get("principal"); ok {
		if principal, ok := value.(*authPrincipal); ok && principal.TenantID != "" {
			return principal.TenantID
		}
	}
	if payloadTenant != "" {
		return payloadTenant
	}
	return "default"
}

// The signal helpers below are fail-closed: database errors propagate to the
// caller (which routes to manual review) instead of silently returning false,
// and every query is scoped to the requesting tenant.

func hasImmediateLoginAfterSwap(tenantID, userID string, swapTime time.Time) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("database not initialized")
	}
	query := `
		SELECT COUNT(*) FROM account_access_logs
		WHERE tenant_id = $1 AND user_id = $2
		AND access_type = 'login'
		AND timestamp BETWEEN $3 AND $4
	`

	fiveMinutesAfter := swapTime.Add(5 * time.Minute)

	var count int
	if err := db.QueryRow(query, tenantID, userID, swapTime, fiveMinutesAfter).Scan(&count); err != nil {
		return false, fmt.Errorf("query login-after-swap signal: %w", err)
	}

	return count > 0, nil
}

// hasNewDeviceAfterSwap queries device_fingerprints.first_seen_at (the column
// created by database/20260827_service_base_tables.sql).
func hasNewDeviceAfterSwap(tenantID, userID string, swapTime time.Time) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("database not initialized")
	}
	query := `
		SELECT COUNT(*) FROM device_fingerprints
		WHERE tenant_id = $1 AND user_id = $2
		AND first_seen_at > $3
	`

	var count int
	if err := db.QueryRow(query, tenantID, userID, swapTime).Scan(&count); err != nil {
		return false, fmt.Errorf("query new-device signal: %w", err)
	}

	return count > 0, nil
}

func hasLocationAnomaly(tenantID, userID string, newLocation string) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("database not initialized")
	}

	// Get user's usual locations
	query := `
		SELECT location, COUNT(*) as count
		FROM account_access_logs
		WHERE tenant_id = $1 AND user_id = $2
		AND timestamp > NOW() - INTERVAL '30 days'
		GROUP BY location
		ORDER BY count DESC
		LIMIT 3
	`

	rows, err := db.Query(query, tenantID, userID)
	if err != nil {
		return false, fmt.Errorf("query location history: %w", err)
	}
	defer rows.Close()

	usualLocations := []string{}
	for rows.Next() {
		var location string
		var count int
		if err := rows.Scan(&location, &count); err != nil {
			return false, fmt.Errorf("scan location history: %w", err)
		}
		usualLocations = append(usualLocations, location)
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate location history: %w", err)
	}

	// Check if new location is in usual locations
	for _, loc := range usualLocations {
		if loc == newLocation {
			return false, nil
		}
	}

	return len(usualLocations) > 0, nil
}

func hasMultipleFailedOTP(tenantID, userID string, swapTime time.Time) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("database not initialized")
	}
	query := `
		SELECT COUNT(*) FROM account_access_logs
		WHERE tenant_id = $1 AND user_id = $2
		AND access_type = 'otp_request'
		AND success = false
		AND timestamp BETWEEN $3 AND $4
	`

	oneHourBefore := swapTime.Add(-1 * time.Hour)

	var count int
	if err := db.QueryRow(query, tenantID, userID, oneHourBefore, swapTime).Scan(&count); err != nil {
		return false, fmt.Errorf("query failed-OTP signal: %w", err)
	}

	return count >= 3, nil
}

func hasSettingsChangesAfterSwap(tenantID, userID string, swapTime time.Time) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("database not initialized")
	}
	query := `
		SELECT COUNT(*) FROM account_access_logs
		WHERE tenant_id = $1 AND user_id = $2
		AND access_type = 'settings_change'
		AND timestamp > $3
		AND timestamp < $4
	`

	thirtyMinutesAfter := swapTime.Add(30 * time.Minute)

	var count int
	if err := db.QueryRow(query, tenantID, userID, swapTime, thirtyMinutesAfter).Scan(&count); err != nil {
		return false, fmt.Errorf("query settings-change signal: %w", err)
	}

	return count > 0, nil
}

func hasTransferAttemptsAfterSwap(tenantID, userID string, swapTime time.Time) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("database not initialized")
	}
	query := `
		SELECT COUNT(*) FROM account_access_logs
		WHERE tenant_id = $1 AND user_id = $2
		AND access_type = 'transfer'
		AND timestamp > $3
		AND timestamp < $4
	`

	oneHourAfter := swapTime.Add(1 * time.Hour)

	var count int
	if err := db.QueryRow(query, tenantID, userID, swapTime, oneHourAfter).Scan(&count); err != nil {
		return false, fmt.Errorf("query transfer-attempt signal: %w", err)
	}

	return count > 0, nil
}

func hasFrequentSIMSwaps(tenantID, userID string) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("database not initialized")
	}
	query := `
		SELECT COUNT(*) FROM sim_swap_events
		WHERE tenant_id = $1 AND user_id = $2
		AND swap_timestamp > NOW() - INTERVAL '90 days'
	`

	var count int
	if err := db.QueryRow(query, tenantID, userID).Scan(&count); err != nil {
		return false, fmt.Errorf("query SIM swap history: %w", err)
	}

	return count >= 3, nil
}

func initTelcoVerifier() {
	endpoint := strings.TrimRight(os.Getenv("TELCO_VERIFICATION_URL"), "/")
	apiKey := strings.TrimSpace(os.Getenv("TELCO_VERIFICATION_API_KEY"))
	if endpoint == "" || apiKey == "" {
		log.Fatal("TELCO_VERIFICATION_URL and TELCO_VERIFICATION_API_KEY must be configured")
	}
	telcoVerifier = &telcoVerificationClient{endpoint: endpoint, apiKey: apiKey, httpClient: &http.Client{Timeout: 5 * time.Second}}
}

func verifyWithTelco(requestContext context.Context, telco, phoneNumber, userID string) (bool, error) {
	if telcoVerifier == nil {
		return false, fmt.Errorf("telco verifier is not initialized")
	}
	payload, err := json.Marshal(gin.H{"telco": telco, "phone_number": phoneNumber, "user_id": userID})
	if err != nil {
		return false, fmt.Errorf("encode telco verification request: %w", err)
	}
	req, err := http.NewRequestWithContext(requestContext, http.MethodPost, telcoVerifier.endpoint+"/v1/sim-swaps/verify", bytes.NewReader(payload))
	if err != nil {
		return false, fmt.Errorf("create telco verification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+telcoVerifier.apiKey)
	resp, err := telcoVerifier.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("call telco verifier: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, fmt.Errorf("read telco verification response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("telco verifier returned status %d", resp.StatusCode)
	}
	var verification telcoVerificationResponse
	if err := json.Unmarshal(body, &verification); err != nil {
		return false, fmt.Errorf("decode telco verification response: %w", err)
	}
	if verification.Status == "" {
		return false, fmt.Errorf("telco verification response lacks status")
	}
	return verification.Verified, nil
}

func storeSIMSwapEvent(event SIMSwapEvent, analysis RiskAnalysis) error {
	query := `
		INSERT INTO sim_swap_events
		(tenant_id, event_id, user_id, phone_number, old_sim_id, new_sim_id, telco,
		 swap_timestamp, location, risk_score, risk_level, is_fraud, red_flags)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	redFlagsJSON, _ := json.Marshal(analysis.RedFlags)

	_, err := db.Exec(query,
		event.TenantID,
		event.EventID,
		event.UserID,
		event.PhoneNumber,
		event.OldSIMID,
		event.NewSIMID,
		event.Telco,
		event.SwapTimestamp,
		event.Location,
		analysis.RiskScore,
		analysis.RiskLevel,
		analysis.IsSIMSwapFraud,
		redFlagsJSON,
	)

	return err
}

func createAlert(event SIMSwapEvent, analysis RiskAnalysis) {
	query := `
		INSERT INTO sim_swap_alerts
		(tenant_id, user_id, event_id, risk_score, risk_level, red_flags, recommendation, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
	`

	redFlagsJSON, _ := json.Marshal(analysis.RedFlags)

	_, err := db.Exec(query,
		event.TenantID,
		event.UserID,
		analysis.EventID,
		analysis.RiskScore,
		analysis.RiskLevel,
		redFlagsJSON,
		analysis.Recommendation,
	)

	if err != nil {
		log.Printf("Error creating alert: %v", err)
	}

	// Send notification (SMS/Email)
	sendNotification(event.UserID, analysis)
}

func sendNotification(userID string, analysis RiskAnalysis) {
	// This would integrate with notification service
	log.Printf("ALERT: SIM swap fraud detected for user %s (risk: %d)", userID, analysis.RiskScore)
}

func blockUserAccount(tenantID, userID string, reason string) {
	query := `
		INSERT INTO blocked_accounts (tenant_id, user_id, reason, blocked_at)
		VALUES ($1, $2, $3, NOW())
	`

	_, err := db.Exec(query, tenantID, userID, reason)
	if err != nil {
		log.Printf("Error blocking account: %v", err)
	}

	log.Printf("BLOCKED: Account %s - %s", userID, reason)
}

func verifySIMChange(c *gin.Context) {
	var event SIMSwapEvent
	if err := c.ShouldBindJSON(&event); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	verified, err := verifyWithTelco(c.Request.Context(), event.Telco, event.PhoneNumber, event.UserID)
	if err != nil {
		log.Printf("telco verification unavailable: %v", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "telco verification unavailable"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"event_id": event.EventID,
		"verified": verified,
		"telco":    event.Telco,
		"recommendation": func() string {
			if !verified {
				return "SIM swap not verified by telco - potential fraud"
			}
			return "SIM swap verified by telco"
		}(),
	})
}

func analyzeDevice(c *gin.Context) {
	var device DeviceInfo
	if err := c.ShouldBindJSON(&device); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	device.TenantID = requestTenant(c, device.TenantID)

	// Check if device is known
	isKnown := isKnownDevice(device.TenantID, device.UserID, device.DeviceID)

	// Check if device is suspicious
	isSuspicious := isSuspiciousDevice(device)

	c.JSON(http.StatusOK, gin.H{
		"device_id":     device.DeviceID,
		"is_known":      isKnown,
		"is_suspicious": isSuspicious,
		"recommendation": func() string {
			if !isKnown && isSuspicious {
				return "BLOCK - Unknown and suspicious device"
			} else if !isKnown {
				return "VERIFY - New device detected, require additional verification"
			}
			return "ALLOW - Known device"
		}(),
	})
}

func isKnownDevice(tenantID, userID, deviceID string) bool {
	query := `
		SELECT COUNT(*) FROM device_fingerprints
		WHERE tenant_id = $1 AND user_id = $2 AND device_id = $3
	`

	var count int
	err := db.QueryRow(query, tenantID, userID, deviceID).Scan(&count)
	if err != nil {
		return false
	}

	return count > 0
}

func isSuspiciousDevice(device DeviceInfo) bool {
	// Check for suspicious patterns
	// - VPN/proxy usage
	// - Emulator
	// - Rooted/jailbroken device
	// For now, simplified check
	return false
}

func checkLocationAnomaly(c *gin.Context) {
	var req struct {
		UserID   string `json:"user_id"`
		Location string `json:"location"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hasAnomaly, err := hasLocationAnomaly(requestTenant(c, ""), req.UserID, req.Location)
	if err != nil {
		// Fail-closed: cannot evaluate location history → manual verification.
		log.Printf("Location anomaly check failed for user %s: %v", req.UserID, err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":       "Location check unavailable",
			"disposition": "manual_review",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":    req.UserID,
		"location":   req.Location,
		"is_anomaly": hasAnomaly,
		"recommendation": func() string {
			if hasAnomaly {
				return "Location anomaly detected - require additional verification"
			}
			return "Location is within normal range"
		}(),
	})
}

func monitorAccountAccess(c *gin.Context) {
	var accessLog AccountAccessLog
	if err := c.ShouldBindJSON(&accessLog); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	accessLog.TenantID = requestTenant(c, accessLog.TenantID)

	// Store access log
	storeAccessLog(accessLog)

	// Check for suspicious patterns
	isSuspicious := isAccessSuspicious(accessLog)

	c.JSON(http.StatusOK, gin.H{
		"access_id":     accessLog.AccessID,
		"is_suspicious": isSuspicious,
		"recommendation": func() string {
			if isSuspicious {
				return "Suspicious access pattern - investigate immediately"
			}
			return "Normal access pattern"
		}(),
	})
}

func storeAccessLog(accessLog AccountAccessLog) {
	query := `
		INSERT INTO account_access_logs
		(tenant_id, access_id, user_id, device_id, access_type, success, ip_address, location, timestamp)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := db.Exec(query,
		accessLog.TenantID,
		accessLog.AccessID,
		accessLog.UserID,
		accessLog.DeviceID,
		accessLog.AccessType,
		accessLog.Success,
		accessLog.IPAddress,
		accessLog.Location,
		accessLog.Timestamp,
	)

	if err != nil {
		log.Printf("Error storing access log: %v", err)
	}
}

func isAccessSuspicious(accessLog AccountAccessLog) bool {
	// Check for suspicious patterns
	// - Multiple failed attempts
	// - Access from unusual location
	// - Access at unusual time
	// Simplified for now
	return false
}

func getUserRisk(c *gin.Context) {
	userID := c.Param("user_id")
	tenantID := requestTenant(c, "")

	query := `
		SELECT event_id, risk_score, risk_level, is_fraud, red_flags
		FROM sim_swap_events
		WHERE tenant_id = $1 AND user_id = $2
		ORDER BY swap_timestamp DESC
		LIMIT 1
	`

	var eventID, riskLevel string
	var riskScore int
	var isFraud bool
	var redFlagsJSON []byte

	err := db.QueryRow(query, tenantID, userID).Scan(&eventID, &riskScore, &riskLevel, &isFraud, &redFlagsJSON)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "No SIM swap events found for user"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var redFlags []string
	json.Unmarshal(redFlagsJSON, &redFlags)

	c.JSON(http.StatusOK, gin.H{
		"user_id":    userID,
		"event_id":   eventID,
		"risk_score": riskScore,
		"risk_level": riskLevel,
		"is_fraud":   isFraud,
		"red_flags":  redFlags,
	})
}

func getAlerts(c *gin.Context) {
	tenantID := requestTenant(c, "")
	query := `
		SELECT user_id, event_id, risk_score, risk_level, created_at
		FROM sim_swap_alerts
		WHERE tenant_id = $1
		AND created_at > NOW() - INTERVAL '24 hours'
		ORDER BY created_at DESC
		LIMIT 50
	`

	rows, err := db.Query(query, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	alerts := []gin.H{}
	for rows.Next() {
		var userID, eventID, riskLevel string
		var riskScore int
		var createdAt time.Time

		rows.Scan(&userID, &eventID, &riskScore, &riskLevel, &createdAt)

		alerts = append(alerts, gin.H{
			"user_id":    userID,
			"event_id":   eventID,
			"risk_score": riskScore,
			"risk_level": riskLevel,
			"created_at": createdAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

func getDailyReport(c *gin.Context) {
	query := `
		SELECT
			COUNT(*) as total_events,
			SUM(CASE WHEN is_fraud THEN 1 ELSE 0 END) as fraud_detected,
			AVG(risk_score) as avg_risk_score
		FROM sim_swap_events
		WHERE tenant_id = $1 AND DATE(swap_timestamp) = CURRENT_DATE
	`

	var totalEvents, fraudDetected int
	var avgRiskScore float64

	err := db.QueryRow(query, requestTenant(c, "")).Scan(&totalEvents, &fraudDetected, &avgRiskScore)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"date":           time.Now().Format("2006-01-02"),
		"total_events":   totalEvents,
		"fraud_detected": fraudDetected,
		"avg_risk_score": avgRiskScore,
	})
}

func blockAccount(c *gin.Context) {
	var req struct {
		UserID string `json:"user_id"`
		Reason string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	blockUserAccount(requestTenant(c, ""), req.UserID, req.Reason)

	c.JSON(http.StatusOK, gin.H{
		"user_id": req.UserID,
		"blocked": true,
		"reason":  req.Reason,
	})
}

func healthCheck(c *gin.Context) {
	dbHealthy := true
	if err := db.Ping(); err != nil {
		dbHealthy = false
	}

	redisHealthy := true
	if err := redisClient.Ping(ctx).Err(); err != nil {
		redisHealthy = false
	}

	status := "healthy"
	if !dbHealthy || !redisHealthy {
		status = "degraded"
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    status,
		"database":  dbHealthy,
		"redis":     redisHealthy,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func getRiskLevel(score int) string {
	if score >= 80 {
		return "critical"
	} else if score >= 60 {
		return "high"
	} else if score >= 40 {
		return "medium"
	}
	return "low"
}

func generateRecommendation(score int, shouldBlock bool) string {
	if shouldBlock {
		return "BLOCK ACCOUNT - High probability of SIM swap fraud. Lock account immediately and contact user."
	} else if score >= 60 {
		return "HIGH ALERT - Suspected SIM swap fraud. Require additional verification before allowing transactions."
	} else if score >= 40 {
		return "MONITOR - Some suspicious activity. Watch for additional red flags."
	}
	return "NORMAL - SIM swap appears legitimate."
}


func getEnvInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if n, err := strconv.Atoi(value); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
