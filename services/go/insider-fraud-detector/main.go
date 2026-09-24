package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

const serviceName = "insider-fraud-detector"

type accessEvent struct {
	TenantID   string    `json:"tenant_id" binding:"required"`
	UserID     string    `json:"user_id" binding:"required"`
	EmployeeID string    `json:"employee_id" binding:"required"`
	Action     string    `json:"action" binding:"required"`
	Resource   string    `json:"resource" binding:"required"`
	Timestamp  time.Time `json:"timestamp" binding:"required"`
	IPAddress  string    `json:"ip_address" binding:"required"`
	Location   string    `json:"location"`
}

type unusualActivityRequest struct {
	TenantID   string `json:"tenant_id" binding:"required"`
	EmployeeID string `json:"employee_id" binding:"required"`
	TimeWindow int    `json:"time_window_hours" binding:"gte=1,lte=8760"`
}

type dataExfiltrationRequest struct {
	TenantID    string `json:"tenant_id" binding:"required"`
	EmployeeID  string `json:"employee_id" binding:"required"`
	DataVolume  int64  `json:"data_volume" binding:"gte=0"`
	Destination string `json:"destination" binding:"required"`
}

type collusionRequest struct {
	TenantID    string   `json:"tenant_id" binding:"required"`
	EmployeeIDs []string `json:"employee_ids" binding:"min=2,max=25"`
}

type keycloakClient struct {
	serverURL, realm, clientID, clientSecret string
	httpClient                               *http.Client
	roles                                    map[string]struct{}

	cacheMu  sync.Mutex
	cache    map[string]*introspectCacheEntry
	inflight map[string]*introspectCall
}

type app struct {
	db       *pgxpool.Pool
	keycloak *keycloakClient
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	poolConfig, err := pgxpool.ParseConfig(requiredEnv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("invalid DATABASE_URL: %v", err)
	}
	poolConfig.MaxConns = int32(intEnv("DB_MAX_CONNS", 20))
	poolConfig.MinConns = int32(intEnv("DB_MIN_CONNS", 2))
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		log.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("ping PostgreSQL: %v", err)
	}
	keycloak, err := newKeycloakClient()
	if err != nil {
		log.Fatalf("configure Keycloak: %v", err)
	}
	application := &app{db: pool, keycloak: keycloak}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery(), maxBody(1<<20))
	router.GET("/api/v1/insider-fraud/health", application.health)
	api := router.Group("/api/v1/insider-fraud")
	api.Use(application.authenticate())
	api.POST("/monitor-access", application.monitorAccess)
	api.POST("/detect-unusual-activity", application.detectUnusualActivity)
	api.POST("/detect-data-exfiltration", application.detectDataExfiltration)
	api.POST("/detect-authorization-abuse", application.detectAuthorizationAbuse)
	api.POST("/detect-collusion", application.detectCollusion)
	api.GET("/alerts", application.getAlerts)
	api.GET("/employee-risk-score/:employee_id", application.getEmployeeRiskScore)

	server := &http.Server{Addr: envOr("LISTEN_ADDR", ":8090"), Handler: router, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("%s listening on %s", serviceName, server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve HTTP: %v", err)
	}
}

func (a *app) health(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	if err := a.db.Ping(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy", "service": serviceName})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "healthy", "service": serviceName, "timestamp": time.Now().UTC().Format(time.RFC3339)})
}

func (a *app) monitorAccess(c *gin.Context) {
	var event accessEvent
	if !bindJSON(c, &event) || !tenantMatches(c, event.TenantID) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	if err := a.persistAccess(ctx, event); err != nil {
		internalError(c, err)
		return
	}

	history, err := a.accessHistory(ctx, event.TenantID, event.EmployeeID, 24)
	if err != nil {
		internalError(c, err)
		return
	}
	score, flags := accessRisk(event, history)
	if err := a.persistEventAndAlert(ctx, event.TenantID, event.EmployeeID, "access_monitoring", score, flags, actor(c)); err != nil {
		internalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"employee_id": event.EmployeeID, "risk_score": score, "risk_level": riskLevel(score), "red_flags": flags, "accesses_last_24h": history.total, "evaluated_at": time.Now().UTC().Format(time.RFC3339)})
}

func (a *app) detectUnusualActivity(c *gin.Context) {
	var req unusualActivityRequest
	if !bindJSON(c, &req) || !tenantMatches(c, req.TenantID) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	history, err := a.accessHistory(ctx, req.TenantID, req.EmployeeID, req.TimeWindow)
	if err != nil {
		internalError(c, err)
		return
	}
	patterns := make([]string, 0, 3)
	score := 0
	if history.total >= unusualAccessThreshold(req.TimeWindow) {
		patterns = append(patterns, "excessive_access_events")
		score += 35
	}
	if history.afterHours > 0 {
		patterns = append(patterns, "after_hours_access")
		score += min(25, history.afterHours*5)
	}
	if history.privileged > 0 {
		patterns = append(patterns, "privileged_resource_access")
		score += min(30, history.privileged*5)
	}
	score = min(100, score)
	if err := a.persistEventAndAlert(ctx, req.TenantID, req.EmployeeID, "unusual_activity", score, patterns, actor(c)); err != nil {
		internalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"employee_id": req.EmployeeID, "unusual_patterns": patterns, "risk_score": score, "risk_level": riskLevel(score), "accesses_in_window": history.total, "time_window_hours": req.TimeWindow, "evaluated_at": time.Now().UTC().Format(time.RFC3339)})
}

func (a *app) detectDataExfiltration(c *gin.Context) {
	var req dataExfiltrationRequest
	if !bindJSON(c, &req) || !tenantMatches(c, req.TenantID) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	if _, err := a.db.Exec(ctx, `INSERT INTO data_exfiltration_attempts (tenant_id, employee_id, data_volume, destination, detected_at) VALUES ($1,$2,$3,$4,NOW())`, req.TenantID, req.EmployeeID, req.DataVolume, req.Destination); err != nil {
		internalError(c, err)
		return
	}
	var attempts int
	if err := a.db.QueryRow(ctx, `SELECT COUNT(*) FROM data_exfiltration_attempts WHERE tenant_id=$1 AND employee_id=$2 AND detected_at >= NOW() - INTERVAL '30 days'`, req.TenantID, req.EmployeeID).Scan(&attempts); err != nil {
		internalError(c, err)
		return
	}
	indicators := make([]string, 0, 3)
	score := 0
	if req.DataVolume >= 1_000_000_000 {
		score += 45
		indicators = append(indicators, "large_data_transfer")
	}
	if isExternalDestination(req.Destination) {
		score += 35
		indicators = append(indicators, "external_destination")
	}
	if attempts > 1 {
		score += min(20, (attempts-1)*10)
		indicators = append(indicators, "repeated_exfiltration_attempts")
	}
	score = min(100, score)
	if err := a.persistEventAndAlert(ctx, req.TenantID, req.EmployeeID, "data_exfiltration", score, indicators, actor(c)); err != nil {
		internalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"employee_id": req.EmployeeID, "risk_score": score, "risk_level": riskLevel(score), "indicators": indicators, "is_exfiltration": score >= 60, "attempts_last_30_days": attempts, "evaluated_at": time.Now().UTC().Format(time.RFC3339)})
}

func (a *app) detectAuthorizationAbuse(c *gin.Context) {
	var event accessEvent
	if !bindJSON(c, &event) || !tenantMatches(c, event.TenantID) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	if err := a.persistAccess(ctx, event); err != nil {
		internalError(c, err)
		return
	}
	var privilegedActions int
	var distinctIPs int
	if err := a.db.QueryRow(ctx, `SELECT COUNT(*), COUNT(DISTINCT ip_address) FROM privileged_access_logs WHERE tenant_id=$1 AND employee_id=$2 AND resource IN ('customer_database','financial_records','ledger','kyc_documents') AND created_at >= NOW() - INTERVAL '24 hours'`, event.TenantID, event.EmployeeID).Scan(&privilegedActions, &distinctIPs); err != nil {
		internalError(c, err)
		return
	}
	score := 0
	factors := make([]string, 0, 3)
	if privilegedActions >= 5 {
		score += 50
		factors = append(factors, "repeated_privileged_actions")
	}
	if distinctIPs > 2 {
		score += 25
		factors = append(factors, "multiple_source_ips")
	}
	if event.Timestamp.Hour() < 6 || event.Timestamp.Hour() > 22 {
		score += 20
		factors = append(factors, "after_hours_privileged_action")
	}
	score = min(100, score)
	if err := a.persistEventAndAlert(ctx, event.TenantID, event.EmployeeID, "authorization_abuse", score, factors, actor(c)); err != nil {
		internalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"employee_id": event.EmployeeID, "abuse_detected": score >= 60, "risk_score": score, "risk_level": riskLevel(score), "factors": factors, "privileged_actions_last_24h": privilegedActions, "evaluated_at": time.Now().UTC().Format(time.RFC3339)})
}

func (a *app) detectCollusion(c *gin.Context) {
	var req collusionRequest
	if !bindJSON(c, &req) || !tenantMatches(c, req.TenantID) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	var sharedResourceCount int
	if err := a.db.QueryRow(ctx, `SELECT COUNT(*) FROM (SELECT resource FROM privileged_access_logs WHERE tenant_id=$1 AND employee_id = ANY($2) AND created_at >= NOW() - INTERVAL '24 hours' GROUP BY resource HAVING COUNT(DISTINCT employee_id) >= 2) AS shared_resources`, req.TenantID, req.EmployeeIDs).Scan(&sharedResourceCount); err != nil {
		internalError(c, err)
		return
	}
	score := min(100, sharedResourceCount*35)
	factors := []string{}
	if sharedResourceCount > 0 {
		factors = append(factors, "shared_privileged_resource_access")
	}
	for _, employeeID := range req.EmployeeIDs {
		if err := a.persistEventAndAlert(ctx, req.TenantID, employeeID, "collusion_analysis", score, factors, actor(c)); err != nil {
			internalError(c, err)
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"employees": req.EmployeeIDs, "collusion_detected": score >= 35, "risk_score": score, "risk_level": riskLevel(score), "shared_resource_count": sharedResourceCount, "factors": factors, "evaluated_at": time.Now().UTC().Format(time.RFC3339)})
}

func (a *app) getAlerts(c *gin.Context) {
	tenantID, ok := tenantFromHeader(c)
	if !ok {
		return
	}
	limit := boundedQueryInt(c, "limit", 50, 1, 200)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	rows, err := a.db.Query(ctx, `SELECT id, employee_id, alert_type, risk_level, created_at FROM insider_fraud_alerts WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		internalError(c, err)
		return
	}
	defer rows.Close()
	alerts := make([]gin.H, 0)
	for rows.Next() {
		var id int64
		var employeeID, alertType, level string
		var createdAt time.Time
		if err := rows.Scan(&id, &employeeID, &alertType, &level, &createdAt); err != nil {
			internalError(c, err)
			return
		}
		alerts = append(alerts, gin.H{"alert_id": id, "employee_id": employeeID, "alert_type": alertType, "risk_level": level, "timestamp": createdAt.UTC().Format(time.RFC3339)})
	}
	if err := rows.Err(); err != nil {
		internalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"alerts": alerts, "count": len(alerts)})
}

func (a *app) getEmployeeRiskScore(c *gin.Context) {
	tenantID, ok := tenantFromHeader(c)
	if !ok {
		return
	}
	employeeID := c.Param("employee_id")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	var average float64
	var eventCount int
	if err := a.db.QueryRow(ctx, `SELECT COALESCE(AVG(risk_score),0), COUNT(*) FROM insider_fraud_events WHERE tenant_id=$1 AND employee_id=$2 AND created_at >= NOW() - INTERVAL '365 days'`, tenantID, employeeID).Scan(&average, &eventCount); err != nil {
		internalError(c, err)
		return
	}
	var factors []string
	if err := a.db.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT activity_type), ARRAY[]::TEXT[]) FROM unusual_activities WHERE tenant_id=$1 AND employee_id=$2 AND created_at >= NOW() - INTERVAL '365 days'`, tenantID, employeeID).Scan(&factors); err != nil {
		internalError(c, err)
		return
	}
	score := int(math.Round(math.Min(100, average)))
	c.JSON(http.StatusOK, gin.H{"employee_id": employeeID, "risk_score": score, "risk_level": riskLevel(score), "factors": factors, "events_last_365_days": eventCount, "evaluated_at": time.Now().UTC().Format(time.RFC3339)})
}

type history struct{ total, afterHours, privileged int }

func (a *app) accessHistory(ctx context.Context, tenantID, employeeID string, hours int) (history, error) {
	interval := fmt.Sprintf("%d hours", hours)
	var value history
	err := a.db.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE EXTRACT(HOUR FROM created_at) < 6 OR EXTRACT(HOUR FROM created_at) > 22), COUNT(*) FILTER (WHERE resource IN ('customer_database','financial_records','ledger','kyc_documents')) FROM privileged_access_logs WHERE tenant_id=$1 AND employee_id=$2 AND created_at >= NOW() - $3::interval`, tenantID, employeeID, interval).Scan(&value.total, &value.afterHours, &value.privileged)
	return value, err
}

func (a *app) persistAccess(ctx context.Context, event accessEvent) error {
	_, err := a.db.Exec(ctx, `INSERT INTO privileged_access_logs (tenant_id, employee_id, resource, action, ip_address, location, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, event.TenantID, event.EmployeeID, event.Resource, event.Action, event.IPAddress, event.Location, event.Timestamp.UTC())
	return err
}

func (a *app) persistEventAndAlert(ctx context.Context, tenantID, employeeID, activity string, score int, factors []string, actorID string) error {
	encoded, err := json.Marshal(gin.H{"factors": factors, "actor_id": actorID})
	if err != nil {
		return err
	}
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `INSERT INTO insider_fraud_events (tenant_id, employee_id, event_type, risk_score, metadata, created_at) VALUES ($1,$2,$3,$4,$5,NOW())`, tenantID, employeeID, activity, score, encoded); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO unusual_activities (tenant_id, employee_id, activity_type, risk_score, created_at) VALUES ($1,$2,$3,$4,NOW())`, tenantID, employeeID, activity, score); err != nil {
		return err
	}
	if score >= 50 {
		if _, err = tx.Exec(ctx, `INSERT INTO insider_fraud_alerts (tenant_id, employee_id, alert_type, risk_level, created_at) VALUES ($1,$2,$3,$4,NOW())`, tenantID, employeeID, activity, riskLevel(score)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
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
			log.Printf("insider fraud token validation failed: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		subject, ok := claims["sub"].(string)
		if !ok || subject == "" || !a.keycloak.authorized(claims) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient role"})
			return
		}
		c.Set("subject", subject)
		c.Next()
	}
}

func newKeycloakClient() (*keycloakClient, error) {
	client := &keycloakClient{serverURL: strings.TrimRight(requiredEnv("KEYCLOAK_URL"), "/"), realm: requiredEnv("KEYCLOAK_REALM"), clientID: requiredEnv("KEYCLOAK_CLIENT_ID"), clientSecret: requiredEnv("KEYCLOAK_CLIENT_SECRET"), httpClient: &http.Client{Timeout: 5 * time.Second}, roles: map[string]struct{}{}, cache: make(map[string]*introspectCacheEntry), inflight: make(map[string]*introspectCall)}
	for _, role := range strings.Split(envOr("KEYCLOAK_REQUIRED_ROLES", "fraud_analyst,fraud_operator,admin"), ",") {
		if role = strings.TrimSpace(role); role != "" {
			client.roles[role] = struct{}{}
		}
	}
	return client, nil
}


const (
	// introspectCacheTTL takes the Keycloak round trip (10-40ms) off every
	// authenticated request; revocation lag is bounded by the TTL.
	introspectCacheTTL = 45 * time.Second
	// introspectNegTTL bounds reuse of failed/inactive results.
	introspectNegTTL      = 5 * time.Second
	introspectCacheMaxLen = 10000
)

type introspectCacheEntry struct {
	claims    map[string]interface{}
	err       error
	expiresAt time.Time
}

// introspectCall deduplicates concurrent introspection misses for the same
// token (singleflight): followers wait on done and share the leader's result.
type introspectCall struct {
	done   chan struct{}
	claims map[string]interface{}
	err    error
}

// introspect validates the token through a bounded TTL cache keyed by the
// SHA-256 of the token (the raw token is never a map key) with singleflight
// dedup on misses. Only a cold cache reaches Keycloak.
func (k *keycloakClient) introspect(ctx context.Context, token string) (map[string]interface{}, error) {
	if token == "" {
		return nil, fmt.Errorf("empty access token")
	}
	sum := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(sum[:])

	k.cacheMu.Lock()
	if entry, ok := k.cache[key]; ok && time.Now().Before(entry.expiresAt) {
		k.cacheMu.Unlock()
		return entry.claims, entry.err
	}
	if call, ok := k.inflight[key]; ok {
		k.cacheMu.Unlock()
		select {
		case <-call.done:
			return call.claims, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &introspectCall{done: make(chan struct{})}
	k.inflight[key] = call
	k.cacheMu.Unlock()

	claims, err := k.introspectUncached(ctx, token)
	ttl := introspectCacheTTL
	if err != nil {
		ttl = introspectNegTTL
	}

	k.cacheMu.Lock()
	if len(k.cache) >= introspectCacheMaxLen {
		now := time.Now()
		for ck, e := range k.cache {
			if now.After(e.expiresAt) {
				delete(k.cache, ck)
			}
		}
	}
	if len(k.cache) < introspectCacheMaxLen {
		k.cache[key] = &introspectCacheEntry{claims: claims, err: err, expiresAt: time.Now().Add(ttl)}
	}
	delete(k.inflight, key)
	call.claims, call.err = claims, err
	close(call.done)
	k.cacheMu.Unlock()
	return claims, err
}

func (k *keycloakClient) introspectUncached(ctx context.Context, token string) (map[string]interface{}, error) {
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection status %d", resp.StatusCode)
	}
	claims := map[string]interface{}{}
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, err
	}
	if active, ok := claims["active"].(bool); !ok || !active {
		return nil, fmt.Errorf("inactive token")
	}
	return claims, nil
}

func (k *keycloakClient) authorized(claims map[string]interface{}) bool {
	readRoles := func(value interface{}) []string {
		output := []string{}
		if values, ok := value.([]interface{}); ok {
			for _, item := range values {
				if role, ok := item.(string); ok {
					output = append(output, role)
				}
			}
		}
		if values, ok := value.([]string); ok {
			output = append(output, values...)
		}
		return output
	}
	for _, role := range readRoles(claims["roles"]) {
		if _, ok := k.roles[role]; ok {
			return true
		}
	}
	if realm, ok := claims["realm_access"].(map[string]interface{}); ok {
		for _, role := range readRoles(realm["roles"]) {
			if _, ok := k.roles[role]; ok {
				return true
			}
		}
	}
	return false
}

func maxBody(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) { c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit); c.Next() }
}
func bindJSON(c *gin.Context, target interface{}) bool {
	if err := c.ShouldBindJSON(target); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "detail": err.Error()})
		return false
	}
	return true
}
func tenantFromHeader(c *gin.Context) (string, bool) {
	tenant := strings.TrimSpace(c.GetHeader("X-Tenant-ID"))
	if tenant == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return "", false
	}
	return tenant, true
}
func tenantMatches(c *gin.Context, tenantID string) bool {
	tenant, ok := tenantFromHeader(c)
	if !ok {
		return false
	}
	if tenant != tenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "tenant ID does not match request context"})
		return false
	}
	return true
}
func actor(c *gin.Context) string {
	value, _ := c.Get("subject")
	subject, _ := value.(string)
	return subject
}
func riskLevel(score int) string {
	if score >= 70 {
		return "critical"
	}
	if score >= 50 {
		return "high"
	}
	if score >= 30 {
		return "medium"
	}
	return "low"
}
func accessRisk(event accessEvent, history history) (int, []string) {
	score := 0
	flags := []string{}
	if event.Timestamp.Hour() < 6 || event.Timestamp.Hour() > 22 {
		score += 20
		flags = append(flags, "after_hours_access")
	}
	if isPrivileged(event.Resource) {
		score += 20
		flags = append(flags, "privileged_resource_access")
	}
	if history.total >= 20 {
		score += 25
		flags = append(flags, "high_access_velocity")
	}
	if history.privileged >= 10 {
		score += 20
		flags = append(flags, "repeated_privileged_access")
	}
	return min(100, score), flags
}
func isPrivileged(resource string) bool {
	switch resource {
	case "customer_database", "financial_records", "ledger", "kyc_documents":
		return true
	}
	return false
}
func isExternalDestination(destination string) bool {
	return destination == "external" || destination == "personal_email" || strings.HasPrefix(destination, "http://") || strings.HasPrefix(destination, "https://")
}
func unusualAccessThreshold(hours int) int { return max(10, hours*3) }
func boundedQueryInt(c *gin.Context, key string, fallback, lower, upper int) int {
	value := c.Query(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < lower || parsed > upper {
		return fallback
	}
	return parsed
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
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
