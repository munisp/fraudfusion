package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/munisp/fraudfusion/services/go/aml-monitor/handlers"
	"github.com/munisp/fraudfusion/services/go/aml-monitor/mlclient"
	"github.com/munisp/fraudfusion/services/go/aml-monitor/repository"
)

var (
	db          *sql.DB
	redisClient *redis.Client
	mlClient    *mlclient.Client
)

func main() {
	// Initialize database (pgx stdlib driver, TLS required by default)
	initDB()
	defer db.Close()

	// Initialize Redis
	initRedis()
	defer redisClient.Close()

	// Initialize repository and apply idempotent schema
	repo := repository.NewAMLRepository(db, redisClient)
	schemaCtx, schemaCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer schemaCancel()
	if err := repo.EnsureSchema(schemaCtx); err != nil {
		log.Fatal("Failed to ensure AML schema:", err)
	}

	// Initialize HTTP client to the Python ML inference service.
	// The previous gRPC integration referenced generated protobuf bindings
	// that never existed; ML inference is now plain HTTP with timeout/retry
	// and fail-closed-to-manual-review behaviour in the handlers.
	var err error
	mlClient, err = mlclient.NewClient(os.Getenv("AML_ML_SERVICE_URL"))
	if err != nil {
		log.Fatal("Invalid AML_ML_SERVICE_URL:", err)
	}

	// Initialize Gin router
	r := gin.Default()

	// Middleware
	r.Use(corsMiddleware())
	r.Use(authMiddleware())
	r.Use(rateLimitMiddleware())

	// Initialize handlers
	amlHandler := handlers.NewAMLHandler(repo, mlClient)

	// Routes
	api := r.Group("/api/v1/aml")
	{
		// Transaction monitoring
		api.POST("/transactions/analyze", amlHandler.AnalyzeTransaction)
		api.POST("/transactions/batch-analyze", amlHandler.BatchAnalyzeTransactions)
		api.GET("/transactions/:id/risk-score", amlHandler.GetTransactionRiskScore)

		// Pattern detection
		api.POST("/patterns/detect", amlHandler.DetectSuspiciousPatterns)
		api.GET("/users/:user_id/patterns", amlHandler.GetUserPatterns)

		// SAR management — restricted to compliance officers and admins
		sar := api.Group("/sar", requireRole("compliance_officer", "admin"))
		sar.POST("/generate", amlHandler.GenerateSAR)
		sar.GET("/list", amlHandler.ListSARs)
		sar.GET("/:sar_id", amlHandler.GetSAR)
		sar.PUT("/:sar_id/file", amlHandler.FileSAR)

		// Sanctions screening — restricted to compliance officers and admins
		sanctions := api.Group("/sanctions", requireRole("compliance_officer", "admin"))
		sanctions.POST("/check", amlHandler.CheckSanctions)
		sanctions.GET("/entity/:entity_id", amlHandler.GetEntitySanctionsStatus)

		// Source of funds
		api.POST("/source-of-funds/verify", amlHandler.VerifySourceOfFunds)

		// Reporting
		api.GET("/reports/daily", requireRole("compliance_officer", "auditor", "admin"), amlHandler.GetDailyReport)
		api.GET("/reports/flagged-transactions", amlHandler.GetFlaggedTransactions)

		// Health check
		api.GET("/health", healthCheck)
	}

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Printf("AML Monitor Service starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func initDB() {
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	// TLS is required by default; "disable" must be opted into explicitly for
	// local development only, and production configs should use verify-full.
	sslMode := getEnv("DB_SSLMODE", "require")
	if sslMode == "disable" && !strings.EqualFold(os.Getenv("DB_ALLOW_INSECURE"), "true") {
		log.Fatal("DB_SSLMODE=disable requires DB_ALLOW_INSECURE=true (local development only)")
	}

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		dbHost, dbPort, dbUser, dbPassword, dbName, sslMode)

	var err error
	db, err = sql.Open("pgx", connStr)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Test connection with retry/backoff
	ping := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return db.PingContext(ctx)
	}
	if err := withBackoff(ping); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	log.Println("Database connection established")
}

func initRedis() {
	redisHost := getEnv("REDIS_HOST", "localhost")
	redisPort := getEnv("REDIS_PORT", "6379")

	redisClient = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", redisHost, redisPort),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})

	ping := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return redisClient.Ping(ctx).Err()
	}
	if err := withBackoff(ping); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}

	log.Println("Redis connection established")
}

// withBackoff retries op with capped exponential backoff (5 attempts).
func withBackoff(op func() error) error {
	var err error
	delay := 200 * time.Millisecond
	for attempt := 0; attempt < 5; attempt++ {
		if err = op(); err == nil {
			return nil
		}
		time.Sleep(delay)
		delay *= 2
		if delay > 4*time.Second {
			delay = 4 * time.Second
		}
	}
	return err
}

// corsMiddleware applies a configurable origin allowlist. The previous
// implementation allowed any origin ("*"). When CORS_ALLOWED_ORIGINS is unset
// no cross-origin access is permitted.
func corsMiddleware() gin.HandlerFunc {
	allowed := map[string]struct{}{}
	for _, origin := range strings.Split(os.Getenv("CORS_ALLOWED_ORIGINS"), ",") {
		if origin = strings.TrimSpace(origin); origin != "" {
			allowed[origin] = struct{}{}
		}
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if _, ok := allowed[origin]; ok {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Vary", "Origin")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth for health check endpoint
		if c.Request.URL.Path == "/api/v1/aml/health" {
			c.Next()
			return
		}

		token := c.GetHeader("Authorization")
		if len(token) < 8 || token[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer authorization required"})
			c.Abort()
			return
		}

		// FAIL-CLOSED: any verification error denies the request.
		claims, err := validateJWTToken(token[7:])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("user_id", claims.Subject)
		c.Set("user_roles", claims.Roles)
		c.Set("user_email", claims.Email)
		c.Set("jwt_claims", claims)

		c.Next()
	}
}

// requireRole enforces that the authenticated principal carries at least one
// of the required Keycloak realm roles.
func requireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		value, exists := c.Get("jwt_claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			c.Abort()
			return
		}
		claims, ok := value.(*JWTClaims)
		if !ok || !hasAnyRole(claims, roles...) {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient role", "required": roles})
			c.Abort()
			return
		}
		c.Next()
	}
}

// rateLimitScript atomically increments the counter and sets the window
// expiry, removing the Incr-then-Expire race.
var rateLimitScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then
	redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
`)

func rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		key := fmt.Sprintf("rate_limit:%s", c.ClientIP())

		count, err := rateLimitScript.Run(ctx, redisClient, []string{key}, 60).Int()
		if err != nil {
			// FAIL-CLOSED: if the rate limiter cannot run, reject rather than
			// allow unlimited traffic.
			log.Printf("Rate limiter error (failing closed): %v", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "rate limiter unavailable"})
			c.Abort()
			return
		}

		// Limit: 100 requests per minute
		if count > 100 {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func healthCheck(c *gin.Context) {
	// Check database
	dbHealthy := true
	dbLatencyMs := float64(0)
	dbStart := time.Now()
	dbCtx, dbCancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	if err := db.PingContext(dbCtx); err != nil {
		dbHealthy = false
	} else {
		dbLatencyMs = float64(time.Since(dbStart).Microseconds()) / 1000.0
	}
	dbCancel()

	// Check Redis
	redisHealthy := true
	redisLatencyMs := float64(0)
	redisStart := time.Now()
	redisCtx, redisCancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	if err := redisClient.Ping(redisCtx).Err(); err != nil {
		redisHealthy = false
	} else {
		redisLatencyMs = float64(time.Since(redisStart).Microseconds()) / 1000.0
	}
	redisCancel()

	// Check ML inference service over HTTP
	mlHealthy := true
	mlLatencyMs := float64(0)
	mlStart := time.Now()
	mlCtx, mlCancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	if err := mlClient.Health(mlCtx); err != nil {
		mlHealthy = false
	} else {
		mlLatencyMs = float64(time.Since(mlStart).Microseconds()) / 1000.0
	}
	mlCancel()

	// Determine overall status
	status := "healthy"
	httpStatus := http.StatusOK

	if !dbHealthy || !redisHealthy || !mlHealthy {
		if !dbHealthy && !redisHealthy && !mlHealthy {
			status = "unhealthy"
			httpStatus = http.StatusServiceUnavailable
		} else {
			status = "degraded"
		}
	}

	c.JSON(httpStatus, gin.H{
		"status":    status,
		"timestamp": time.Now().Unix(),
		"checks": gin.H{
			"database": gin.H{
				"healthy":    dbHealthy,
				"latency_ms": dbLatencyMs,
			},
			"redis": gin.H{
				"healthy":    redisHealthy,
				"latency_ms": redisLatencyMs,
			},
			"ml_service": gin.H{
				"healthy":    mlHealthy,
				"url":        mlClient.BaseURL(),
				"latency_ms": mlLatencyMs,
			},
		},
		"version": os.Getenv("APP_VERSION"),
	})
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
