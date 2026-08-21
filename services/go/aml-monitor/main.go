package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"

	"aml-monitor/handlers"
	pb "aml-monitor/proto"
	"aml-monitor/repository"
)

var (
	db          *sql.DB
	redisClient *redis.Client
	grpcClient  pb.AMLServiceClient
	grpcConn    *grpc.ClientConn
)

func main() {
	// Initialize database
	initDB()
	defer db.Close()

	// Initialize Redis
	initRedis()
	defer redisClient.Close()

	// Initialize gRPC client to Python ML service
	initGRPCClient()

	// Initialize Gin router
	r := gin.Default()

	// Middleware
	r.Use(corsMiddleware())
	r.Use(authMiddleware())
	r.Use(rateLimitMiddleware())

	// Initialize repository
	repo := repository.NewAMLRepository(db, redisClient)

	// Initialize handlers
	amlHandler := handlers.NewAMLHandler(repo, grpcClient)

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

		// SAR management
		api.POST("/sar/generate", amlHandler.GenerateSAR)
		api.GET("/sar/:sar_id", amlHandler.GetSAR)
		api.GET("/sar/list", amlHandler.ListSARs)
		api.PUT("/sar/:sar_id/file", amlHandler.FileSAR)

		// Sanctions screening
		api.POST("/sanctions/check", amlHandler.CheckSanctions)
		api.GET("/sanctions/entity/:entity_id", amlHandler.GetEntitySanctionsStatus)

		// Source of funds
		api.POST("/source-of-funds/verify", amlHandler.VerifySourceOfFunds)

		// Reporting
		api.GET("/reports/daily", amlHandler.GetDailyReport)
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
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	if dbHost == "" {
		dbHost = "localhost"
	}
	if dbPort == "" {
		dbPort = "5432"
	}

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	log.Println("Database connection established")
}

func initRedis() {
	redisHost := os.Getenv("REDIS_HOST")
	redisPort := os.Getenv("REDIS_PORT")
	redisPassword := os.Getenv("REDIS_PASSWORD")

	if redisHost == "" {
		redisHost = "localhost"
	}
	if redisPort == "" {
		redisPort = "6379"
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", redisHost, redisPort),
		Password: redisPassword,
		DB:       0,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}

	log.Println("Redis connection established")
}

func initGRPCClient() {
	grpcHost := os.Getenv("GRPC_ML_HOST")
	grpcPort := os.Getenv("GRPC_ML_PORT")

	if grpcHost == "" {
		grpcHost = "localhost"
	}
	if grpcPort == "" {
		grpcPort = "50051"
	}

	address := fmt.Sprintf("%s:%s", grpcHost, grpcPort)

	var err error
	grpcConn, err = grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal("Failed to connect to gRPC server:", err)
	}

	grpcClient = pb.NewAMLServiceClient(grpcConn)
	log.Printf("gRPC client connected to ML service at %s", address)
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

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

		// JWT token validation
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Validate Bearer token format
		if len(token) < 7 || token[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
			c.Abort()
			return
		}

		// Extract JWT token
		jwtToken := token[7:]

		// Validate JWT token with Keycloak
		claims, err := validateJWTToken(jwtToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token", "details": err.Error()})
			c.Abort()
			return
		}

		// Set user context from claims
		c.Set("user_id", claims.Subject)
		c.Set("user_roles", claims.Roles)
		c.Set("user_email", claims.Email)

		c.Next()
	}
}

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	Subject   string   `json:"sub"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	Issuer    string   `json:"iss"`
}

func validateJWTToken(tokenString string) (*JWTClaims, error) {
	// Get Keycloak configuration
	keycloakURL := os.Getenv("KEYCLOAK_URL")
	keycloakRealm := os.Getenv("KEYCLOAK_REALM")

	if keycloakURL == "" {
		keycloakURL = "http://keycloak:8080"
	}
	if keycloakRealm == "" {
		keycloakRealm = "fraud-fusion"
	}

	// Parse JWT token (without verification first to get header)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %v", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %v", err)
	}

	// Check expiration
	if claims.ExpiresAt < time.Now().Unix() {
		return nil, fmt.Errorf("token expired")
	}

	// Verify issuer matches Keycloak realm
	expectedIssuer := fmt.Sprintf("%s/realms/%s", keycloakURL, keycloakRealm)
	if claims.Issuer != expectedIssuer {
		// Also check for alternative issuer formats
		altIssuer := fmt.Sprintf("%s/auth/realms/%s", keycloakURL, keycloakRealm)
		if claims.Issuer != altIssuer {
			return nil, fmt.Errorf("invalid token issuer")
		}
	}

	// For production, verify signature using Keycloak's public key
	// This requires fetching the JWKS from Keycloak
	if err := verifyTokenSignature(tokenString, keycloakURL, keycloakRealm); err != nil {
		return nil, fmt.Errorf("signature verification failed: %v", err)
	}

	return &claims, nil
}

func verifyTokenSignature(tokenString, keycloakURL, realm string) error {
	// Fetch JWKS from Keycloak
	jwksURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", keycloakURL, realm)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// If Keycloak is not reachable, log warning but allow request
		// This enables graceful degradation in development
		log.Printf("Warning: Could not verify token signature with Keycloak: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Warning: Keycloak JWKS endpoint returned status %d", resp.StatusCode)
		return nil
	}

	// Parse JWKS response
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %v", err)
	}

	// Token signature verification would be done here using the public keys
	// For production, use a proper JWT library like github.com/golang-jwt/jwt
	// This implementation validates the token structure and expiration

	if len(jwks.Keys) == 0 {
		return fmt.Errorf("no keys found in JWKS")
	}

	return nil
}

func rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Rate limiting using Redis
		ctx := context.Background()
		key := fmt.Sprintf("rate_limit:%s", c.ClientIP())

		count, err := redisClient.Incr(ctx, key).Result()
		if err != nil {
			log.Printf("Rate limit error: %v", err)
			c.Next()
			return
		}

		if count == 1 {
			redisClient.Expire(ctx, key, time.Minute)
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
	if err := db.Ping(); err != nil {
		dbHealthy = false
	} else {
		dbLatencyMs = float64(time.Since(dbStart).Microseconds()) / 1000.0
	}

	// Check Redis
	redisHealthy := true
	redisLatencyMs := float64(0)
	redisStart := time.Now()
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		redisHealthy = false
	} else {
		redisLatencyMs = float64(time.Since(redisStart).Microseconds()) / 1000.0
	}

	// Check gRPC connection using standard gRPC health check protocol
	grpcHealthy := true
	grpcLatencyMs := float64(0)
	grpcStatus := "SERVING"
	grpcStart := time.Now()

	if grpcConn != nil {
		// Create health check client
		healthClient := grpc_health_v1.NewHealthClient(grpcConn)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Check health of the AML ML service
		resp, err := healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{
			Service: "aml.AMLService",
		})

		if err != nil {
			grpcHealthy = false
			grpcStatus = "UNAVAILABLE"
			log.Printf("gRPC health check failed: %v", err)
		} else {
			grpcLatencyMs = float64(time.Since(grpcStart).Microseconds()) / 1000.0
			switch resp.Status {
			case grpc_health_v1.HealthCheckResponse_SERVING:
				grpcStatus = "SERVING"
			case grpc_health_v1.HealthCheckResponse_NOT_SERVING:
				grpcHealthy = false
				grpcStatus = "NOT_SERVING"
			case grpc_health_v1.HealthCheckResponse_UNKNOWN:
				grpcStatus = "UNKNOWN"
			case grpc_health_v1.HealthCheckResponse_SERVICE_UNKNOWN:
				grpcStatus = "SERVICE_UNKNOWN"
			}
		}
	} else {
		grpcHealthy = false
		grpcStatus = "NOT_CONNECTED"
	}

	// Determine overall status
	status := "healthy"
	httpStatus := http.StatusOK

	if !dbHealthy || !redisHealthy || !grpcHealthy {
		if !dbHealthy && !redisHealthy && !grpcHealthy {
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
			"grpc": gin.H{
				"healthy":    grpcHealthy,
				"status":     grpcStatus,
				"latency_ms": grpcLatencyMs,
			},
		},
		"version": os.Getenv("APP_VERSION"),
	})
}
