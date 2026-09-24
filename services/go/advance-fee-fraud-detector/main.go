package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	_ "github.com/lib/pq"
)

var (
	db          *sql.DB
	redisClient *redis.Client
	ctx         = context.Background()
)

// Message represents an email or message to analyze
type Message struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	SenderEmail string    `json:"sender_email"`
	SenderName  string    `json:"sender_name"`
	Subject     string    `json:"subject"`
	Content     string    `json:"content"`
	Timestamp   time.Time `json:"timestamp"`
}

// RiskAnalysis represents the fraud analysis result
type RiskAnalysis struct {
	MessageID      string   `json:"message_id"`
	RiskScore      int      `json:"risk_score"`
	RiskLevel      string   `json:"risk_level"`
	ScamType       string   `json:"scam_type"`
	Is419Scam      bool     `json:"is_419_scam"`
	RedFlags       []string `json:"red_flags"`
	Recommendation string   `json:"recommendation"`
}

// FeeRequest represents a detected fee request
type FeeRequest struct {
	MessageID  string    `json:"message_id"`
	Amount     float64   `json:"amount"`
	Currency   string    `json:"currency"`
	Purpose    string    `json:"purpose"`
	DetectedAt time.Time `json:"detected_at"`
}

func main() {
	// Initialize database
	initDB()
	defer db.Close()

	// Initialize Redis
	initRedis()
	defer redisClient.Close()

	// Setup Gin router
	router := gin.Default()

	// All routes require a valid Keycloak token (fail-closed introspection);
	// mutating actions additionally require fraud_analyst/admin.
	router.Use(authMiddleware())

	// API routes
	v1 := router.Group("/api/v1/advance-fee-fraud")
	{
		v1.POST("/analyze-message", requireRole("fraud_analyst", "admin"), analyzeMessage)
		v1.POST("/detect-419", requireRole("fraud_analyst", "admin"), detect419)
		v1.POST("/detect-inheritance-scam", requireRole("fraud_analyst", "admin"), detectInheritanceScam)
		v1.POST("/detect-lottery-scam", requireRole("fraud_analyst", "admin"), detectLotteryScam)
		v1.POST("/verify-sender", verifySender)
		v1.POST("/track-fee-requests", requireRole("fraud_analyst", "admin"), trackFeeRequests)
		v1.GET("/risk/:message_id", getMessageRisk)
		v1.GET("/known-patterns", getKnownPatterns)
		v1.GET("/reports/daily", getDailyReport)
		v1.GET("/health", healthCheck)
	}

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8087"
	}

	log.Printf("Advance Fee Fraud Detector starting on port %s", port)
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

func analyzeMessage(c *gin.Context) {
	var message Message
	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	analysis := performAnalysis(message)

	// Store analysis in database
	if err := storeAnalysis(message, analysis); err != nil {
		log.Printf("Error storing analysis: %v", err)
	}

	c.JSON(http.StatusOK, analysis)
}

func performAnalysis(message Message) RiskAnalysis {
	riskScore := 0
	redFlags := []string{}
	scamTypes := []string{}

	combinedText := strings.ToLower(message.Subject + " " + message.Content)

	// Check for Nigerian prince / 419 patterns
	if is419, flags := detect419Pattern(combinedText); is419 {
		riskScore += 50
		redFlags = append(redFlags, flags...)
		scamTypes = append(scamTypes, "419_scam")
	}

	// Check for inheritance scam
	if isInheritance, flags := detectInheritancePattern(combinedText); isInheritance {
		riskScore += 45
		redFlags = append(redFlags, flags...)
		scamTypes = append(scamTypes, "inheritance_scam")
	}

	// Check for lottery scam
	if isLottery, flags := detectLotteryPattern(combinedText); isLottery {
		riskScore += 40
		redFlags = append(redFlags, flags...)
		scamTypes = append(scamTypes, "lottery_scam")
	}

	// Check for business proposal scam
	if isBusiness, flags := detectBusinessProposalPattern(combinedText); isBusiness {
		riskScore += 35
		redFlags = append(redFlags, flags...)
		scamTypes = append(scamTypes, "business_proposal")
	}

	// Check for upfront fee requests
	if feeRequests := detectFeeRequests(combinedText); len(feeRequests) > 0 {
		riskScore += 30
		redFlags = append(redFlags, fmt.Sprintf("%d upfront fee request(s) detected", len(feeRequests)))
	}

	// Check for urgency and secrecy
	if urgencyScore := detectUrgencyAndSecrecy(combinedText); urgencyScore > 0 {
		riskScore += urgencyScore
		redFlags = append(redFlags, "Urgency and secrecy tactics detected")
	}

	// Check sender legitimacy (disposable-looking local part only)
	if !verifySenderLegitimacy(message.SenderEmail) {
		riskScore += 20
		redFlags = append(redFlags, "Suspicious sender email pattern")
	}

	// Check for poor grammar (common in 419 scams)
	if hasGrammarIssues(combinedText) {
		riskScore += 15
		redFlags = append(redFlags, "Poor grammar/spelling detected")
	}

	// Free webmail is never a standalone signal (it is the norm in Nigeria);
	// it only mildly amplifies risk when the CONTENT already flagged.
	if len(redFlags) > 0 && isFreeWebmailProvider(message.SenderEmail) {
		riskScore += 5
		redFlags = append(redFlags, "Free webmail sender combined with other fraud indicators")
	}

	// Determine primary scam type
	scamType := "unknown"
	if len(scamTypes) > 0 {
		scamType = scamTypes[0]
	}

	// Determine risk level
	riskLevel := getRiskLevel(riskScore)

	// Generate recommendation
	recommendation := generateRecommendation(riskScore, scamType)

	return RiskAnalysis{
		MessageID:      message.ID,
		RiskScore:      min(riskScore, 100),
		RiskLevel:      riskLevel,
		ScamType:       scamType,
		Is419Scam:      riskScore >= 60,
		RedFlags:       redFlags,
		Recommendation: recommendation,
	}
}

func detect419Pattern(text string) (bool, []string) {
	flags := []string{}
	score := 0

	patterns := []struct {
		regex string
		flag  string
		score int
	}{
		{`(nigerian|african)\s+(prince|princess|king|royal)`, "Nigerian royalty mentioned", 30},
		{`(million|billion)\s+(dollars|pounds|euros|usd|gbp|eur)`, "Large sum of money mentioned", 25},
		{`(transfer|move)\s+(funds|money)\s+out\s+of`, "Money transfer out of country", 20},
		{`(deceased|late)\s+(relative|husband|wife|father|mother)`, "Deceased relative mentioned", 20},
		{`(confidential|private|secret)\s+(transaction|deal|business)`, "Confidential transaction", 15},
		{`(business\s+proposal|investment\s+opportunity)`, "Business proposal", 15},
		{`(urgent|immediate)\s+(attention|response|reply)`, "Urgent response required", 10},
	}

	for _, p := range patterns {
		matched, _ := regexp.MatchString(p.regex, text)
		if matched {
			score += p.score
			flags = append(flags, p.flag)
		}
	}

	return score >= 30, flags
}

func detectInheritancePattern(text string) (bool, []string) {
	flags := []string{}
	score := 0

	patterns := []struct {
		regex string
		flag  string
		score int
	}{
		{`(inherit|inheritance|estate|will)`, "Inheritance mentioned", 25},
		{`(next\s+of\s+kin|beneficiary|heir)`, "Next of kin/beneficiary", 20},
		{`(unclaimed|dormant)\s+(funds|account)`, "Unclaimed funds", 20},
		{`(lawyer|attorney|solicitor|barrister)`, "Legal representative", 15},
		{`(bank|financial\s+institution)`, "Bank mentioned", 10},
	}

	for _, p := range patterns {
		matched, _ := regexp.MatchString(p.regex, text)
		if matched {
			score += p.score
			flags = append(flags, p.flag)
		}
	}

	return score >= 30, flags
}

func detectLotteryPattern(text string) (bool, []string) {
	flags := []string{}
	score := 0

	patterns := []struct {
		regex string
		flag  string
		score int
	}{
		{`(lottery|sweepstakes|raffle)\s+(winner|won)`, "Lottery winner claim", 30},
		{`(congratulations|congrats).*won`, "Congratulations message", 20},
		{`(claim|collect)\s+(prize|winnings)`, "Prize claim request", 20},
		{`(processing\s+fee|handling\s+fee|tax)`, "Processing fee mentioned", 25},
		{`never\s+(entered|participated)`, "Never entered lottery", 15},
	}

	for _, p := range patterns {
		matched, _ := regexp.MatchString(p.regex, text)
		if matched {
			score += p.score
			flags = append(flags, p.flag)
		}
	}

	return score >= 30, flags
}

func detectBusinessProposalPattern(text string) (bool, []string) {
	flags := []string{}
	score := 0

	patterns := []struct {
		regex string
		flag  string
		score int
	}{
		{`business\s+(proposal|opportunity|partnership)`, "Business proposal", 20},
		{`(lucrative|profitable)\s+(deal|venture)`, "Lucrative deal", 15},
		{`(commission|percentage)\s+for\s+your\s+(assistance|help)`, "Commission offer", 20},
		{`(confidential|discreet)\s+(transaction|deal)`, "Confidential deal", 15},
		{`(foreign|overseas)\s+(investment|contract)`, "Foreign investment", 15},
	}

	for _, p := range patterns {
		matched, _ := regexp.MatchString(p.regex, text)
		if matched {
			score += p.score
			flags = append(flags, p.flag)
		}
	}

	return score >= 25, flags
}

func detectFeeRequests(text string) []string {
	requests := []string{}

	patterns := []string{
		`(processing|handling|transfer|legal|administrative)\s+fee`,
		`(pay|send|wire|transfer)\s+.*\s+(fee|charge|cost)`,
		`upfront\s+(payment|fee|cost)`,
		`(advance|initial)\s+(payment|deposit)`,
		`(tax|duty|customs)\s+(payment|fee)`,
	}

	for _, pattern := range patterns {
		matched, _ := regexp.MatchString(pattern, text)
		if matched {
			requests = append(requests, pattern)
		}
	}

	return requests
}

func detectUrgencyAndSecrecy(text string) int {
	score := 0

	urgencyKeywords := []string{"urgent", "immediate", "quickly", "asap", "time sensitive", "deadline"}
	secrecyKeywords := []string{"confidential", "secret", "private", "discreet", "do not tell", "keep quiet"}

	for _, keyword := range urgencyKeywords {
		if strings.Contains(text, keyword) {
			score += 5
		}
	}

	for _, keyword := range secrecyKeywords {
		if strings.Contains(text, keyword) {
			score += 5
		}
	}

	return min(score, 20)
}

// freeWebmailProviders are the dominant consumer mail providers in Nigeria;
// using one is normal and must never be a standalone fraud signal.
var freeWebmailProviders = []string{"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}

// isFreeWebmailProvider reports whether the email is hosted on a common free
// webmail provider.
func isFreeWebmailProvider(email string) bool {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 {
		return false
	}
	for _, provider := range freeWebmailProviders {
		if parts[1] == provider {
			return true
		}
	}
	return false
}

// suspiciousLocalPart matches disposable-looking local parts (5+ digit runs),
// e.g. "agent78342@...". Checked against the local part only.
var suspiciousLocalPart = regexp.MustCompile(`^[^@]*\d{5,}[^@]*@`)

func verifySenderLegitimacy(email string) bool {
	// Only genuinely suspicious sender patterns flag here — free webmail
	// providers (Gmail/Yahoo/Hotmail/Outlook) are the norm in Nigeria and are
	// handled as a mild combined signal in performAnalysis instead.
	return !suspiciousLocalPart.MatchString(strings.ToLower(email))
}

func hasGrammarIssues(text string) bool {
	// Simplified grammar check
	issues := 0

	// Multiple spaces
	if strings.Contains(text, "  ") {
		issues++
	}

	// Excessive punctuation
	if strings.Count(text, "!") > 3 || strings.Count(text, "?") > 3 {
		issues++
	}

	// Common grammar errors in scams
	grammarErrors := []string{
		"i am writing you",
		"i am contacting you",
		"this is to inform you that",
		"dear sir/madam",
		"dear friend",
	}

	for _, error := range grammarErrors {
		if strings.Contains(text, error) {
			issues++
		}
	}

	return issues >= 2
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

func generateRecommendation(score int, scamType string) string {
	if score >= 80 {
		return fmt.Sprintf("BLOCK - Confirmed %s detected. Delete immediately and report as spam.", scamType)
	} else if score >= 60 {
		return fmt.Sprintf("HIGH RISK - Likely %s. Do not respond or send any money.", scamType)
	} else if score >= 40 {
		return fmt.Sprintf("CAUTION - Potential %s indicators. Verify sender before responding.", scamType)
	}
	return "LOW RISK - Standard email precautions apply."
}

func storeAnalysis(message Message, analysis RiskAnalysis) error {
	query := `
		INSERT INTO advance_fee_messages
		(message_id, user_id, sender_email, sender_name, subject, content,
		 risk_score, risk_level, scam_type, is_419_scam, red_flags, recommendation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	redFlagsJSON, _ := json.Marshal(analysis.RedFlags)

	_, err := db.Exec(query,
		analysis.MessageID,
		message.UserID,
		message.SenderEmail,
		message.SenderName,
		message.Subject,
		message.Content,
		analysis.RiskScore,
		analysis.RiskLevel,
		analysis.ScamType,
		analysis.Is419Scam,
		redFlagsJSON,
		analysis.Recommendation,
	)

	return err
}

func detect419(c *gin.Context) {
	var message Message
	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	combinedText := strings.ToLower(message.Subject + " " + message.Content)
	is419, flags := detect419Pattern(combinedText)

	c.JSON(http.StatusOK, gin.H{
		"message_id":  message.ID,
		"is_419_scam": is419,
		"red_flags":   flags,
		"recommendation": func() string {
			if is419 {
				return "BLOCK - Nigerian 419 scam detected"
			}
			return "No 419 pattern detected"
		}(),
	})
}

func detectInheritanceScam(c *gin.Context) {
	var message Message
	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	combinedText := strings.ToLower(message.Subject + " " + message.Content)
	isInheritance, flags := detectInheritancePattern(combinedText)

	c.JSON(http.StatusOK, gin.H{
		"message_id":          message.ID,
		"is_inheritance_scam": isInheritance,
		"red_flags":           flags,
		"recommendation": func() string {
			if isInheritance {
				return "BLOCK - Inheritance scam detected"
			}
			return "No inheritance scam pattern detected"
		}(),
	})
}

func detectLotteryScam(c *gin.Context) {
	var message Message
	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	combinedText := strings.ToLower(message.Subject + " " + message.Content)
	isLottery, flags := detectLotteryPattern(combinedText)

	c.JSON(http.StatusOK, gin.H{
		"message_id":      message.ID,
		"is_lottery_scam": isLottery,
		"red_flags":       flags,
		"recommendation": func() string {
			if isLottery {
				return "BLOCK - Lottery scam detected"
			}
			return "No lottery scam pattern detected"
		}(),
	})
}

func verifySender(c *gin.Context) {
	var req struct {
		SenderEmail string `json:"sender_email"`
		SenderName  string `json:"sender_name"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	isLegit := verifySenderLegitimacy(req.SenderEmail)

	c.JSON(http.StatusOK, gin.H{
		"sender_email":  req.SenderEmail,
		"is_legitimate": isLegit,
		"recommendation": func() string {
			if !isLegit {
				return "Suspicious sender - verify through official channels"
			}
			return "Sender appears legitimate"
		}(),
	})
}

func trackFeeRequests(c *gin.Context) {
	var message Message
	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	combinedText := strings.ToLower(message.Subject + " " + message.Content)
	feeRequests := detectFeeRequests(combinedText)

	c.JSON(http.StatusOK, gin.H{
		"message_id":            message.ID,
		"fee_requests_detected": len(feeRequests) > 0,
		"request_count":         len(feeRequests),
		"requests":              feeRequests,
		"recommendation": func() string {
			if len(feeRequests) > 0 {
				return "WARNING - Upfront fee request detected. Do not send money."
			}
			return "No fee requests detected"
		}(),
	})
}

func getMessageRisk(c *gin.Context) {
	messageID := c.Param("message_id")

	var analysis RiskAnalysis
	var redFlagsJSON []byte

	query := `
		SELECT message_id, risk_score, risk_level, scam_type, is_419_scam, red_flags, recommendation
		FROM advance_fee_messages
		WHERE message_id = $1
	`

	err := db.QueryRow(query, messageID).Scan(
		&analysis.MessageID,
		&analysis.RiskScore,
		&analysis.RiskLevel,
		&analysis.ScamType,
		&analysis.Is419Scam,
		&redFlagsJSON,
		&analysis.Recommendation,
	)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Message not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	json.Unmarshal(redFlagsJSON, &analysis.RedFlags)

	c.JSON(http.StatusOK, analysis)
}

func getKnownPatterns(c *gin.Context) {
	patterns := []gin.H{
		{"type": "419_scam", "description": "Nigerian prince / inheritance scam"},
		{"type": "lottery_scam", "description": "Fake lottery winnings"},
		{"type": "inheritance_scam", "description": "Unclaimed inheritance"},
		{"type": "business_proposal", "description": "Fake business opportunity"},
		{"type": "overpayment", "description": "Overpayment scam"},
		{"type": "employment", "description": "Fake job offer"},
	}

	c.JSON(http.StatusOK, gin.H{
		"patterns": patterns,
		"count":    len(patterns),
	})
}

func getDailyReport(c *gin.Context) {
	query := `
		SELECT
			COUNT(*) as total_analyzed,
			SUM(CASE WHEN is_419_scam THEN 1 ELSE 0 END) as scams_detected,
			AVG(risk_score) as avg_risk_score
		FROM advance_fee_messages
		WHERE DATE(created_at) = CURRENT_DATE
	`

	var totalAnalyzed, scamsDetected int
	var avgRiskScore float64

	err := db.QueryRow(query).Scan(&totalAnalyzed, &scamsDetected, &avgRiskScore)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"date":           time.Now().Format("2006-01-02"),
		"total_analyzed": totalAnalyzed,
		"scams_detected": scamsDetected,
		"avg_risk_score": avgRiskScore,
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
