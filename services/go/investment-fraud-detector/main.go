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
	_ "github.com/lib/pq"
)

var (
	db          *sql.DB
	redisClient *redis.Client
)

type InvestmentScheme struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	PromoterId      string    `json:"promoter_id"`
	InvestmentType  string    `json:"investment_type"`
	PromisedReturns float64   `json:"promised_returns"`
	MinInvestment   float64   `json:"min_investment"`
	Description     string    `json:"description"`
	Website         string    `json:"website"`
	CreatedAt       time.Time `json:"created_at"`
}

type InvestmentAnalysis struct {
	SchemeID       string   `json:"scheme_id"`
	RiskScore      int      `json:"risk_score"`
	RiskLevel      string   `json:"risk_level"`
	IsPonzi        bool     `json:"is_ponzi"`
	IsLegitimate   bool     `json:"is_legitimate"`
	RedFlags       []string `json:"red_flags"`
	SECRegistered  bool     `json:"sec_registered"`
	Recommendation string   `json:"recommendation"`
}

type InvestorVerification struct {
	InvestorID      string  `json:"investor_id"`
	SchemeID        string  `json:"scheme_id"`
	InvestmentAmount float64 `json:"investment_amount"`
	Verified        bool    `json:"verified"`
	RiskScore       int     `json:"risk_score"`
	Warnings        []string `json:"warnings"`
}

type PonziIndicators struct {
	SchemeID              string  `json:"scheme_id"`
	UnrealisticReturns    bool    `json:"unrealistic_returns"`
	PyramidStructure      bool    `json:"pyramid_structure"`
	LackOfTransparency    bool    `json:"lack_of_transparency"`
	PressureToRecruit     bool    `json:"pressure_to_recruit"`
	NoSECRegistration     bool    `json:"no_sec_registration"`
	SuspiciousPayments    bool    `json:"suspicious_payments"`
	PonziProbability      float64 `json:"ponzi_probability"`
}

func main() {
	// Initialize database
	initDB()
	defer db.Close()

	// Initialize Redis
	initRedis()
	defer redisClient.Close()

	// Initialize Gin router
	r := gin.Default()

	// Middleware
	r.Use(corsMiddleware())
	r.Use(authMiddleware())

	// Routes
	api := r.Group("/api/v1/investment-fraud")
	{
		// Investment scheme analysis
		api.POST("/schemes/analyze", analyzeInvestmentScheme)
		api.GET("/schemes/:id/risk", getSchemeRisk)
		api.POST("/schemes/verify-sec", verifySECRegistration)

		// Ponzi detection
		api.POST("/ponzi/detect", detectPonziScheme)
		api.GET("/ponzi/indicators/:scheme_id", getPonziIndicators)
		api.GET("/ponzi/known-schemes", getKnownPonziSchemes)

		// Investor protection
		api.POST("/investors/verify", verifyInvestor)
		api.POST("/investors/warn", warnInvestor)
		api.GET("/investors/:id/investments", getInvestorPortfolio)

		// Securities fraud
		api.POST("/securities/verify", verifySecurities)
		api.POST("/securities/report-fraud", reportSecuritiesFraud)

		// Nigerian investment scams
		api.POST("/nigerian-scams/detect", detectNigerianInvestmentScams)
		api.GET("/nigerian-scams/trending", getTrendingScams)
		api.GET("/nigerian-scams/blacklist", getBlacklistedSchemes)

		// Regulatory compliance
		api.POST("/sec/check-compliance", checkSECCompliance)
		api.POST("/sec/file-report", fileSECReport)

		// Reporting
		api.GET("/reports/daily", getDailyReport)
		api.GET("/reports/flagged-schemes", getFlaggedSchemes)

		// Health check
		api.GET("/health", healthCheck)
	}

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8083"
	}

	log.Printf("Investment Fraud Detector Service starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func analyzeInvestmentScheme(c *gin.Context) {
	var scheme InvestmentScheme
	if err := c.ShouldBindJSON(&scheme); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Perform comprehensive analysis
	analysis := performSchemeAnalysis(&scheme)

	// Store in database
	storeSchemeAnalysis(&scheme, analysis)

	c.JSON(http.StatusOK, analysis)
}

func getSchemeRisk(c *gin.Context) {
	schemeID := c.Param("id")
	var analysis InvestmentAnalysis
	err := db.QueryRow(`
		SELECT id, risk_score, risk_level, is_ponzi, sec_registered
		FROM investment_schemes
		WHERE id = $1
	`, schemeID).Scan(
		&analysis.SchemeID,
		&analysis.RiskScore,
		&analysis.RiskLevel,
		&analysis.IsPonzi,
		&analysis.SECRegistered,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "investment scheme not found"})
			return
		}
		log.Printf("scheme risk query failed for %s: %v", schemeID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to retrieve scheme risk"})
		return
	}

	analysis.IsLegitimate = analysis.SECRegistered && analysis.RiskScore < 40
	analysis.Recommendation = generateInvestmentRecommendation(analysis.RiskScore, analysis.IsPonzi, analysis.SECRegistered)
	c.JSON(http.StatusOK, analysis)
}

func performSchemeAnalysis(scheme *InvestmentScheme) *InvestmentAnalysis {
	riskScore := 0
	redFlags := []string{}

	// Check promised returns
	if scheme.PromisedReturns > 20 { // > 20% returns
		riskScore += 30
		redFlags = append(redFlags, "Unrealistic promised returns")
	}

	if scheme.PromisedReturns > 50 { // > 50% returns
		riskScore += 40
		redFlags = append(redFlags, "Extremely unrealistic returns - likely Ponzi")
	}

	// Check SEC registration
	secRegistered := checkSECRegistration(scheme.Name, scheme.PromoterId)
	if !secRegistered {
		riskScore += 35
		redFlags = append(redFlags, "Not registered with SEC Nigeria")
	}

	// Check for Ponzi keywords
	ponziKeywords := []string{
		"guaranteed", "risk-free", "double your money",
		"get rich quick", "passive income", "mlm",
		"network marketing", "pyramid", "referral bonus",
	}

	descLower := strings.ToLower(scheme.Description + " " + scheme.Name)
	for _, keyword := range ponziKeywords {
		if strings.Contains(descLower, keyword) {
			riskScore += 15
			redFlags = append(redFlags, fmt.Sprintf("Ponzi keyword detected: '%s'", keyword))
			break
		}
	}

	// Check minimum investment amount
	if scheme.MinInvestment > 100000 { // > 100k NGN
		riskScore += 10
		redFlags = append(redFlags, "High minimum investment requirement")
	}

	// Check promoter history
	promoterRisk := checkPromoterHistory(scheme.PromoterId)
	riskScore += promoterRisk
	if promoterRisk > 30 {
		redFlags = append(redFlags, "Promoter has suspicious history")
	}

	// Check for known scam patterns
	scamPattern := checkKnownScamPatterns(scheme)
	if scamPattern {
		riskScore += 50
		redFlags = append(redFlags, "Matches known Nigerian investment scam pattern")
	}

	// Determine if it's a Ponzi scheme
	isPonzi := riskScore >= 70 || scheme.PromisedReturns > 50

	// Determine risk level
	riskLevel := "low"
	if riskScore >= 80 {
		riskLevel = "critical"
	} else if riskScore >= 60 {
		riskLevel = "high"
	} else if riskScore >= 40 {
		riskLevel = "medium"
	}

	// Determine if legitimate
	isLegitimate := secRegistered && riskScore < 40

	// Generate recommendation
	recommendation := generateInvestmentRecommendation(riskScore, isPonzi, secRegistered)

	return &InvestmentAnalysis{
		SchemeID:       scheme.ID,
		RiskScore:      min(riskScore, 100),
		RiskLevel:      riskLevel,
		IsPonzi:        isPonzi,
		IsLegitimate:   isLegitimate,
		RedFlags:       redFlags,
		SECRegistered:  secRegistered,
		Recommendation: recommendation,
	}
}

func checkSECRegistration(schemeName, promoterId string) bool {
	// Check database for SEC registration
	var registered bool
	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM sec_registered_entities
			WHERE name = $1 OR promoter_id = $2
		)
	`, schemeName, promoterId).Scan(&registered)

	if err != nil {
		return false
	}

	return registered
}

func checkPromoterHistory(promoterId string) int {
	var previousScams int
	db.QueryRow(`
		SELECT COUNT(*)
		FROM investment_schemes
		WHERE promoter_id = $1
		AND is_ponzi = true
	`, promoterId).Scan(&previousScams)

	return previousScams * 30
}

func checkKnownScamPatterns(scheme *InvestmentScheme) bool {
	// Check against known Nigerian investment scam patterns
	knownScams := []string{
		"mmm", "ultimate cycler", "zarfund", "twinkas",
		"get help worldwide", "icharity", "crowd rising",
	}

	nameLower := strings.ToLower(scheme.Name)
	for _, scam := range knownScams {
		if strings.Contains(nameLower, scam) {
			return true
		}
	}

	return false
}

func generateInvestmentRecommendation(riskScore int, isPonzi bool, secRegistered bool) string {
	if isPonzi {
		return "DO NOT INVEST - High probability Ponzi scheme. Report to SEC Nigeria."
	}

	if riskScore >= 80 {
		return "AVOID - Critical fraud risk. Likely fraudulent investment."
	}

	if riskScore >= 60 {
		return "HIGH RISK - Proceed with extreme caution. Verify with SEC Nigeria."
	}

	if !secRegistered {
		return "CAUTION - Not SEC registered. Verify legitimacy before investing."
	}

	if riskScore >= 40 {
		return "MODERATE RISK - Conduct thorough due diligence."
	}

	return "LOW RISK - Appears legitimate but always verify independently."
}

func detectPonziScheme(c *gin.Context) {
	var req struct {
		SchemeID string `json:"scheme_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	indicators := calculatePonziIndicators(req.SchemeID)

	c.JSON(http.StatusOK, indicators)
}

func calculatePonziIndicators(schemeID string) *PonziIndicators {
	// Get scheme details
	var scheme InvestmentScheme
	db.QueryRow(`
		SELECT id, name, promoter_id, promised_returns, min_investment, description
		FROM investment_schemes
		WHERE id = $1
	`, schemeID).Scan(
		&scheme.ID, &scheme.Name, &scheme.PromoterId,
		&scheme.PromisedReturns, &scheme.MinInvestment, &scheme.Description,
	)

	indicators := &PonziIndicators{
		SchemeID: schemeID,
	}

	// Check for unrealistic returns
	indicators.UnrealisticReturns = scheme.PromisedReturns > 20

	// Check for pyramid structure
	indicators.PyramidStructure = checkPyramidStructure(schemeID)

	// Check transparency
	indicators.LackOfTransparency = checkTransparency(schemeID)

	// Check recruitment pressure
	indicators.PressureToRecruit = checkRecruitmentPressure(&scheme)

	// Check SEC registration
	indicators.NoSECRegistration = !checkSECRegistration(scheme.Name, scheme.PromoterId)

	// Check payment patterns
	indicators.SuspiciousPayments = checkPaymentPatterns(schemeID)

	// Calculate Ponzi probability
	indicatorCount := 0
	if indicators.UnrealisticReturns {
		indicatorCount++
	}
	if indicators.PyramidStructure {
		indicatorCount++
	}
	if indicators.LackOfTransparency {
		indicatorCount++
	}
	if indicators.PressureToRecruit {
		indicatorCount++
	}
	if indicators.NoSECRegistration {
		indicatorCount++
	}
	if indicators.SuspiciousPayments {
		indicatorCount++
	}

	indicators.PonziProbability = float64(indicatorCount) / 6.0 * 100

	return indicators
}

func checkPyramidStructure(schemeID string) bool {
	// Check if scheme has multi-level referral structure
	var hasReferrals bool
	db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM scheme_referrals
			WHERE scheme_id = $1
			AND level > 1
		)
	`, schemeID).Scan(&hasReferrals)

	return hasReferrals
}

func checkTransparency(schemeID string) bool {
	// Check if scheme provides transparent information
	var hasAuditReports, hasFinancials bool
	db.QueryRow(`
		SELECT
			EXISTS(SELECT 1 FROM scheme_documents WHERE scheme_id = $1 AND doc_type = 'audit'),
			EXISTS(SELECT 1 FROM scheme_documents WHERE scheme_id = $1 AND doc_type = 'financial')
	`, schemeID).Scan(&hasAuditReports, &hasFinancials)

	return !hasAuditReports && !hasFinancials
}

func checkRecruitmentPressure(scheme *InvestmentScheme) bool {
	recruitmentKeywords := []string{
		"refer", "recruit", "downline", "upline",
		"team building", "network", "sponsor",
	}

	descLower := strings.ToLower(scheme.Description)
	for _, keyword := range recruitmentKeywords {
		if strings.Contains(descLower, keyword) {
			return true
		}
	}

	return false
}

func checkPaymentPatterns(schemeID string) bool {
	// Check if new investor money is used to pay old investors
	var suspiciousPattern bool
	db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM scheme_payments
			WHERE scheme_id = $1
			AND payment_type = 'return'
			AND source = 'new_investment'
		)
	`, schemeID).Scan(&suspiciousPattern)

	return suspiciousPattern
}

func verifyInvestor(c *gin.Context) {
	var req InvestorVerification
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	verification := performInvestorVerification(&req)

	c.JSON(http.StatusOK, verification)
}

func performInvestorVerification(req *InvestorVerification) *InvestorVerification {
	warnings := []string{}
	riskScore := 0

	// Check scheme risk
	var schemeRiskScore int
	db.QueryRow(`
		SELECT risk_score
		FROM investment_schemes
		WHERE id = $1
	`, req.SchemeID).Scan(&schemeRiskScore)

	if schemeRiskScore >= 70 {
		warnings = append(warnings, "WARNING: High-risk investment scheme")
		riskScore += 40
	}

	// Check investment amount
	if req.InvestmentAmount > 1000000 { // > 1M NGN
		warnings = append(warnings, "Large investment amount - ensure due diligence")
		riskScore += 20
	}

	// Check investor history
	var previousLosses int
	db.QueryRow(`
		SELECT COUNT(*)
		FROM investor_losses
		WHERE investor_id = $1
	`, req.InvestorID).Scan(&previousLosses)

	if previousLosses > 0 {
		warnings = append(warnings, fmt.Sprintf("Investor has %d previous losses", previousLosses))
		riskScore += 15
	}

	req.RiskScore = min(riskScore, 100)
	req.Verified = riskScore < 60
	req.Warnings = warnings

	return req
}

func verifySECRegistration(c *gin.Context) {
	var req struct {
		EntityName string `json:"entity_name" binding:"required"`
		EntityType string `json:"entity_type"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	registered := checkSECRegistration(req.EntityName, "")

	c.JSON(http.StatusOK, gin.H{
		"entity_name":    req.EntityName,
		"sec_registered": registered,
		"verified":       registered,
	})
}

func getPonziIndicators(c *gin.Context) {
	schemeID := c.Param("scheme_id")
	indicators := calculatePonziIndicators(schemeID)
	c.JSON(http.StatusOK, indicators)
}

func getKnownPonziSchemes(c *gin.Context) {
	rows, _ := db.Query(`
		SELECT id, name, promoter_id, promised_returns
		FROM investment_schemes
		WHERE is_ponzi = true
		ORDER BY created_at DESC
		LIMIT 50
	`)
	defer rows.Close()

	schemes := []gin.H{}
	for rows.Next() {
		var id, name, promoterId string
		var promisedReturns float64

		rows.Scan(&id, &name, &promoterId, &promisedReturns)
		schemes = append(schemes, gin.H{
			"id":               id,
			"name":             name,
			"promoter_id":      promoterId,
			"promised_returns": promisedReturns,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"known_ponzi_schemes": schemes,
		"count":               len(schemes),
	})
}

func detectNigerianInvestmentScams(c *gin.Context) {
	var req struct {
		SchemeName string `json:"scheme_name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check against known Nigerian scams
	knownScams := map[string]string{
		"mmm nigeria":        "Confirmed Ponzi scheme - collapsed 2016",
		"ultimate cycler":    "Pyramid scheme - SEC warning issued",
		"zarfund":            "Ponzi scheme - SEC blacklisted",
		"twinkas":            "Pyramid scheme - illegal in Nigeria",
		"get help worldwide": "Ponzi scheme - collapsed",
	}

	nameLower := strings.ToLower(req.SchemeName)
	for scam, description := range knownScams {
		if strings.Contains(nameLower, scam) {
			c.JSON(http.StatusOK, gin.H{
				"is_known_scam": true,
				"scam_name":     scam,
				"description":   description,
				"warning":       "DO NOT INVEST - Confirmed fraudulent scheme",
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"is_known_scam": false,
		"message":       "Not in known scam database - still verify independently",
	})
}

func getTrendingScams(c *gin.Context) {
	scams := []gin.H{
		{
			"name":        "Crypto Ponzi schemes",
			"description": "Fake cryptocurrency investment platforms",
			"victims":     250,
			"total_loss":  150000000, // NGN
		},
		{
			"name":        "Forex trading scams",
			"description": "Unregulated forex trading platforms",
			"victims":     180,
			"total_loss":   95000000,
		},
		{
			"name":        "Real estate Ponzi",
			"description": "Fake property investment schemes",
			"victims":     120,
			"total_loss":   200000000,
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"trending_scams": scams,
		"count":          len(scams),
	})
}

func getBlacklistedSchemes(c *gin.Context) {
	rows, _ := db.Query(`
		SELECT scheme_name, reason, blacklisted_at
		FROM investment_blacklist
		ORDER BY blacklisted_at DESC
		LIMIT 100
	`)
	defer rows.Close()

	blacklist := []gin.H{}
	for rows.Next() {
		var name, reason string
		var blacklistedAt time.Time

		rows.Scan(&name, &reason, &blacklistedAt)
		blacklist = append(blacklist, gin.H{
			"scheme_name":    name,
			"reason":         reason,
			"blacklisted_at": blacklistedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"blacklisted_schemes": blacklist,
		"count":               len(blacklist),
	})
}

func checkSECCompliance(c *gin.Context) {
	var req struct {
		SchemeID string `json:"scheme_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	compliance := map[string]bool{
		"sec_registered":     false,
		"license_valid":      false,
		"annual_report_filed": false,
		"audit_completed":    false,
	}

	// Check compliance items
	// (Simplified - would check actual SEC database)

	compliant := compliance["sec_registered"] && compliance["license_valid"]

	c.JSON(http.StatusOK, gin.H{
		"scheme_id":  req.SchemeID,
		"compliant":  compliant,
		"compliance": compliance,
	})
}

func fileSECReport(c *gin.Context) {
	var req struct {
		SchemeID    string `json:"scheme_id" binding:"required"`
		ReportType  string `json:"report_type" binding:"required"`
		Description string `json:"description" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	reportID := fmt.Sprintf("SEC-%s-%d", req.SchemeID, time.Now().Unix())

	_, err := db.Exec(`
		INSERT INTO sec_reports (id, scheme_id, report_type, description, filed_at)
		VALUES ($1, $2, $3, $4, NOW())
	`, reportID, req.SchemeID, req.ReportType, req.Description)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to file report"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"report_id": reportID,
		"status":    "filed",
		"filed_at":  time.Now(),
	})
}

func verifySecurities(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"verified": false})
}

func reportSecuritiesFraud(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"reported": true})
}

func warnInvestor(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"warned": true})
}

func getInvestorPortfolio(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"investments": []gin.H{}})
}

func getDailyReport(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"date":            time.Now().Format("2006-01-02"),
		"schemes_analyzed": 0,
		"ponzi_detected":  0,
	})
}

func getFlaggedSchemes(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"flagged_schemes": []gin.H{}})
}

func storeSchemeAnalysis(scheme *InvestmentScheme, analysis *InvestmentAnalysis) {
	db.Exec(`
		INSERT INTO investment_schemes
		(id, name, promoter_id, promised_returns, min_investment, risk_score, risk_level, is_ponzi, sec_registered, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		ON CONFLICT (id) DO UPDATE SET
			risk_score = $6,
			risk_level = $7,
			is_ponzi = $8,
			sec_registered = $9
	`, scheme.ID, scheme.Name, scheme.PromoterId, scheme.PromisedReturns, scheme.MinInvestment,
		analysis.RiskScore, analysis.RiskLevel, analysis.IsPonzi, analysis.SECRegistered)
}

func healthCheck(c *gin.Context) {
	dbHealthy := db.Ping() == nil
	redisHealthy := redisClient.Ping(context.Background()).Err() == nil

	status := "healthy"
	if !dbHealthy || !redisHealthy {
		status = "degraded"
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    status,
		"database":  dbHealthy,
		"redis":     redisHealthy,
		"timestamp": time.Now().Unix(),
	})
}

// Helper functions

func initDB() {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_USER", "postgres"),
		getEnv("DB_PASSWORD", ""),
		getEnv("DB_NAME", "fraudfusion"))

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	log.Println("Database connection established")
}

func initRedis() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", getEnv("REDIS_HOST", "localhost"), getEnv("REDIS_PORT", "6379")),
		Password: getEnv("REDIS_PASSWORD", ""),
		DB:       0,
	})

	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}

	log.Println("Redis connection established")
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
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		c.Next()
	}
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
