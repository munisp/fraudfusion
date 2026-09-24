package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	_ "github.com/lib/pq"
)

var (
	db          *sql.DB
	redisClient *redis.Client
)

type CryptoTransaction struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	WalletAddress   string    `json:"wallet_address"`
	Cryptocurrency  string    `json:"cryptocurrency"`
	Amount          float64   `json:"amount"`
	TransactionType string    `json:"transaction_type"` // buy, sell, send, receive
	Counterparty    string    `json:"counterparty"`
	Platform        string    `json:"platform"` // binance, luno, quidax, etc.
	Timestamp       time.Time `json:"timestamp"`
}

type CryptoRiskAnalysis struct {
	TransactionID   string   `json:"transaction_id"`
	RiskScore       int      `json:"risk_score"`
	RiskLevel       string   `json:"risk_level"`
	Flagged         bool     `json:"flagged"`
	RiskFactors     []string `json:"risk_factors"`
	WalletRiskScore int      `json:"wallet_risk_score"`
	Recommendation  string   `json:"recommendation"`
}

type WalletVerification struct {
	WalletAddress string    `json:"wallet_address"`
	Verified      bool      `json:"verified"`
	RiskScore     int       `json:"risk_score"`
	Blacklisted   bool      `json:"blacklisted"`
	Exchanges     []string  `json:"exchanges"`
	FirstSeen     time.Time `json:"first_seen"`
	LastActivity  time.Time `json:"last_activity"`
}

type P2PTradingAlert struct {
	TradeID     string    `json:"trade_id"`
	SellerID    string    `json:"seller_id"`
	BuyerID     string    `json:"buyer_id"`
	Amount      float64   `json:"amount"`
	Currency    string    `json:"currency"`
	AlertType   string    `json:"alert_type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	DetectedAt  time.Time `json:"detected_at"`
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
	api := r.Group("/api/v1/crypto-fraud")
	{
		// Transaction analysis
		api.POST("/transactions/analyze", analyzeTransaction)
		api.POST("/transactions/batch-analyze", batchAnalyzeTransactions)
		api.GET("/transactions/:id/risk", getTransactionRisk)

		// Wallet verification
		api.POST("/wallets/verify", verifyWallet)
		api.GET("/wallets/:address/risk", getWalletRisk)
		api.POST("/wallets/blacklist", requireRole("fraud_analyst", "admin"), blacklistWallet)

		// P2P trading fraud detection
		api.POST("/p2p/analyze", analyzeP2PTrade)
		api.GET("/p2p/alerts", getP2PAlerts)

		// Exchange integration
		api.POST("/exchanges/verify", verifyExchange)
		api.GET("/exchanges/:exchange/stats", getExchangeStats)

		// Blockchain analysis
		api.POST("/blockchain/trace", traceBlockchainTransaction)
		api.POST("/blockchain/cluster", clusterWallets)

		// Nigerian crypto fraud patterns
		api.POST("/patterns/detect", detectNigerianCryptoPatterns)
		api.GET("/patterns/trending", getTrendingScams)

		// Reporting
		api.GET("/reports/daily", getDailyReport)
		api.GET("/reports/flagged", getFlaggedTransactions)

		// Health check
		api.GET("/health", healthCheck)
	}

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	log.Printf("Crypto Fraud Detector Service starting on port %s", port)
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func analyzeTransaction(c *gin.Context) {
	var txn CryptoTransaction
	if err := c.ShouldBindJSON(&txn); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Perform risk analysis
	analysis := performRiskAnalysis(c.Request.Context(), &txn)

	// Store in database
	storeTransactionAnalysis(c.Request.Context(), &txn, analysis)

	c.JSON(http.StatusOK, analysis)
}

func performRiskAnalysis(ctx context.Context, txn *CryptoTransaction) *CryptoRiskAnalysis {
	riskScore := 0
	riskFactors := []string{}

	// Check wallet reputation
	walletRisk := checkWalletReputation(ctx, txn.WalletAddress)
	riskScore += walletRisk

	if walletRisk > 70 {
		riskFactors = append(riskFactors, "High-risk wallet address")
	}

	// Check transaction amount
	if txn.Amount > 10000 { // > $10,000 equivalent
		riskScore += 20
		riskFactors = append(riskFactors, "Large transaction amount")
	}

	// Check platform legitimacy
	if !isLegitimateExchange(txn.Platform) {
		riskScore += 30
		riskFactors = append(riskFactors, "Unverified exchange platform")
	}

	// Check for P2P trading patterns
	if strings.Contains(strings.ToLower(txn.Platform), "p2p") {
		p2pRisk := analyzeP2PRisk(ctx, txn)
		riskScore += p2pRisk
		if p2pRisk > 0 {
			riskFactors = append(riskFactors, "P2P trading risk detected")
		}
	}

	// Check transaction velocity
	velocityRisk := checkTransactionVelocity(ctx, txn.UserID)
	riskScore += velocityRisk
	if velocityRisk > 20 {
		riskFactors = append(riskFactors, "Unusual transaction velocity")
	}

	// Check for known scam patterns
	scamRisk := checkScamPatterns(txn)
	riskScore += scamRisk
	if scamRisk > 0 {
		riskFactors = append(riskFactors, "Matches known scam pattern")
	}

	// Determine risk level
	riskLevel := "low"
	if riskScore >= 80 {
		riskLevel = "critical"
	} else if riskScore >= 60 {
		riskLevel = "high"
	} else if riskScore >= 40 {
		riskLevel = "medium"
	}

	// Generate recommendation
	recommendation := generateRecommendation(riskScore, riskFactors)

	return &CryptoRiskAnalysis{
		TransactionID:   txn.ID,
		RiskScore:       min(riskScore, 100),
		RiskLevel:       riskLevel,
		Flagged:         riskScore >= 60,
		RiskFactors:     riskFactors,
		WalletRiskScore: walletRisk,
		Recommendation:  recommendation,
	}
}

func checkWalletReputation(ctx context.Context, address string) int {
	// Check cache first
	cacheKey := fmt.Sprintf("wallet:risk:%s", address)

	if val, err := redisClient.Get(ctx, cacheKey).Result(); err == nil {
		var score int
		fmt.Sscanf(val, "%d", &score)
		return score
	}

	// One round trip: blacklist check + wallet history aggregates.
	var blacklisted bool
	var txnCount int
	var avgAmount float64
	err := db.QueryRowContext(ctx, `
		SELECT
			EXISTS(SELECT 1 FROM crypto_blacklist WHERE wallet_address = $1),
			(SELECT COUNT(*) FROM crypto_transactions WHERE wallet_address = $1),
			(SELECT COALESCE(AVG(amount), 0) FROM crypto_transactions WHERE wallet_address = $1)
	`, address).Scan(&blacklisted, &txnCount, &avgAmount)
	if err != nil {
		log.Printf("wallet reputation query failed for %s: %v", address, err)
	}

	if blacklisted {
		if err := redisClient.Set(ctx, cacheKey, "100", 24*time.Hour).Err(); err != nil {
			log.Printf("redis cache write failed for %s: %v", cacheKey, err)
		}
		return 100
	}

	riskScore := 0

	// New wallet (< 5 transactions)
	if txnCount < 5 {
		riskScore += 30
	}

	// High average transaction amount
	if avgAmount > 5000 {
		riskScore += 20
	}

	// Cache result
	if err := redisClient.Set(ctx, cacheKey, fmt.Sprintf("%d", riskScore), 1*time.Hour).Err(); err != nil {
		log.Printf("redis cache write failed for %s: %v", cacheKey, err)
	}

	return riskScore
}

func isLegitimateExchange(platform string) bool {
	// List of legitimate Nigerian crypto exchanges
	legitimateExchanges := map[string]bool{
		"binance":     true,
		"luno":        true,
		"quidax":      true,
		"buycoin":     true,
		"yellow card": true,
		"coinbase":    true,
		"kraken":      true,
		"paxful":      true,
	}

	platformLower := strings.ToLower(platform)
	for exchange := range legitimateExchanges {
		if strings.Contains(platformLower, exchange) {
			return true
		}
	}

	return false
}

func analyzeP2PRisk(ctx context.Context, txn *CryptoTransaction) int {
	riskScore := 0

	// One round trip: account age + recent P2P velocity.
	var accountAge, recentP2PCount int
	err := db.QueryRowContext(ctx, `
		SELECT
			COALESCE((SELECT EXTRACT(DAY FROM NOW() - created_at) FROM users WHERE id = $1), 0),
			(SELECT COUNT(*) FROM crypto_transactions
				WHERE user_id = $1 AND platform LIKE '%p2p%'
				AND timestamp >= NOW() - INTERVAL '24 hours')
	`, txn.UserID).Scan(&accountAge, &recentP2PCount)
	if err != nil {
		log.Printf("p2p risk query failed for user %s: %v", txn.UserID, err)
	}

	if accountAge < 7 {
		riskScore += 25
	}

	if recentP2PCount > 5 {
		riskScore += 30
	}

	return riskScore
}

func checkTransactionVelocity(ctx context.Context, userID string) int {
	// One scan computing both windows instead of two COUNT(*) round trips.
	var count24h, count1h int
	err := db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours'),
			COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '1 hour')
		FROM crypto_transactions
		WHERE user_id = $1 AND timestamp >= NOW() - INTERVAL '24 hours'
	`, userID).Scan(&count24h, &count1h)
	if err != nil {
		log.Printf("velocity query failed for user %s: %v", userID, err)
	}

	riskScore := 0

	if count24h > 20 {
		riskScore += 25
	}

	if count1h > 5 {
		riskScore += 30
	}

	return riskScore
}

func checkScamPatterns(txn *CryptoTransaction) int {
	riskScore := 0

	// Check for known scam patterns in Nigerian crypto space
	scamPatterns := []string{
		"investment",
		"double",
		"guaranteed",
		"roi",
		"mining pool",
		"cloud mining",
	}

	descriptionLower := strings.ToLower(txn.Platform)
	for _, pattern := range scamPatterns {
		if strings.Contains(descriptionLower, pattern) {
			riskScore += 40
			break
		}
	}

	return riskScore
}

func generateRecommendation(riskScore int, riskFactors []string) string {
	if riskScore >= 80 {
		return "BLOCK transaction immediately - critical fraud risk"
	} else if riskScore >= 60 {
		return "HOLD transaction for manual review - high fraud risk"
	} else if riskScore >= 40 {
		return "APPROVE with enhanced monitoring - medium risk"
	}
	return "APPROVE transaction - low risk"
}

func verifyWallet(c *gin.Context) {
	var req struct {
		WalletAddress string `json:"wallet_address" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	verification := performWalletVerification(c.Request.Context(), req.WalletAddress)

	c.JSON(http.StatusOK, verification)
}

func performWalletVerification(ctx context.Context, address string) *WalletVerification {
	// Check if wallet is blacklisted
	var blacklisted bool
	db.QueryRow("SELECT EXISTS(SELECT 1 FROM crypto_blacklist WHERE wallet_address = $1)", address).Scan(&blacklisted)

	// Get wallet history
	var firstSeen, lastActivity time.Time
	db.QueryRow(`
		SELECT MIN(timestamp), MAX(timestamp)
		FROM crypto_transactions
		WHERE wallet_address = $1
	`, address).Scan(&firstSeen, &lastActivity)

	// Calculate risk score
	riskScore := checkWalletReputation(ctx, address)

	// Get associated exchanges
	rows, _ := db.Query(`
		SELECT DISTINCT platform
		FROM crypto_transactions
		WHERE wallet_address = $1
		LIMIT 10
	`, address)
	defer rows.Close()

	exchanges := []string{}
	for rows.Next() {
		var platform string
		rows.Scan(&platform)
		exchanges = append(exchanges, platform)
	}

	return &WalletVerification{
		WalletAddress: address,
		Verified:      !blacklisted && riskScore < 60,
		RiskScore:     riskScore,
		Blacklisted:   blacklisted,
		Exchanges:     exchanges,
		FirstSeen:     firstSeen,
		LastActivity:  lastActivity,
	}
}

type p2pTradeRequest struct {
	TradeID      string  `json:"trade_id" binding:"required"`
	SellerID     string  `json:"seller_id" binding:"required"`
	BuyerID      string  `json:"buyer_id" binding:"required"`
	Amount       float64 `json:"amount" binding:"gt=0"`
	Currency     string  `json:"currency" binding:"required"`
	PricePerUnit float64 `json:"price_per_unit" binding:"gt=0"`
	Platform     string  `json:"platform" binding:"required"`
}

func analyzeP2PTrade(c *gin.Context) {
	var req p2pTradeRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := storeP2PTrade(&req); err != nil {
		log.Printf("failed to persist P2P trade: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist P2P trade"})
		return
	}
	alerts := detectP2PFraud(&req)
	if err := storeP2PAlerts(c.Request.Context(), alerts); err != nil {
		log.Printf("failed to persist P2P alerts: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist P2P alerts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"trade_id": req.TradeID,
		"alerts":   alerts,
		"flagged":  len(alerts) > 0,
	})
}

func detectP2PFraud(trade *p2pTradeRequest) []*P2PTradingAlert {
	alerts := []*P2PTradingAlert{}

	// Check seller reputation
	var sellerTrades, sellerDisputes int
	db.QueryRow(`
		SELECT COUNT(*), SUM(CASE WHEN disputed THEN 1 ELSE 0 END)
		FROM p2p_trades
		WHERE seller_id = $1
	`, trade.SellerID).Scan(&sellerTrades, &sellerDisputes)

	if sellerTrades > 0 && float64(sellerDisputes)/float64(sellerTrades) > 0.3 {
		alerts = append(alerts, &P2PTradingAlert{
			TradeID:     trade.TradeID,
			SellerID:    trade.SellerID,
			BuyerID:     trade.BuyerID,
			Amount:      trade.Amount,
			Currency:    trade.Currency,
			AlertType:   "high_dispute_rate",
			Severity:    "high",
			Description: fmt.Sprintf("Seller has high dispute rate: %d/%d trades", sellerDisputes, sellerTrades),
			DetectedAt:  time.Now(),
		})
	}

	// Check for price manipulation
	var avgPrice float64
	db.QueryRow(`
		SELECT AVG(price_per_unit)
		FROM p2p_trades
		WHERE currency = $1
		AND created_at >= NOW() - INTERVAL '24 hours'
	`, trade.Currency).Scan(&avgPrice)

	if avgPrice > 0 {
		deviation := math.Abs(trade.PricePerUnit-avgPrice) / avgPrice
		if deviation >= 0.25 {
			severity := "medium"
			if deviation >= 0.50 {
				severity = "high"
			}
			alerts = append(alerts, &P2PTradingAlert{
				TradeID: trade.TradeID, SellerID: trade.SellerID, BuyerID: trade.BuyerID,
				Amount: trade.Amount, Currency: trade.Currency, AlertType: "price_deviation",
				Severity:    severity,
				Description: fmt.Sprintf("P2P price %.8f deviates %.1f%% from 24-hour market average %.8f", trade.PricePerUnit, deviation*100, avgPrice),
				DetectedAt:  time.Now(),
			})
		}
	}

	return alerts
}

func storeP2PTrade(trade *p2pTradeRequest) error {
	_, err := db.Exec(`
		INSERT INTO p2p_trades (id, seller_id, buyer_id, amount, currency, price_per_unit, platform, status, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'analyzed',NOW())
		ON CONFLICT (id) DO UPDATE SET seller_id=EXCLUDED.seller_id, buyer_id=EXCLUDED.buyer_id, amount=EXCLUDED.amount, currency=EXCLUDED.currency, price_per_unit=EXCLUDED.price_per_unit, platform=EXCLUDED.platform, status=EXCLUDED.status`,
		trade.TradeID, trade.SellerID, trade.BuyerID, trade.Amount, trade.Currency, trade.PricePerUnit, trade.Platform)
	return err
}

// storeP2PAlerts inserts all alerts in ONE multi-row statement instead of an
// N+1 loop of round trips.
func storeP2PAlerts(ctx context.Context, alerts []*P2PTradingAlert) error {
	if len(alerts) == 0 {
		return nil
	}
	var sb strings.Builder
	sb.WriteString(`INSERT INTO p2p_trading_alerts (trade_id, seller_id, buyer_id, amount, currency, alert_type, severity, description, detected_at) VALUES `)
	args := make([]interface{}, 0, len(alerts)*9)
	for i, alert := range alerts {
		if i > 0 {
			sb.WriteByte(',')
		}
		base := i*9 + 1
		fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)", base, base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8)
		args = append(args, alert.TradeID, alert.SellerID, alert.BuyerID, alert.Amount, alert.Currency, alert.AlertType, alert.Severity, alert.Description, alert.DetectedAt)
	}
	_, err := db.ExecContext(ctx, sb.String(), args...)
	return err
}

func storeTransactionAnalysis(ctx context.Context, txn *CryptoTransaction, analysis *CryptoRiskAnalysis) {
	_, err := db.ExecContext(ctx, `
		INSERT INTO crypto_transactions
		(id, user_id, wallet_address, cryptocurrency, amount, transaction_type, platform, risk_score, risk_level, flagged, timestamp)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, txn.ID, txn.UserID, txn.WalletAddress, txn.Cryptocurrency, txn.Amount, txn.TransactionType, txn.Platform, analysis.RiskScore, analysis.RiskLevel, analysis.Flagged, txn.Timestamp)

	if err != nil {
		log.Printf("Failed to store transaction analysis: %v", err)
	}
}

// maxBatchSize bounds the batch endpoint so one request cannot queue
// thousands of analyses; batchWorkers bounds concurrent DB/Redis work.
const (
	maxBatchSize = 100
	batchWorkers = 8
)

func batchAnalyzeTransactions(c *gin.Context) {
	var req struct {
		Transactions []CryptoTransaction `json:"transactions"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Transactions) > maxBatchSize {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("batch size exceeds limit of %d", maxBatchSize)})
		return
	}

	ctx := c.Request.Context()
	results := make([]gin.H, len(req.Transactions))
	var wg sync.WaitGroup
	sem := make(chan struct{}, batchWorkers)
	for i := range req.Transactions {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			txn := &req.Transactions[i]
			analysis := performRiskAnalysis(ctx, txn)
			storeTransactionAnalysis(ctx, txn, analysis)
			results[i] = gin.H{
				"transaction_id": txn.ID,
				"risk_score":     analysis.RiskScore,
				"flagged":        analysis.Flagged,
			}
		}(i)
	}
	wg.Wait()

	c.JSON(http.StatusOK, gin.H{
		"total_analyzed": len(req.Transactions),
		"results":        results,
	})
}

func getTransactionRisk(c *gin.Context) {
	txnID := c.Param("id")

	var analysis CryptoRiskAnalysis
	var riskFactorsJSON []byte

	err := db.QueryRow(`
		SELECT risk_score, risk_level, flagged
		FROM crypto_transactions
		WHERE id = $1
	`, txnID).Scan(&analysis.RiskScore, &analysis.RiskLevel, &analysis.Flagged)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Transaction not found"})
		return
	}

	json.Unmarshal(riskFactorsJSON, &analysis.RiskFactors)
	analysis.TransactionID = txnID

	c.JSON(http.StatusOK, analysis)
}

func getWalletRisk(c *gin.Context) {
	address := c.Param("address")
	verification := performWalletVerification(c.Request.Context(), address)
	c.JSON(http.StatusOK, verification)
}

func blacklistWallet(c *gin.Context) {
	var req struct {
		WalletAddress string `json:"wallet_address" binding:"required"`
		Reason        string `json:"reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := db.Exec(`
		INSERT INTO crypto_blacklist (wallet_address, reason, blacklisted_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (wallet_address) DO NOTHING
	`, req.WalletAddress, req.Reason)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to blacklist wallet"})
		return
	}

	// Invalidate cache
	ctx := context.Background()
	if err := redisClient.Del(ctx, fmt.Sprintf("wallet:risk:%s", req.WalletAddress)).Err(); err != nil {
		log.Printf("redis cache invalidate failed for wallet %s: %v", req.WalletAddress, err)
	}

	c.JSON(http.StatusOK, gin.H{
		"wallet_address": req.WalletAddress,
		"blacklisted":    true,
	})
}

func verifyExchange(c *gin.Context) {
	var req struct {
		ExchangeName string `json:"exchange_name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	legitimate := isLegitimateExchange(req.ExchangeName)

	c.JSON(http.StatusOK, gin.H{
		"exchange_name": req.ExchangeName,
		"legitimate":    legitimate,
		"verified":      legitimate,
	})
}

func getExchangeStats(c *gin.Context) {
	exchange := c.Param("exchange")

	var totalTxns int
	var totalVolume float64
	var flaggedCount int

	db.QueryRow(`
		SELECT COUNT(*), COALESCE(SUM(amount), 0), SUM(CASE WHEN flagged THEN 1 ELSE 0 END)
		FROM crypto_transactions
		WHERE platform = $1
	`, exchange).Scan(&totalTxns, &totalVolume, &flaggedCount)

	c.JSON(http.StatusOK, gin.H{
		"exchange":           exchange,
		"total_transactions": totalTxns,
		"total_volume":       totalVolume,
		"flagged_count":      flaggedCount,
		"fraud_rate":         float64(flaggedCount) / float64(max(totalTxns, 1)),
	})
}

func traceBlockchainTransaction(c *gin.Context) {
	var req struct {
		TransactionHash string `json:"transaction_hash" binding:"required"`
		Blockchain      string `json:"blockchain" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Simplified blockchain tracing (would integrate with actual blockchain APIs)
	trace := map[string]interface{}{
		"transaction_hash": req.TransactionHash,
		"blockchain":       req.Blockchain,
		"hops":             []string{},
		"risk_score":       calculateBlockchainRisk(req.TransactionHash),
	}

	c.JSON(http.StatusOK, trace)
}

func calculateBlockchainRisk(txHash string) int {
	// Simplified risk calculation
	// In production, would analyze blockchain data
	hash := sha256.Sum256([]byte(txHash))
	hashHex := hex.EncodeToString(hash[:])

	// Use hash to generate deterministic "risk score"
	score := int(hashHex[0]) % 100
	return score
}

func clusterWallets(c *gin.Context) {
	var req struct {
		WalletAddresses []string `json:"wallet_addresses" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Simplified wallet clustering
	clusters := map[string][]string{
		"cluster_1": req.WalletAddresses,
	}

	c.JSON(http.StatusOK, gin.H{
		"clusters": clusters,
		"count":    len(clusters),
	})
}

func detectNigerianCryptoPatterns(c *gin.Context) {
	var req struct {
		UserID string `json:"user_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	patterns := []string{}

	// Check for Ponzi scheme patterns
	var investmentTxns int
	db.QueryRow(`
		SELECT COUNT(*)
		FROM crypto_transactions
		WHERE user_id = $1
		AND platform LIKE '%investment%'
	`, req.UserID).Scan(&investmentTxns)

	if investmentTxns > 3 {
		patterns = append(patterns, "Potential Ponzi scheme involvement")
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":  req.UserID,
		"patterns": patterns,
		"flagged":  len(patterns) > 0,
	})
}

func getTrendingScams(c *gin.Context) {
	// Return trending crypto scams in Nigeria
	scams := []gin.H{
		{
			"name":        "Fake crypto investment platforms",
			"severity":    "high",
			"occurrences": 150,
		},
		{
			"name":        "P2P payment reversal scams",
			"severity":    "medium",
			"occurrences": 89,
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"trending_scams": scams,
		"count":          len(scams),
	})
}

func getDailyReport(c *gin.Context) {
	dateStr := c.DefaultQuery("date", time.Now().Format("2006-01-02"))
	date, _ := time.Parse("2006-01-02", dateStr)

	var totalTxns, flaggedTxns int
	var totalVolume float64

	db.QueryRow(`
		SELECT COUNT(*), SUM(CASE WHEN flagged THEN 1 ELSE 0 END), COALESCE(SUM(amount), 0)
		FROM crypto_transactions
		WHERE DATE(timestamp) = $1
	`, date).Scan(&totalTxns, &flaggedTxns, &totalVolume)

	c.JSON(http.StatusOK, gin.H{
		"date":                 date.Format("2006-01-02"),
		"total_transactions":   totalTxns,
		"flagged_transactions": flaggedTxns,
		"total_volume":         totalVolume,
		"fraud_rate":           float64(flaggedTxns) / float64(max(totalTxns, 1)),
	})
}

func getFlaggedTransactions(c *gin.Context) {
	limit := 50
	rows, _ := db.Query(`
		SELECT id, user_id, amount, cryptocurrency, risk_score, timestamp
		FROM crypto_transactions
		WHERE flagged = true
		ORDER BY timestamp DESC
		LIMIT $1
	`, limit)
	defer rows.Close()

	transactions := []gin.H{}
	for rows.Next() {
		var id, userID, crypto string
		var amount float64
		var riskScore int
		var timestamp time.Time

		rows.Scan(&id, &userID, &amount, &crypto, &riskScore, &timestamp)
		transactions = append(transactions, gin.H{
			"id":             id,
			"user_id":        userID,
			"amount":         amount,
			"cryptocurrency": crypto,
			"risk_score":     riskScore,
			"timestamp":      timestamp,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"flagged_transactions": transactions,
		"count":                len(transactions),
	})
}

func getP2PAlerts(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"alerts": []gin.H{},
		"count":  0,
	})
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
	sslMode := getEnv("DB_SSLMODE", "require")
	if sslMode == "disable" && !strings.EqualFold(os.Getenv("DB_ALLOW_INSECURE"), "true") {
		log.Fatal("DB_SSLMODE=disable requires DB_ALLOW_INSECURE=true (local development only)")
	}
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_USER", "postgres"),
		getEnv("DB_PASSWORD", ""),
		getEnv("DB_NAME", "fraudfusion"),
		sslMode)

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

	if err := withBackoff(func() error { return db.Ping() }); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	log.Println("Database connection established")
}

func getEnvInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if n, err := strconv.Atoi(value); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func initRedis() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", getEnv("REDIS_HOST", "localhost"), getEnv("REDIS_PORT", "6379")),
		Password: getEnv("REDIS_PASSWORD", ""),
		DB:       0,
	})

	if err := withBackoff(func() error { return redisClient.Ping(context.Background()).Err() }); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}

	log.Println("Redis connection established")
}

// corsMiddleware applies a configurable origin allowlist (CORS_ALLOWED_ORIGINS,
// comma-separated). When unset, no cross-origin access is permitted; the
// previous wildcard ("*") policy was removed.
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

// authMiddleware is implemented in auth.go (Keycloak token introspection, fail-closed).

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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
