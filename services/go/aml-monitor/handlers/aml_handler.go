package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/munisp/fraudfusion/services/go/aml-monitor/mlclient"
	"github.com/munisp/fraudfusion/services/go/aml-monitor/models"
	"github.com/munisp/fraudfusion/services/go/aml-monitor/repository"
)

type AMLHandler struct {
	repo      *repository.AMLRepository
	ml        *mlclient.Client
	watchlist *Watchlist
}

// batchWorkers bounds concurrent ML+DB work inside one batch request.
const batchWorkers = 10

func NewAMLHandler(repo *repository.AMLRepository, ml *mlclient.Client, watchlist *Watchlist) *AMLHandler {
	return &AMLHandler{
		repo:      repo,
		ml:        ml,
		watchlist: watchlist,
	}
}

// manualReviewTransactionResponse fails closed: when the ML service is
// unavailable the transaction is flagged and routed to manual review instead
// of being waved through.
func manualReviewTransactionResponse(c *gin.Context, transactionID string, mlErr error) {
	log.Printf("ML scoring unavailable for %s, routing to manual review: %v", transactionID, mlErr)
	c.JSON(http.StatusAccepted, gin.H{
		"transaction_id": transactionID,
		"risk_score":     100,
		"risk_level":     "manual_review",
		"flagged":        true,
		"sar_required":   false,
		"recommendation": "ML scoring unavailable - routed to manual review",
		"analyzed_at":    time.Now().Unix(),
	})
}

// AnalyzeTransaction handles single transaction analysis
func (h *AMLHandler) AnalyzeTransaction(c *gin.Context) {
	var req models.TransactionAnalysisRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Call the ML inference service over HTTP
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	mlReq := &mlclient.TransactionRequest{
		TransactionID:   req.TransactionID,
		UserID:          req.UserID,
		Amount:          req.Amount,
		Currency:        req.Currency,
		TransactionType: req.TransactionType,
		CountryCode:     req.CountryCode,
		Timestamp:       time.Now().Unix(),
	}

	resp, err := h.ml.AnalyzeTransaction(ctx, mlReq)
	if err != nil {
		// Fail closed to manual review; never allow unscored transactions.
		analysis := &models.TransactionAnalysis{
			TransactionID:  req.TransactionID,
			UserID:         req.UserID,
			RiskScore:      100,
			RiskLevel:      "manual_review",
			Flagged:        true,
			Recommendation: "ML scoring unavailable - routed to manual review",
			CreatedAt:      time.Now(),
		}
		if storeErr := h.repo.StoreTransactionAnalysis(analysis); storeErr != nil {
			log.Printf("Failed to store manual-review analysis: %v", storeErr)
		}
		manualReviewTransactionResponse(c, req.TransactionID, err)
		return
	}

	// Nigerian CTR rule: NGN transactions at or above the ₦10M threshold are
	// auto-flagged and a CTR obligation is recorded, regardless of ML score.
	ctrRequired := requiresCTR(req.Currency, req.Amount)
	riskScore := resp.RiskScore
	riskFactors := resp.RiskFactors
	flagged := resp.Flagged
	if ctrRequired {
		flagged = true
		if riskScore < 80 {
			riskScore = 80
		}
		riskFactors = append(riskFactors, fmt.Sprintf("ctr_threshold_exceeded: NGN %.0f >= %.0f (NFIU CTR)", req.Amount, ctrThresholdNGN()))
		if err := h.repo.StoreCTRReport(&models.CTRReport{
			TransactionID: req.TransactionID,
			UserID:        req.UserID,
			Amount:        req.Amount,
			Currency:      req.Currency,
			Threshold:     ctrThresholdNGN(),
			Status:        "pending_report",
		}); err != nil {
			log.Printf("Failed to record CTR obligation for %s: %v", req.TransactionID, err)
		}
	}

	// Store result in database
	analysis := &models.TransactionAnalysis{
		TransactionID:  req.TransactionID,
		UserID:         req.UserID,
		RiskScore:      int(riskScore),
		RiskLevel:      resp.RiskLevel,
		Flagged:        flagged,
		SARRequired:    resp.SarRequired,
		RiskFactors:    riskFactors,
		Recommendation: resp.Recommendation,
		CreatedAt:      time.Now(),
	}

	if err := h.repo.StoreTransactionAnalysis(analysis); err != nil {
		log.Printf("Failed to store analysis: %v", err)
	}
	h.repo.CacheRiskScore(req.TransactionID, int(riskScore))

	c.JSON(http.StatusOK, gin.H{
		"transaction_id":  resp.TransactionID,
		"risk_score":      riskScore,
		"risk_level":      resp.RiskLevel,
		"risk_factors":    riskFactors,
		"flagged":         flagged,
		"sar_required":    resp.SarRequired,
		"ctr_required":    ctrRequired,
		"recommendation":  resp.Recommendation,
		"detailed_scores": resp.DetailedScores,
		"analyzed_at":     time.Now().Unix(),
	})
}

// BatchAnalyzeTransactions handles batch transaction analysis
func (h *AMLHandler) BatchAnalyzeTransactions(c *gin.Context) {
	var req models.BatchTransactionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.Transactions) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No transactions provided"})
		return
	}

	if len(req.Transactions) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum 100 transactions per batch"})
		return
	}

	results := make([]map[string]interface{}, len(req.Transactions))
	var flaggedCount, sarRequiredCount int64

	// Fan out with a bounded worker pool: 100 transactions serially paying an
	// ML round trip each was the audit's worst batch path (A3).
	var wg sync.WaitGroup
	sem := make(chan struct{}, batchWorkers)
	for i := range req.Transactions {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			txn := req.Transactions[i]
			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()

			mlReq := &mlclient.TransactionRequest{
				TransactionID:   txn.TransactionID,
				UserID:          txn.UserID,
				Amount:          txn.Amount,
				Currency:        txn.Currency,
				TransactionType: txn.TransactionType,
				CountryCode:     txn.CountryCode,
				Timestamp:       time.Now().Unix(),
			}

			resp, err := h.ml.AnalyzeTransaction(ctx, mlReq)
			if err != nil {
				// Fail closed: unscored transactions are flagged for manual review.
				results[i] = map[string]interface{}{
					"transaction_id": txn.TransactionID,
					"risk_level":     "manual_review",
					"flagged":        true,
					"error":          "Analysis unavailable - routed to manual review",
				}
				return
			}

			// Nigerian CTR rule applies per transaction in batch too.
			ctrRequired := requiresCTR(txn.Currency, txn.Amount)
			flagged := resp.Flagged || ctrRequired

			if flagged {
				atomic.AddInt64(&flaggedCount, 1)
			}
			if resp.SarRequired {
				atomic.AddInt64(&sarRequiredCount, 1)
			}

			results[i] = map[string]interface{}{
				"transaction_id": resp.TransactionID,
				"risk_score":     resp.RiskScore,
				"risk_level":     resp.RiskLevel,
				"flagged":        flagged,
				"sar_required":   resp.SarRequired,
				"ctr_required":   ctrRequired,
			}

			if ctrRequired {
				h.repo.StoreCTRReport(&models.CTRReport{
					TransactionID: txn.TransactionID,
					UserID:        txn.UserID,
					Amount:        txn.Amount,
					Currency:      txn.Currency,
					Threshold:     ctrThresholdNGN(),
					Status:        "pending_report",
				})
			}

			// Store in database
			analysis := &models.TransactionAnalysis{
				TransactionID: txn.TransactionID,
				UserID:        txn.UserID,
				RiskScore:     int(resp.RiskScore),
				RiskLevel:     resp.RiskLevel,
				Flagged:       flagged,
				SARRequired:   resp.SarRequired,
				RiskFactors:   resp.RiskFactors,
				CreatedAt:     time.Now(),
			}
			h.repo.StoreTransactionAnalysis(analysis)
		}(i)
	}
	wg.Wait()

	c.JSON(http.StatusOK, gin.H{
		"total_analyzed":     len(req.Transactions),
		"flagged_count":      flaggedCount,
		"sar_required_count": sarRequiredCount,
		"results":            results,
	})
}

// GetTransactionRiskScore retrieves risk score for a transaction
func (h *AMLHandler) GetTransactionRiskScore(c *gin.Context) {
	transactionID := c.Param("id")
	if transactionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Transaction ID required"})
		return
	}

	// Check cache first
	if score, found := h.repo.GetCachedRiskScore(transactionID); found {
		c.JSON(http.StatusOK, gin.H{
			"transaction_id": transactionID,
			"risk_score":     score,
			"source":         "cache",
		})
		return
	}

	// Get from database
	analysis, err := h.repo.GetTransactionAnalysis(transactionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Transaction not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"transaction_id": analysis.TransactionID,
		"risk_score":     analysis.RiskScore,
		"risk_level":     analysis.RiskLevel,
		"flagged":        analysis.Flagged,
		"sar_required":   analysis.SARRequired,
		"risk_factors":   analysis.RiskFactors,
		"analyzed_at":    analysis.CreatedAt.Unix(),
		"source":         "database",
	})
}

// DetectSuspiciousPatterns detects patterns across transactions
func (h *AMLHandler) DetectSuspiciousPatterns(c *gin.Context) {
	var req models.PatternDetectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.UserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID required"})
		return
	}

	if req.DaysLookback == 0 {
		req.DaysLookback = 30 // Default to 30 days
	}

	// Call the ML inference service over HTTP
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	mlReq := &mlclient.PatternRequest{
		UserID:       req.UserID,
		DaysLookback: int32(req.DaysLookback),
	}

	resp, err := h.ml.DetectSuspiciousPattern(ctx, mlReq)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Pattern detection unavailable", "details": err.Error()})
		return
	}

	// Store patterns in database
	for _, pattern := range resp.Patterns {
		patternRecord := &models.SuspiciousPattern{
			UserID:         req.UserID,
			PatternType:    pattern.PatternType,
			Description:    pattern.Description,
			Confidence:     int(pattern.Confidence),
			TransactionIDs: pattern.TransactionIDs,
			TotalAmount:    pattern.TotalAmount,
			DetectedAt:     time.Now(),
		}
		h.repo.StorePattern(patternRecord)
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":            resp.UserID,
		"patterns_detected":  len(resp.Patterns),
		"patterns":           resp.Patterns,
		"overall_risk_score": resp.OverallRiskScore,
		"suspicious":         resp.Suspicious,
	})
}

// GetUserPatterns retrieves patterns for a user
func (h *AMLHandler) GetUserPatterns(c *gin.Context) {
	userID := c.Param("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID required"})
		return
	}

	daysStr := c.DefaultQuery("days", "30")
	days, _ := strconv.Atoi(daysStr)

	limit := 200
	if raw := c.Query("limit"); raw != "" {
		if parsed, parseErr := strconv.Atoi(raw); parseErr == nil {
			limit = parsed
		}
	}
	patterns, err := h.repo.GetUserPatterns(userID, days, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve patterns"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":        userID,
		"patterns_count": len(patterns),
		"patterns":       patterns,
	})
}

// GenerateSAR generates a Suspicious Activity Report
func (h *AMLHandler) GenerateSAR(c *gin.Context) {
	var req models.SARGenerationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := req.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Call the ML inference service over HTTP
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	mlReq := &mlclient.SARRequest{
		UserID:                 req.UserID,
		TransactionIDs:         req.TransactionIDs,
		SuspiciousActivityType: req.ActivityType,
		Narrative:              req.Narrative,
	}

	resp, err := h.ml.GenerateSAR(ctx, mlReq)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "SAR generation unavailable", "details": err.Error()})
		return
	}

	// Store SAR in database
	sar := &models.SAR{
		SARID:             resp.SarID,
		UserID:            resp.UserID,
		FilingInstitution: resp.FilingInstitution,
		ActivityType:      resp.SuspiciousActivityType,
		Narrative:         resp.Narrative,
		TransactionIDs:    req.TransactionIDs,
		FilingDate:        time.Unix(resp.FilingDate, 0),
		Status:            resp.Status,
		CreatedAt:         time.Now(),
	}

	if err := h.repo.StoreSAR(sar); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store SAR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sar_id":             resp.SarID,
		"user_id":            resp.UserID,
		"filing_institution": resp.FilingInstitution,
		"activity_type":      resp.SuspiciousActivityType,
		"status":             resp.Status,
		"filing_date":        resp.FilingDate,
		"transactions_count": len(resp.Transactions),
	})
}

// GetSAR retrieves a SAR by ID
func (h *AMLHandler) GetSAR(c *gin.Context) {
	sarID := c.Param("sar_id")
	if sarID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SAR ID required"})
		return
	}

	sar, err := h.repo.GetSAR(sarID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "SAR not found"})
		return
	}

	c.JSON(http.StatusOK, sar)
}

// ListSARs lists all SARs with filters
func (h *AMLHandler) ListSARs(c *gin.Context) {
	status := c.DefaultQuery("status", "")
	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	if limit > 100 {
		limit = 100
	}

	sars, total, err := h.repo.ListSARs(status, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve SARs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total":  total,
		"limit":  limit,
		"offset": offset,
		"sars":   sars,
	})
}

// FileSAR files a SAR with regulatory authorities
func (h *AMLHandler) FileSAR(c *gin.Context) {
	sarID := c.Param("sar_id")
	if sarID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SAR ID required"})
		return
	}

	var req models.SARFilingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get SAR from database
	sar, err := h.repo.GetSAR(sarID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "SAR not found"})
		return
	}

	if sar.Status == "filed" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SAR already filed"})
		return
	}

	// File with regulatory authority (CBN/EFCC). Only a successful regulator
	// response may mark the SAR "filed"; failures keep it in filing_failed
	// and raise an alert so compliance can retry.
	filingResult := h.fileWithRegulator(sar, req.RegulatoryAuthority)
	newStatus := sarFilingOutcome(filingResult.Success)

	if !filingResult.Success {
		log.Printf("ALERT: SAR %s filing with %s FAILED: %s", sarID, req.RegulatoryAuthority, filingResult.Error)
		if err := h.repo.UpdateSARFiling(sarID, newStatus, "", false); err != nil {
			log.Printf("Failed to record SAR filing failure for %s: %v", sarID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update SAR status"})
			return
		}
		c.JSON(http.StatusBadGateway, gin.H{
			"sar_id":     sarID,
			"status":     newStatus,
			"filed_with": req.RegulatoryAuthority,
			"error":      filingResult.Error,
		})
		return
	}

	// STR deadline tracking: filing is measured against the 72h NFIU window
	// from detection (SAR creation); breaches raise the alert metric.
	filedWithinSLA := recordSTRSLAOutcome(sar.CreatedAt, time.Now())
	if !filedWithinSLA {
		log.Printf("ALERT: SAR %s filed AFTER the %s STR deadline (detected %s)", sarID, strSLA(), sar.CreatedAt.Format(time.RFC3339))
	}

	if err := h.repo.UpdateSARFiling(sarID, newStatus, filingResult.ReferenceNumber, filedWithinSLA); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update SAR status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sar_id":           sarID,
		"status":           newStatus,
		"filed_with":       req.RegulatoryAuthority,
		"reference_number": filingResult.ReferenceNumber,
		"filed_within_sla": filedWithinSLA,
		"filed_at":         time.Now().Unix(),
	})
}

// ComplianceMetrics exposes STR SLA breach metrics for compliance monitoring.
func (h *AMLHandler) ComplianceMetrics(c *gin.Context) {
	sla := strSLA()
	overdue, err := h.repo.CountOverdueUnfiledSARs(sla)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to compute compliance metrics"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"str_sla_hours":                    int(sla.Hours()),
		"str_sla_late_filings_this_process": STRSLABreaches(),
		"str_overdue_unfiled":              overdue,
		"ctr_threshold_ngn":                ctrThresholdNGN(),
		"evaluated_at":                     time.Now().Unix(),
	})
}

// CheckSanctions checks if entity is on sanctions lists
func (h *AMLHandler) CheckSanctions(c *gin.Context) {
	var req models.SanctionsCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.EntityName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Entity name required"})
		return
	}

	// Check cache first
	if result, found := h.repo.GetCachedSanctionsCheck(req.EntityName); found {
		c.JSON(http.StatusOK, gin.H{
			"entity_name":   req.EntityName,
			"is_sanctioned": result.IsSanctioned,
			"matches":       result.Matches,
			"source":        "cache",
		})
		return
	}

	// Primary screening: the local watchlist (UN SC Consolidated List, OFAC
	// SDN, Nigerian domestic list sample). Matches carry real list names.
	localMatches := h.watchlist.Match(req.EntityName)
	matches := make([]*models.SanctionsMatch, 0, len(localMatches))
	for _, m := range localMatches {
		matches = append(matches, &models.SanctionsMatch{
			ListName:   m.ListName,
			EntityName: m.EntryName,
			Details:    fmt.Sprintf("%s match on %s (ref %s)", m.MatchType, m.EntryName, m.Reference),
			MatchScore: m.MatchScore * 100,
		})
	}

	// Augmentation: the ML service adds fuzzy/semantic signals on top of the
	// list-based screening. An ML outage never suppresses a real list hit.
	mlAugmentation := "unavailable"
	mlConfidence := 0.0
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	resp, err := h.ml.CheckSanctions(ctx, &mlclient.SanctionsRequest{
		EntityName: req.EntityName,
		EntityType: req.EntityType,
	})
	cancel()
	if err != nil {
		log.Printf("ML sanctions augmentation unavailable for %s (local list result stands): %v", req.EntityName, err)
	} else {
		mlAugmentation = "applied"
		mlConfidence = resp.Confidence
		for _, match := range resp.Matches {
			matches = append(matches, &models.SanctionsMatch{
				ListName:   "aml_ml_service_augmentation",
				EntityName: req.EntityName,
				Details:    match,
				MatchScore: resp.Confidence,
			})
		}
	}

	isSanctioned := len(localMatches) > 0 || (err == nil && resp.IsSanctioned)

	// Cache result
	h.repo.CacheSanctionsCheck(req.EntityName, isSanctioned, matches)

	// Store in database
	sanctionsCheck := &models.SanctionsCheck{
		EntityName:   req.EntityName,
		EntityType:   req.EntityType,
		IsSanctioned: isSanctioned,
		MatchCount:   len(matches),
		Confidence:   int(mlConfidence),
		CheckedAt:    time.Now(),
	}
	h.repo.StoreSanctionsCheck(sanctionsCheck)

	c.JSON(http.StatusOK, gin.H{
		"entity_name":      req.EntityName,
		"is_sanctioned":    isSanctioned,
		"matches":          matches,
		"confidence":       mlConfidence,
		"screening_source": "local_watchlist",
		"ml_augmentation":  mlAugmentation,
		"checked_at":       time.Now().Unix(),
	})
}

// GetEntitySanctionsStatus retrieves sanctions status for an entity
func (h *AMLHandler) GetEntitySanctionsStatus(c *gin.Context) {
	entityID := c.Param("entity_id")
	if entityID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Entity ID required"})
		return
	}

	checks, err := h.repo.GetEntitySanctionsHistory(entityID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve sanctions history"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"entity_id":    entityID,
		"checks_count": len(checks),
		"checks":       checks,
	})
}

// VerifySourceOfFunds verifies source of funds
func (h *AMLHandler) VerifySourceOfFunds(c *gin.Context) {
	var req models.SourceOfFundsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := req.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Call the ML inference service over HTTP
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	mlReq := &mlclient.SourceOfFundsRequest{
		UserID:              req.UserID,
		Amount:              req.Amount,
		DeclaredSource:      req.DeclaredSource,
		SupportingDocuments: req.SupportingDocuments,
	}

	resp, err := h.ml.VerifySourceOfFunds(ctx, mlReq)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Source of funds verification unavailable", "details": err.Error()})
		return
	}

	// Store verification result
	verification := &models.SourceOfFundsVerification{
		UserID:             req.UserID,
		Amount:             req.Amount,
		DeclaredSource:     req.DeclaredSource,
		Verified:           resp.Verified,
		ConfidenceScore:    int(resp.ConfidenceScore),
		VerificationMethod: resp.VerificationMethod,
		Discrepancies:      resp.Discrepancies,
		VerifiedAt:         time.Now(),
	}
	h.repo.StoreSourceOfFundsVerification(verification)

	c.JSON(http.StatusOK, gin.H{
		"user_id":             req.UserID,
		"verified":            resp.Verified,
		"confidence_score":    resp.ConfidenceScore,
		"verification_method": resp.VerificationMethod,
		"discrepancies":       resp.Discrepancies,
		"recommendation":      resp.Recommendation,
		"verified_at":         time.Now().Unix(),
	})
}

// GetDailyReport generates daily AML report
func (h *AMLHandler) GetDailyReport(c *gin.Context) {
	dateStr := c.DefaultQuery("date", time.Now().Format("2006-01-02"))
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format"})
		return
	}

	report, err := h.repo.GetDailyReport(date)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate report"})
		return
	}

	c.JSON(http.StatusOK, report)
}

// GetFlaggedTransactions retrieves flagged transactions
func (h *AMLHandler) GetFlaggedTransactions(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")
	riskLevel := c.DefaultQuery("risk_level", "")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	if limit > 100 {
		limit = 100
	}

	transactions, total, err := h.repo.GetFlaggedTransactions(riskLevel, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve flagged transactions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total":        total,
		"limit":        limit,
		"offset":       offset,
		"transactions": transactions,
	})
}

// Helper methods

func (h *AMLHandler) fileWithRegulator(sar *models.SAR, authority string) *models.FilingResult {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var endpoint, apiKey string
	switch authority {
	case "CBN":
		endpoint, apiKey = os.Getenv("CBN_NFIU_ENDPOINT"), os.Getenv("CBN_API_KEY")
	case "EFCC":
		endpoint, apiKey = os.Getenv("EFCC_ENDPOINT"), os.Getenv("EFCC_API_KEY")
	default:
		return &models.FilingResult{Success: false, FiledAt: time.Now(), Error: "unsupported regulatory authority"}
	}
	if !strings.HasPrefix(endpoint, "https://") || strings.TrimSpace(apiKey) == "" {
		return &models.FilingResult{Success: false, FiledAt: time.Now(), Error: "regulatory HTTPS endpoint and API key must be configured"}
	}

	payload := map[string]interface{}{
		"sar_id": sar.SARID, "user_id": sar.UserID, "filing_institution": sar.FilingInstitution,
		"activity_type": sar.ActivityType, "narrative": sar.Narrative, "transaction_ids": sar.TransactionIDs,
		"filing_date": time.Now().UTC().Format(time.RFC3339), "regulatory_authority": authority,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return &models.FilingResult{Success: false, FiledAt: time.Now(), Error: "encode regulatory filing payload"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return &models.FilingResult{Success: false, FiledAt: time.Now(), Error: "create regulatory filing request"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Institution-ID", sar.FilingInstitution)
	req.Header.Set("X-Request-ID", sar.SARID+"-"+strconv.FormatInt(time.Now().UnixNano(), 10))

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return &models.FilingResult{Success: false, FiledAt: time.Now(), Error: "regulatory filing request failed"}
	}
	defer resp.Body.Close()
	var result struct {
		ReferenceNumber string `json:"reference_number"`
		Message         string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return &models.FilingResult{Success: false, FiledAt: time.Now(), Error: "invalid regulatory filing response"}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return &models.FilingResult{Success: false, ReferenceNumber: result.ReferenceNumber, FiledAt: time.Now(), Error: result.Message}
	}
	if result.ReferenceNumber == "" {
		return &models.FilingResult{Success: false, FiledAt: time.Now(), Error: "regulatory filing response lacks reference number"}
	}
	return &models.FilingResult{Success: true, ReferenceNumber: result.ReferenceNumber, FiledAt: time.Now()}
}
