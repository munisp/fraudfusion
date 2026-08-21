package models

import (
	"errors"
	"time"
)

// TransactionAnalysisRequest represents a request to analyze a transaction
type TransactionAnalysisRequest struct {
	TransactionID   string  `json:"transaction_id" binding:"required"`
	UserID          string  `json:"user_id" binding:"required"`
	Amount          float64 `json:"amount" binding:"required"`
	Currency        string  `json:"currency" binding:"required"`
	TransactionType string  `json:"transaction_type" binding:"required"`
	CountryCode     string  `json:"country_code"`
	Description     string  `json:"description"`
}

func (r *TransactionAnalysisRequest) Validate() error {
	if r.Amount <= 0 {
		return errors.New("amount must be greater than 0")
	}
	if r.Currency == "" {
		r.Currency = "NGN"
	}
	if r.CountryCode == "" {
		r.CountryCode = "NG"
	}
	return nil
}

// BatchTransactionRequest represents a batch of transactions to analyze
type BatchTransactionRequest struct {
	Transactions []TransactionAnalysisRequest `json:"transactions" binding:"required"`
}

// TransactionAnalysis represents the result of transaction analysis
type TransactionAnalysis struct {
	ID             int64     `json:"id"`
	TransactionID  string    `json:"transaction_id"`
	UserID         string    `json:"user_id"`
	RiskScore      int       `json:"risk_score"`
	RiskLevel      string    `json:"risk_level"`
	Flagged        bool      `json:"flagged"`
	SARRequired    bool      `json:"sar_required"`
	RiskFactors    []string  `json:"risk_factors"`
	Recommendation string    `json:"recommendation"`
	CreatedAt      time.Time `json:"created_at"`
}

// PatternDetectionRequest represents a request to detect suspicious patterns
type PatternDetectionRequest struct {
	UserID       string `json:"user_id" binding:"required"`
	DaysLookback int    `json:"days_lookback"`
}

// SuspiciousPattern represents a detected suspicious pattern
type SuspiciousPattern struct {
	ID             int64     `json:"id"`
	UserID         string    `json:"user_id"`
	PatternType    string    `json:"pattern_type"`
	Description    string    `json:"description"`
	Confidence     int       `json:"confidence"`
	TransactionIDs []string  `json:"transaction_ids"`
	TotalAmount    float64   `json:"total_amount"`
	DetectedAt     time.Time `json:"detected_at"`
}

// SARGenerationRequest represents a request to generate a SAR
type SARGenerationRequest struct {
	UserID         string   `json:"user_id" binding:"required"`
	TransactionIDs []string `json:"transaction_ids" binding:"required"`
	ActivityType   string   `json:"activity_type" binding:"required"`
	Narrative      string   `json:"narrative" binding:"required"`
}

func (r *SARGenerationRequest) Validate() error {
	if len(r.TransactionIDs) == 0 {
		return errors.New("at least one transaction ID required")
	}
	if len(r.Narrative) < 50 {
		return errors.New("narrative must be at least 50 characters")
	}
	return nil
}

// SAR represents a Suspicious Activity Report
type SAR struct {
	ID                 int64     `json:"id"`
	SARID              string    `json:"sar_id"`
	UserID             string    `json:"user_id"`
	FilingInstitution  string    `json:"filing_institution"`
	ActivityType       string    `json:"activity_type"`
	Narrative          string    `json:"narrative"`
	TransactionIDs     []string  `json:"transaction_ids"`
	FilingDate         time.Time `json:"filing_date"`
	Status             string    `json:"status"`
	ReferenceNumber    string    `json:"reference_number"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// SARFilingRequest represents a request to file a SAR
type SARFilingRequest struct {
	RegulatoryAuthority string `json:"regulatory_authority" binding:"required"`
	Notes               string `json:"notes"`
}

// FilingResult represents the result of filing a SAR
type FilingResult struct {
	Success         bool      `json:"success"`
	ReferenceNumber string    `json:"reference_number"`
	FiledAt         time.Time `json:"filed_at"`
	Error           string    `json:"error,omitempty"`
}

// SanctionsCheckRequest represents a request to check sanctions
type SanctionsCheckRequest struct {
	EntityName string `json:"entity_name" binding:"required"`
	EntityType string `json:"entity_type"`
}

// SanctionsCheck represents a sanctions check result
type SanctionsCheck struct {
	ID           int64     `json:"id"`
	EntityName   string    `json:"entity_name"`
	EntityType   string    `json:"entity_type"`
	IsSanctioned bool      `json:"is_sanctioned"`
	MatchCount   int       `json:"match_count"`
	Confidence   int       `json:"confidence"`
	CheckedAt    time.Time `json:"checked_at"`
}

// SanctionsMatch represents a match on a sanctions list
type SanctionsMatch struct {
	ListName   string  `json:"list_name"`
	MatchScore float64 `json:"match_score"`
	EntityName string  `json:"entity_name"`
	Details    string  `json:"details"`
}

// CachedSanctionsResult represents cached sanctions check result
type CachedSanctionsResult struct {
	IsSanctioned bool              `json:"is_sanctioned"`
	Matches      []*SanctionsMatch `json:"matches"`
}

// SourceOfFundsRequest represents a request to verify source of funds
type SourceOfFundsRequest struct {
	UserID              string   `json:"user_id" binding:"required"`
	Amount              float64  `json:"amount" binding:"required"`
	DeclaredSource      string   `json:"declared_source" binding:"required"`
	SupportingDocuments []string `json:"supporting_documents"`
}

func (r *SourceOfFundsRequest) Validate() error {
	if r.Amount <= 0 {
		return errors.New("amount must be greater than 0")
	}
	return nil
}

// SourceOfFundsVerification represents source of funds verification result
type SourceOfFundsVerification struct {
	ID                 int64     `json:"id"`
	UserID             string    `json:"user_id"`
	Amount             float64   `json:"amount"`
	DeclaredSource     string    `json:"declared_source"`
	Verified           bool      `json:"verified"`
	ConfidenceScore    int       `json:"confidence_score"`
	VerificationMethod string    `json:"verification_method"`
	Discrepancies      []string  `json:"discrepancies"`
	VerifiedAt         time.Time `json:"verified_at"`
}

// DailyReport represents a daily AML report
type DailyReport struct {
	Date                    time.Time `json:"date"`
	TotalTransactions       int       `json:"total_transactions"`
	FlaggedTransactions     int       `json:"flagged_transactions"`
	HighRiskTransactions    int       `json:"high_risk_transactions"`
	SARsGenerated           int       `json:"sars_generated"`
	SARsFiled               int       `json:"sars_filed"`
	PatternsDetected        int       `json:"patterns_detected"`
	SanctionsChecks         int       `json:"sanctions_checks"`
	SanctionsMatches        int       `json:"sanctions_matches"`
	TotalAmountFlagged      float64   `json:"total_amount_flagged"`
	AverageRiskScore        float64   `json:"average_risk_score"`
}

// RiskScoreDistribution represents distribution of risk scores
type RiskScoreDistribution struct {
	Low      int `json:"low"`
	Medium   int `json:"medium"`
	High     int `json:"high"`
	Critical int `json:"critical"`
}
