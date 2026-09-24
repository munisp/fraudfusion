// Package mlclient implements the AML Monitor's HTTP client for the Python
// ML inference service. It replaces the previous gRPC integration, which
// referenced generated protobuf code that never existed.
//
// Base URL comes from AML_ML_SERVICE_URL (default http://localhost:8100);
// transaction scoring uses POST /v1/aml/score. Every call has a bounded
// timeout and one retry; errors are returned so callers can fail closed to
// manual review.
package mlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is an HTTP client for the AML ML inference service.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient validates the base URL.
func NewClient(baseURL string) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = "http://localhost:8100"
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid AML_ML_SERVICE_URL: %w", err)
	}
	return &Client{baseURL: baseURL, httpClient: &http.Client{Timeout: 10 * time.Second}}, nil
}

// BaseURL returns the configured base URL (used by health checks).
func (c *Client) BaseURL() string { return c.baseURL }

// --- Request/response contracts (mirror the retired aml_service.proto) ---

type TransactionRequest struct {
	TransactionID   string  `json:"transaction_id"`
	UserID          string  `json:"user_id"`
	Amount          float64 `json:"amount"`
	Currency        string  `json:"currency"`
	TransactionType string  `json:"transaction_type"`
	CountryCode     string  `json:"country_code"`
	Timestamp       int64   `json:"timestamp"`
}

type TransactionResponse struct {
	TransactionID  string             `json:"transaction_id"`
	RiskScore      float64            `json:"risk_score"`
	RiskLevel      string             `json:"risk_level"`
	RiskFactors    []string           `json:"risk_factors"`
	Flagged        bool               `json:"flagged"`
	SarRequired    bool               `json:"sar_required"`
	Recommendation string             `json:"recommendation"`
	DetailedScores map[string]float64 `json:"detailed_scores"`
}

type PatternRequest struct {
	UserID       string `json:"user_id"`
	DaysLookback int32  `json:"days_lookback"`
}

type Pattern struct {
	PatternType    string   `json:"pattern_type"`
	Description    string   `json:"description"`
	Confidence     float64  `json:"confidence"`
	TransactionIDs []string `json:"transaction_ids"`
	TotalAmount    float64  `json:"total_amount"`
}

type PatternResponse struct {
	UserID           string    `json:"user_id"`
	Patterns         []Pattern `json:"patterns"`
	OverallRiskScore float64   `json:"overall_risk_score"`
	Suspicious       bool      `json:"suspicious"`
}

type SARRequest struct {
	UserID                 string   `json:"user_id"`
	TransactionIDs         []string `json:"transaction_ids"`
	SuspiciousActivityType string   `json:"suspicious_activity_type"`
	Narrative              string   `json:"narrative"`
}

type SARResponse struct {
	SarID                  string   `json:"sar_id"`
	UserID                 string   `json:"user_id"`
	FilingInstitution      string   `json:"filing_institution"`
	SuspiciousActivityType string   `json:"suspicious_activity_type"`
	Narrative              string   `json:"narrative"`
	FilingDate             int64    `json:"filing_date"`
	Status                 string   `json:"status"`
	Transactions           []string `json:"transactions"`
}

type SanctionsRequest struct {
	EntityName string `json:"entity_name"`
	EntityType string `json:"entity_type"`
}

type SanctionsResponse struct {
	IsSanctioned bool     `json:"is_sanctioned"`
	Matches      []string `json:"matches"`
	Confidence   float64  `json:"confidence"`
}

type SourceOfFundsRequest struct {
	UserID              string   `json:"user_id"`
	Amount              float64  `json:"amount"`
	DeclaredSource      string   `json:"declared_source"`
	SupportingDocuments []string `json:"supporting_documents"`
}

type SourceOfFundsResponse struct {
	Verified           bool     `json:"verified"`
	ConfidenceScore    float64  `json:"confidence_score"`
	VerificationMethod string   `json:"verification_method"`
	Discrepancies      []string `json:"discrepancies"`
	Recommendation     string   `json:"recommendation"`
}

// post issues a JSON POST with one retry and decodes the response into out.
func (c *Client) post(ctx context.Context, path string, payload, out interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode ML request: %w", err)
	}
	endpoint := c.baseURL + path

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create ML request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("call ML service %s: %w", path, err)
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("read ML response: %w", err)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			// 5xx is retryable; 4xx is a client error returned immediately.
			lastErr = fmt.Errorf("ML service %s returned status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(raw)))
			if resp.StatusCode < 500 {
				return lastErr
			}
			continue
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode ML response: %w", err)
		}
		return nil
	}
	return lastErr
}

// AnalyzeTransaction scores a single transaction via POST /v1/aml/score.
func (c *Client) AnalyzeTransaction(ctx context.Context, req *TransactionRequest) (*TransactionResponse, error) {
	out := &TransactionResponse{}
	if err := c.post(ctx, "/v1/aml/score", req, out); err != nil {
		return nil, err
	}
	return out, nil
}

// DetectSuspiciousPattern via POST /v1/aml/patterns.
func (c *Client) DetectSuspiciousPattern(ctx context.Context, req *PatternRequest) (*PatternResponse, error) {
	out := &PatternResponse{}
	if err := c.post(ctx, "/v1/aml/patterns", req, out); err != nil {
		return nil, err
	}
	return out, nil
}

// GenerateSAR via POST /v1/aml/sar.
func (c *Client) GenerateSAR(ctx context.Context, req *SARRequest) (*SARResponse, error) {
	out := &SARResponse{}
	if err := c.post(ctx, "/v1/aml/sar", req, out); err != nil {
		return nil, err
	}
	return out, nil
}

// CheckSanctions via POST /v1/aml/sanctions.
func (c *Client) CheckSanctions(ctx context.Context, req *SanctionsRequest) (*SanctionsResponse, error) {
	out := &SanctionsResponse{}
	if err := c.post(ctx, "/v1/aml/sanctions", req, out); err != nil {
		return nil, err
	}
	return out, nil
}

// VerifySourceOfFunds via POST /v1/aml/source-of-funds.
func (c *Client) VerifySourceOfFunds(ctx context.Context, req *SourceOfFundsRequest) (*SourceOfFundsResponse, error) {
	out := &SourceOfFundsResponse{}
	if err := c.post(ctx, "/v1/aml/source-of-funds", req, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Health probes the ML service root/liveness endpoint.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ML service health: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("ML service unhealthy: status %d", resp.StatusCode)
	}
	return nil
}
