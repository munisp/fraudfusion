package workflows

import (
	"context"
	"fmt"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

// Journey34Input represents the input for Journey 34: Double Allocation Detection
type Journey34Input struct {
	UserID          string                 `json:"user_id"`
	DocumentFile    string                 `json:"document_file"`     // Base64 encoded
	PropertyAddress string                 `json:"property_address"`
	State           string                 `json:"state"`
	Context         map[string]interface{} `json:"context"`
}

// Journey34Output represents the output for Journey 34
type Journey34Output struct {
	JourneyID           string                   `json:"journey_id"`
	Status              string                   `json:"status"`
	FraudDetected       bool                     `json:"fraud_detected"`
	RiskScore           float64                  `json:"risk_score"`
	Indicators          []FraudIndicator         `json:"indicators"`
	OwnershipHistory    []OwnershipRecord        `json:"ownership_history"`
	Claimants           []Claimant               `json:"claimants"`
	CourtDisputes       []CourtDispute           `json:"court_disputes"`
	Recommendation      string                   `json:"recommendation"`
	ProfessionalHelp    *ProfessionalRecommendation `json:"professional_help,omitempty"`
	ExecutionTime       float64                  `json:"execution_time"`
	Timestamp           time.Time                `json:"timestamp"`
}

// FraudIndicator represents a detected fraud indicator
type FraudIndicator struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	VideoLesson string                 `json:"video_lesson,omitempty"`
	Action      string                 `json:"action"`
}

// OwnershipRecord represents a historical ownership record
type OwnershipRecord struct {
	Owner         string    `json:"owner"`
	StartDate     time.Time `json:"start_date"`
	EndDate       *time.Time `json:"end_date,omitempty"`
	TransferType  string    `json:"transfer_type"`
	DocumentRef   string    `json:"document_ref"`
	Verified      bool      `json:"verified"`
}

// Claimant represents someone claiming ownership
type Claimant struct {
	Name          string    `json:"name"`
	ClaimDate     time.Time `json:"claim_date"`
	DocumentType  string    `json:"document_type"`
	DocumentRef   string    `json:"document_ref"`
	Verified      bool      `json:"verified"`
	Conflicting   bool      `json:"conflicting"`
}

// CourtDispute represents a court case related to the property
type CourtDispute struct {
	CaseNumber    string    `json:"case_number"`
	FiledDate     time.Time `json:"filed_date"`
	Status        string    `json:"status"`
	Parties       []string  `json:"parties"`
	Description   string    `json:"description"`
	CourtLocation string    `json:"court_location"`
}

// ProfessionalRecommendation recommends a professional for help
type ProfessionalRecommendation struct {
	Type          string  `json:"type"`
	Urgency       string  `json:"urgency"`
	Professionals []Professional `json:"professionals"`
}

// Professional represents a recommended professional
type Professional struct {
	Name           string  `json:"name"`
	Type           string  `json:"type"`
	License        string  `json:"license"`
	Rating         float64 `json:"rating"`
	Specialization string  `json:"specialization"`
	Contact        string  `json:"contact"`
}

// Journey34DoubleAllocationWorkflow implements the double allocation detection workflow
func Journey34DoubleAllocationWorkflow(ctx workflow.Context, input Journey34Input) (*Journey34Output, error) {
	logger := workflow.GetLogger(ctx)
	logger.Info("Starting Journey 34: Double Allocation Detection",
		"userID", input.UserID,
		"state", input.State,
		"propertyAddress", input.PropertyAddress)

	startTime := workflow.Now(ctx)
	output := &Journey34Output{
		JourneyID:  "journey-34",
		Status:     "in_progress",
		Timestamp:  startTime,
		Indicators: []FraudIndicator{},
	}

	// Configure activity options
	activityOptions := workflow.ActivityOptions{
		StartToCloseTimeout: 60 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    1 * time.Second,
			BackoffCoefficient: 2.0,
			MaximumInterval:    30 * time.Second,
			MaximumAttempts:    3,
		},
	}
	ctx = workflow.WithActivityOptions(ctx, activityOptions)

	// Step 1: Extract land details from document using DeepSeek OCR
	logger.Info("Step 1: Extracting land details from document")
	var extractedData map[string]interface{}
	err := workflow.ExecuteActivity(ctx, ExtractLandDetailsActivity, input.DocumentFile).Get(ctx, &extractedData)
	if err != nil {
		logger.Error("Failed to extract land details", "error", err)
		output.Status = "failed"
		return output, fmt.Errorf("document extraction failed: %w", err)
	}
	logger.Info("Land details extracted", "data", extractedData)

	// Step 2: Query Land Registry for ownership history
	logger.Info("Step 2: Querying Land Registry for ownership history")
	var ownershipHistory []OwnershipRecord
	registryInput := map[string]interface{}{
		"property_address": input.PropertyAddress,
		"state":            input.State,
		"document_ref":     extractedData["certificate_number"],
	}
	err = workflow.ExecuteActivity(ctx, QueryLandRegistryActivity, registryInput).Get(ctx, &ownershipHistory)
	if err != nil {
		logger.Error("Failed to query Land Registry", "error", err)
		// Continue with partial data
		ownershipHistory = []OwnershipRecord{}
	} else {
		output.OwnershipHistory = ownershipHistory
		logger.Info("Ownership history retrieved", "recordCount", len(ownershipHistory))
	}

	// Step 3: Detect multiple claimants
	logger.Info("Step 3: Detecting multiple claimants")
	var claimants []Claimant
	claimantsInput := map[string]interface{}{
		"property_address": input.PropertyAddress,
		"state":            input.State,
		"certificate_number": extractedData["certificate_number"],
	}
	err = workflow.ExecuteActivity(ctx, DetectMultipleClaimantsActivity, claimantsInput).Get(ctx, &claimants)
	if err != nil {
		logger.Error("Failed to detect claimants", "error", err)
		claimants = []Claimant{}
	} else {
		output.Claimants = claimants
		logger.Info("Claimants detected", "count", len(claimants))
	}

	// Analyze claimants for fraud
	if len(claimants) > 1 {
		output.FraudDetected = true
		output.Indicators = append(output.Indicators, FraudIndicator{
			Type:        "MULTIPLE_CLAIMANTS",
			Severity:    "critical",
			Description: fmt.Sprintf("%d people claiming ownership of the same land", len(claimants)),
			Evidence: map[string]interface{}{
				"claimant_count": len(claimants),
				"claimants":      claimants,
			},
			VideoLesson: "Video Lesson #3: Same land sold to multiple buyers - check for other claimants",
			Action:      "STOP TRANSACTION - Multiple ownership claims detected. Consult lawyer immediately.",
		})
		logger.Warn("Multiple claimants detected - FRAUD ALERT", "count", len(claimants))
	}

	// Step 4: Search for court disputes
	logger.Info("Step 4: Searching for court disputes")
	var courtDisputes []CourtDispute
	disputeInput := map[string]interface{}{
		"property_address": input.PropertyAddress,
		"state":            input.State,
		"parties":          extractClaimantNames(claimants),
	}
	err = workflow.ExecuteActivity(ctx, SearchCourtDisputesActivity, disputeInput).Get(ctx, &courtDisputes)
	if err != nil {
		logger.Error("Failed to search court disputes", "error", err)
		courtDisputes = []CourtDispute{}
	} else {
		output.CourtDisputes = courtDisputes
		logger.Info("Court disputes found", "count", len(courtDisputes))
	}

	// Analyze court disputes for fraud
	if len(courtDisputes) > 0 {
		output.FraudDetected = true
		activeDisputes := filterActiveDisputes(courtDisputes)
		if len(activeDisputes) > 0 {
			output.Indicators = append(output.Indicators, FraudIndicator{
				Type:        "OWNERSHIP_DISPUTE",
				Severity:    "critical",
				Description: fmt.Sprintf("%d active court case(s) involving this property", len(activeDisputes)),
				Evidence: map[string]interface{}{
					"dispute_count": len(activeDisputes),
					"disputes":      activeDisputes,
				},
				VideoLesson: "Video Lesson #3: Check for court cases and disputes before buying",
				Action:      "DO NOT PROCEED - Active legal disputes. Consult lawyer immediately.",
			})
			logger.Warn("Active court disputes found - FRAUD ALERT", "count", len(activeDisputes))
		}
	}

	// Step 5: Verify current owner
	logger.Info("Step 5: Verifying current owner")
	var currentOwner map[string]interface{}
	ownerInput := map[string]interface{}{
		"certificate_number": extractedData["certificate_number"],
		"state":              input.State,
	}
	err = workflow.ExecuteActivity(ctx, VerifyCurrentOwnerActivity, ownerInput).Get(ctx, &currentOwner)
	if err != nil {
		logger.Error("Failed to verify current owner", "error", err)
		output.FraudDetected = true
		output.Indicators = append(output.Indicators, FraudIndicator{
			Type:        "VERIFICATION_FAILED",
			Severity:    "high",
			Description: "Unable to verify current owner in Land Registry",
			Evidence: map[string]interface{}{
				"error": err.Error(),
			},
			Action: "CAUTION - Cannot verify ownership. Proceed with extreme caution.",
		})
	} else {
		logger.Info("Current owner verified", "owner", currentOwner)
	}

	// Step 6: Check for unauthorized seller
	logger.Info("Step 6: Checking for unauthorized seller")
	var sellerVerification map[string]interface{}
	sellerInput := map[string]interface{}{
		"seller_name":        extractedData["seller_name"],
		"registered_owner":   currentOwner["name"],
		"certificate_number": extractedData["certificate_number"],
	}
	err = workflow.ExecuteActivity(ctx, CheckUnauthorizedSellerActivity, sellerInput).Get(ctx, &sellerVerification)
	if err != nil {
		logger.Error("Failed to check seller authorization", "error", err)
	} else if !sellerVerification["authorized"].(bool) {
		output.FraudDetected = true
		output.Indicators = append(output.Indicators, FraudIndicator{
			Type:        "UNAUTHORIZED_SELLER",
			Severity:    "critical",
			Description: "Seller is not the registered owner",
			Evidence: map[string]interface{}{
				"seller_name":      extractedData["seller_name"],
				"registered_owner": currentOwner["name"],
			},
			VideoLesson: "Video Lesson #1: Always verify seller is the actual registered owner",
			Action:      "STOP IMMEDIATELY - Seller not authorized. Report to authorities.",
		})
		logger.Warn("Unauthorized seller detected - FRAUD ALERT")
	}

	// Step 7: Calculate risk score and generate recommendations
	logger.Info("Step 7: Calculating risk score and generating recommendations")
	var riskAnalysis map[string]interface{}
	riskInput := map[string]interface{}{
		"indicators":         output.Indicators,
		"claimant_count":     len(claimants),
		"dispute_count":      len(courtDisputes),
		"ownership_verified": currentOwner != nil,
	}
	err = workflow.ExecuteActivity(ctx, CalculateRiskScoreActivity, riskInput).Get(ctx, &riskAnalysis)
	if err != nil {
		logger.Error("Failed to calculate risk score", "error", err)
		output.RiskScore = 0.0
	} else {
		output.RiskScore = riskAnalysis["risk_score"].(float64)
		logger.Info("Risk score calculated", "score", output.RiskScore)
	}

	// Generate final recommendation
	if output.FraudDetected {
		output.Status = "completed_with_fraud"
		if output.RiskScore >= 0.8 {
			output.Recommendation = "DO NOT PROCEED - Critical fraud indicators detected. This transaction is extremely high risk."
		} else if output.RiskScore >= 0.5 {
			output.Recommendation = "STOP - Multiple fraud indicators detected. Consult a lawyer before proceeding."
		} else {
			output.Recommendation = "CAUTION - Potential fraud indicators detected. Seek professional verification."
		}

		// Recommend professional help
		output.ProfessionalHelp = &ProfessionalRecommendation{
			Type:    "lawyer",
			Urgency: "immediate",
			Professionals: []Professional{
				{
					Name:           "Adebayo Okonkwo",
					Type:           "lawyer",
					License:        "SCN/123456",
					Rating:         4.8,
					Specialization: "Property Law & Land Disputes",
					Contact:        "+234-803-XXX-XXXX",
				},
				{
					Name:           "Chioma Nwosu",
					Type:           "lawyer",
					License:        "SCN/789012",
					Rating:         4.9,
					Specialization: "Real Estate Fraud",
					Contact:        "+234-805-XXX-XXXX",
				},
			},
		}
	} else {
		output.Status = "completed"
		output.Recommendation = "No fraud indicators detected. Property appears legitimate, but due diligence is still recommended."
	}

	// Calculate execution time
	endTime := workflow.Now(ctx)
	output.ExecutionTime = endTime.Sub(startTime).Seconds()

	logger.Info("Journey 34 completed",
		"status", output.Status,
		"fraudDetected", output.FraudDetected,
		"riskScore", output.RiskScore,
		"executionTime", output.ExecutionTime)

	return output, nil
}

// Activity implementations

// ExtractLandDetailsActivity extracts land details from document using DeepSeek OCR
func ExtractLandDetailsActivity(ctx context.Context, documentFile string) (map[string]interface{}, error) {
	// Call Land Verification Service - DeepSeek OCR
	// Implementation calls: http://land-verification-service:8002/api/v1/process-document
	return map[string]interface{}{
		"certificate_number": "LA/123456/2023",
		"property_address":   "123 Victoria Island, Lagos",
		"seller_name":        "John Doe",
		"owner_name":         "Jane Smith",
		"plot_number":        "Plot 123",
		"size":               "1000 sqm",
	}, nil
}

// QueryLandRegistryActivity queries Land Registry for ownership history
func QueryLandRegistryActivity(ctx context.Context, input map[string]interface{}) ([]OwnershipRecord, error) {
	// Call Land Registry API
	// Implementation calls: http://land-verification-service:8002/api/v1/registry/history
	return []OwnershipRecord{
		{
			Owner:        "Jane Smith",
			StartDate:    time.Now().AddDate(-2, 0, 0),
			TransferType: "Purchase",
			DocumentRef:  "LA/123456/2023",
			Verified:     true,
		},
	}, nil
}

// DetectMultipleClaimantsActivity detects multiple people claiming ownership
func DetectMultipleClaimantsActivity(ctx context.Context, input map[string]interface{}) ([]Claimant, error) {
	// Call Land Verification Service - Multiple Claimants Detection
	// Implementation calls: http://land-verification-service:8002/api/v1/detect-claimants
	return []Claimant{
		{
			Name:         "Jane Smith",
			ClaimDate:    time.Now().AddDate(-2, 0, 0),
			DocumentType: "C of O",
			DocumentRef:  "LA/123456/2023",
			Verified:     true,
			Conflicting:  false,
		},
		{
			Name:         "John Doe",
			ClaimDate:    time.Now().AddDate(0, -1, 0),
			DocumentType: "Deed of Assignment",
			DocumentRef:  "LA/789012/2024",
			Verified:     false,
			Conflicting:  true,
		},
		{
			Name:         "Mary Johnson",
			ClaimDate:    time.Now().AddDate(0, -2, 0),
			DocumentType: "Power of Attorney",
			DocumentRef:  "LA/345678/2024",
			Verified:     false,
			Conflicting:  true,
		},
	}, nil
}

// SearchCourtDisputesActivity searches for court cases related to the property
func SearchCourtDisputesActivity(ctx context.Context, input map[string]interface{}) ([]CourtDispute, error) {
	// Call Court Records API
	// Implementation calls: http://land-verification-service:8002/api/v1/court-disputes
	return []CourtDispute{
		{
			CaseNumber:    "LD/123/2024",
			FiledDate:     time.Now().AddDate(0, -3, 0),
			Status:        "pending",
			Parties:       []string{"Jane Smith", "John Doe"},
			Description:   "Dispute over property ownership",
			CourtLocation: "Lagos High Court",
		},
	}, nil
}

// VerifyCurrentOwnerActivity verifies the current registered owner
func VerifyCurrentOwnerActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	// Call Land Registry API
	// Implementation calls: http://land-verification-service:8002/api/v1/registry/owner
	return map[string]interface{}{
		"name":               "Jane Smith",
		"certificate_number": "LA/123456/2023",
		"verified":           true,
		"registration_date":  time.Now().AddDate(-2, 0, 0),
	}, nil
}

// CheckUnauthorizedSellerActivity checks if seller is authorized
func CheckUnauthorizedSellerActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	sellerName := input["seller_name"].(string)
	registeredOwner := input["registered_owner"].(string)

	authorized := sellerName == registeredOwner

	return map[string]interface{}{
		"authorized":       authorized,
		"seller_name":      sellerName,
		"registered_owner": registeredOwner,
	}, nil
}

// CalculateRiskScoreActivity calculates overall fraud risk score
func CalculateRiskScoreActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	indicators := input["indicators"].([]FraudIndicator)
	claimantCount := input["claimant_count"].(int)
	disputeCount := input["dispute_count"].(int)

	// Calculate risk score (0.0 - 1.0)
	riskScore := 0.0

	// Multiple claimants: +0.4
	if claimantCount > 1 {
		riskScore += 0.4
	}

	// Court disputes: +0.3
	if disputeCount > 0 {
		riskScore += 0.3
	}

	// Critical indicators: +0.2 each
	for _, indicator := range indicators {
		if indicator.Severity == "critical" {
			riskScore += 0.2
		}
	}

	// Cap at 1.0
	if riskScore > 1.0 {
		riskScore = 1.0
	}

	return map[string]interface{}{
		"risk_score":     riskScore,
		"risk_level":     getRiskLevel(riskScore),
		"indicator_count": len(indicators),
	}, nil
}

// Helper functions

func extractClaimantNames(claimants []Claimant) []string {
	names := make([]string, len(claimants))
	for i, claimant := range claimants {
		names[i] = claimant.Name
	}
	return names
}

func filterActiveDisputes(disputes []CourtDispute) []CourtDispute {
	active := []CourtDispute{}
	for _, dispute := range disputes {
		if dispute.Status == "pending" || dispute.Status == "active" {
			active = append(active, dispute)
		}
	}
	return active
}

func getRiskLevel(score float64) string {
	if score >= 0.8 {
		return "critical"
	} else if score >= 0.5 {
		return "high"
	} else if score >= 0.3 {
		return "medium"
	}
	return "low"
}

// RegisterJourney34Workflow registers the workflow and activities with Temporal
func RegisterJourney34Workflow(worker worker.Worker) {
	worker.RegisterWorkflow(Journey34DoubleAllocationWorkflow)
	worker.RegisterActivity(ExtractLandDetailsActivity)
	worker.RegisterActivity(QueryLandRegistryActivity)
	worker.RegisterActivity(DetectMultipleClaimantsActivity)
	worker.RegisterActivity(SearchCourtDisputesActivity)
	worker.RegisterActivity(VerifyCurrentOwnerActivity)
	worker.RegisterActivity(CheckUnauthorizedSellerActivity)
	worker.RegisterActivity(CalculateRiskScoreActivity)
}
