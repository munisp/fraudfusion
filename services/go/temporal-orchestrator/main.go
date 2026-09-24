package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"

	"github.com/munisp/fraudfusion/services/go/temporal-orchestrator/workflows"
)

// JourneyWorkflow orchestrates user journeys with Temporal
type JourneyWorkflow struct {
	JourneyID string
	UserID    string
	Steps     []JourneyStep
	Context   map[string]interface{}
}

// JourneyStep represents a single step in a journey
type JourneyStep struct {
	ID          string
	Name        string
	Service     string
	Method      string
	StepType    string
	Parameters  map[string]interface{}
	Required    bool
	Condition   string
	RetryPolicy *RetryPolicy
}

// RetryPolicy defines retry behavior
type RetryPolicy struct {
	MaxAttempts     int
	BackoffInterval time.Duration
}

// ExecuteJourneyWorkflow is the main Temporal workflow
func ExecuteJourneyWorkflow(ctx workflow.Context, journey JourneyWorkflow) (map[string]interface{}, error) {
	logger := workflow.GetLogger(ctx)
	logger.Info("Starting journey", "journeyID", journey.JourneyID, "userID", journey.UserID)

	results := make(map[string]interface{})
	journeyContext := journey.Context

	// Execute steps sequentially or in parallel based on StepType
	for _, step := range journey.Steps {
		logger.Info("Executing step", "stepID", step.ID, "name", step.Name)

		// Check condition if present
		if step.Condition != "" {
			shouldExecute := evaluateCondition(step.Condition, journeyContext)
			if !shouldExecute {
				logger.Info("Skipping step due to condition", "stepID", step.ID)
				continue
			}
		}

		// Execute based on step type
		var stepResult interface{}
		var err error

		switch step.StepType {
		case "SEQUENTIAL":
			stepResult, err = executeSequentialStep(ctx, step, journeyContext)
		case "PARALLEL":
			stepResult, err = executeParallelStep(ctx, step, journeyContext)
		case "CONDITIONAL":
			if step.Condition != "" && evaluateCondition(step.Condition, journeyContext) {
				stepResult, err = executeSequentialStep(ctx, step, journeyContext)
			}
		default:
			stepResult, err = executeSequentialStep(ctx, step, journeyContext)
		}

		if err != nil {
			if step.Required {
				logger.Error("Required step failed", "stepID", step.ID, "error", err)
				return nil, fmt.Errorf("required step %s failed: %w", step.ID, err)
			}
			logger.Warn("Optional step failed", "stepID", step.ID, "error", err)
			results[step.ID] = map[string]interface{}{"error": err.Error()}
		} else {
			results[step.ID] = stepResult
			// Update journey context with step results
			journeyContext[step.ID] = stepResult
		}
	}

	logger.Info("Journey completed", "journeyID", journey.JourneyID)
	return results, nil
}

// executeSequentialStep executes a single step
func executeSequentialStep(ctx workflow.Context, step JourneyStep, journeyContext map[string]interface{}) (interface{}, error) {
	// Resolve parameters with context variables
	resolvedParams := resolveParameters(step.Parameters, journeyContext)

	// Activity options with retry policy
	ao := workflow.ActivityOptions{
		StartToCloseTimeout: 5 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts:    3,
			InitialInterval:    1 * time.Second,
			BackoffCoefficient: 2.0,
		},
	}

	if step.RetryPolicy != nil {
		ao.RetryPolicy.MaximumAttempts = int32(step.RetryPolicy.MaxAttempts)
		ao.RetryPolicy.InitialInterval = step.RetryPolicy.BackoffInterval
	}

	ctx = workflow.WithActivityOptions(ctx, ao)

	// Execute activity
	var result interface{}
	err := workflow.ExecuteActivity(ctx, step.Service+"."+step.Method, resolvedParams).Get(ctx, &result)
	return result, err
}

// executeParallelStep executes step in parallel
func executeParallelStep(ctx workflow.Context, step JourneyStep, journeyContext map[string]interface{}) (interface{}, error) {
	// For parallel steps, we execute them asynchronously
	resolvedParams := resolveParameters(step.Parameters, journeyContext)

	ao := workflow.ActivityOptions{
		StartToCloseTimeout: 5 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 3,
			InitialInterval: 1 * time.Second,
		},
	}
	ctx = workflow.WithActivityOptions(ctx, ao)

	var result interface{}
	err := workflow.ExecuteActivity(ctx, step.Service+"."+step.Method, resolvedParams).Get(ctx, &result)
	return result, err
}

// resolveParameters replaces ${variable} references with actual values
func resolveParameters(params map[string]interface{}, context map[string]interface{}) map[string]interface{} {
	resolved := make(map[string]interface{})
	for key, value := range params {
		if strValue, ok := value.(string); ok {
			resolved[key] = resolveVariable(strValue, context)
		} else {
			resolved[key] = value
		}
	}
	return resolved
}

// resolveVariable resolves ${step_id.field} references
func resolveVariable(value string, context map[string]interface{}) interface{} {
	// Simple implementation - in production, use proper template engine
	if len(value) > 2 && value[0:2] == "${" && value[len(value)-1:] == "}" {
		varName := value[2 : len(value)-1]
		if val, ok := context[varName]; ok {
			return val
		}
	}
	return value
}

// evaluateCondition evaluates a simple condition
func evaluateCondition(condition string, context map[string]interface{}) bool {
	// Simple implementation - in production, use proper expression evaluator
	// For now, just return true
	return true
}

// Activities for each service

// LandVerificationActivities contains all land verification activities
type LandVerificationActivities struct{}

func (a *LandVerificationActivities) ProcessDocumentsDeepseek(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	// Call Python land verification service
	return callPythonService(ctx, "land_verification_service", "process_documents_deepseek", params)
}

func (a *LandVerificationActivities) VerifyLandRegistry(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "land_verification_service", "verify_land_registry", params)
}

func (a *LandVerificationActivities) VerifySurveyorGeneral(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "land_verification_service", "verify_surveyor_general", params)
}

func (a *LandVerificationActivities) DetectFraudIntegrated(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "land_verification_service", "detect_fraud_integrated", params)
}

func (a *LandVerificationActivities) RecommendProfessionals(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "land_verification_service", "recommend_professionals", params)
}

func (a *LandVerificationActivities) GenerateReport(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "land_verification_service", "generate_report", params)
}

// DocumentStorageActivities handles document operations
type DocumentStorageActivities struct{}

func (a *DocumentStorageActivities) UploadDocument(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "document_storage_service", "upload_document", params)
}

func (a *DocumentStorageActivities) UploadMultipleDocuments(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "document_storage_service", "upload_multiple_documents", params)
}

// IntegrationActivities handles external integrations
type IntegrationActivities struct{}

func (a *IntegrationActivities) VerifyCAC(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "integration_service", "verify_cac", params)
}

func (a *IntegrationActivities) VerifyBVN(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "integration_service", "verify_bvn", params)
}

func (a *IntegrationActivities) VerifyNIN(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "integration_service", "verify_nin", params)
}

// NotificationActivities handles notifications
type NotificationActivities struct{}

func (a *NotificationActivities) SendNotification(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "notification_service", "send_notification", params)
}

func (a *NotificationActivities) SendBulkNotification(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "notification_service", "send_bulk_notification", params)
}

func (a *NotificationActivities) SendFraudAlert(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "notification_service", "send_fraud_alert", params)
}

// FraudDetectionActivities handles fraud detection
type FraudDetectionActivities struct{}

func (a *FraudDetectionActivities) AnalyzeTransactionSpeed(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "fraud_detection_service", "analyze_transaction_speed", params)
}

func (a *FraudDetectionActivities) AnalyzePriceDeviation(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return callPythonService(ctx, "fraud_detection_service", "analyze_price_deviation", params)
}

// callPythonService invokes a configured downstream service and propagates only its actual response.
// Missing configuration, transport failures, non-success status codes, and malformed payloads are errors
// so Temporal retry policy can handle them; no local success response is fabricated.
func callPythonService(ctx context.Context, service string, method string, params map[string]interface{}) (map[string]interface{}, error) {
	envKey := "SERVICE_" + strings.ToUpper(strings.ReplaceAll(service, "-", "_")) + "_URL"
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv(envKey)), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("%s must be configured for %s", envKey, service)
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", envKey, err)
	}
	body, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("encode %s request: %w", service, err)
	}
	requestURL := baseURL + "/v1/" + url.PathEscape(method)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create %s request: %w", service, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("call %s.%s: %w", service, method, err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", service, err)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%s.%s returned status %d", service, method, response.StatusCode)
	}
	result := map[string]interface{}{}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", service, err)
	}
	return result, nil
}

func main() {
	// Get Temporal server address from environment
	temporalHost := os.Getenv("TEMPORAL_HOST")
	if temporalHost == "" {
		temporalHost = "localhost:7233"
	}

	// Create Temporal client
	c, err := client.Dial(client.Options{
		HostPort: temporalHost,
	})
	if err != nil {
		log.Fatalln("Unable to create Temporal client", err)
	}
	defer c.Close()

	// Create worker
	w := worker.New(c, "fraud-fusion-task-queue", worker.Options{})

	// Register workflows
	w.RegisterWorkflow(ExecuteJourneyWorkflow)

	// Register the journey-specific workflows and their activities.
	workflows.RegisterJourney34Workflow(w)
	workflows.RegisterJourney37Workflow(w)

	// Register activities
	landVerificationActivities := &LandVerificationActivities{}
	w.RegisterActivity(landVerificationActivities)

	documentStorageActivities := &DocumentStorageActivities{}
	w.RegisterActivity(documentStorageActivities)

	integrationActivities := &IntegrationActivities{}
	w.RegisterActivity(integrationActivities)

	notificationActivities := &NotificationActivities{}
	w.RegisterActivity(notificationActivities)

	fraudDetectionActivities := &FraudDetectionActivities{}
	w.RegisterActivity(fraudDetectionActivities)

	// Start worker
	log.Println("Starting Temporal worker on task queue: fraud-fusion-task-queue")
	err = w.Run(worker.InterruptCh())
	if err != nil {
		log.Fatalln("Unable to start worker", err)
	}
}
