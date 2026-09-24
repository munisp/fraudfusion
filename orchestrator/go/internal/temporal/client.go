package temporal

import (
	"context"
	"fmt"
	"os"

	temporalsdk "go.temporal.io/sdk/client"
)

// Client wraps the Temporal Go SDK client for journey workflow execution.
type Client struct {
	client    temporalsdk.Client
	namespace string
	taskQueue string
}

// WorkflowInput is the serializable payload delivered to a registered journey workflow.
type WorkflowInput struct {
	JourneyID string                 `json:"journey_id"`
	UserID    string                 `json:"user_id"`
	Data      map[string]interface{} `json:"data"`
}

// WorkflowResult is the required result contract emitted by a completed journey workflow.
type WorkflowResult struct {
	Status    string                 `json:"status"`
	Decision  string                 `json:"decision"`
	RiskScore float64                `json:"risk_score"`
	Data      map[string]interface{} `json:"data"`
}

// NewClient establishes an SDK connection to Temporal. It returns an error when
// Temporal cannot be reached, ensuring callers fail closed rather than fabricate workflow results.
func NewClient(hostPort, namespace string) (*Client, error) {
	if hostPort == "" {
		return nil, fmt.Errorf("Temporal host and port are required")
	}
	if namespace == "" {
		return nil, fmt.Errorf("Temporal namespace is required")
	}

	sdkClient, err := temporalsdk.Dial(temporalsdk.Options{
		HostPort:  hostPort,
		Namespace: namespace,
	})
	if err != nil {
		return nil, fmt.Errorf("connect to Temporal: %w", err)
	}

	taskQueue := os.Getenv("TEMPORAL_TASK_QUEUE")
	if taskQueue == "" {
		taskQueue = "fraudfusion-journeys"
	}

	return &Client{client: sdkClient, namespace: namespace, taskQueue: taskQueue}, nil
}

// StartWorkflow submits work to Temporal and returns its immutable workflow run ID.
func (c *Client) StartWorkflow(ctx context.Context, workflowID, workflowName string, input WorkflowInput) (string, error) {
	if workflowID == "" || workflowName == "" {
		return "", fmt.Errorf("workflow ID and workflow name are required")
	}

	run, err := c.client.ExecuteWorkflow(ctx, temporalsdk.StartWorkflowOptions{
		ID:        workflowID,
		TaskQueue: c.taskQueue,
	}, workflowName, input)
	if err != nil {
		return "", fmt.Errorf("start Temporal workflow %s: %w", workflowID, err)
	}
	return run.GetRunID(), nil
}

// GetWorkflowResult waits for the Temporal workflow result and decodes the
// persisted outcome into the platform result contract.
func (c *Client) GetWorkflowResult(ctx context.Context, workflowID, runID string) (*WorkflowResult, error) {
	if workflowID == "" || runID == "" {
		return nil, fmt.Errorf("workflow ID and run ID are required")
	}

	run := c.client.GetWorkflow(ctx, workflowID, runID)
	var result WorkflowResult
	if err := run.Get(ctx, &result); err != nil {
		return nil, fmt.Errorf("get Temporal workflow result: %w", err)
	}
	return &result, nil
}

// Health performs a real Temporal server health check via the SDK.
func (c *Client) Health(ctx context.Context) error {
	if _, err := c.client.CheckHealth(ctx, &temporalsdk.CheckHealthRequest{}); err != nil {
		return fmt.Errorf("temporal health check: %w", err)
	}
	return nil
}

// Close releases the Temporal SDK connection.
func (c *Client) Close() {
	if c.client != nil {
		c.client.Close()
	}
}
