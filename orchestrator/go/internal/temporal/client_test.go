package temporal

import (
	"encoding/json"
	"testing"
	"time"
)

// TestWorkflowContractConstants pins the orchestrator side of the
// orchestrator↔worker contract (worker: services/go/temporal-orchestrator).
func TestWorkflowContractConstants(t *testing.T) {
	if ExecuteJourneyWorkflowName != "ExecuteJourneyWorkflow" {
		t.Fatalf("workflow name contract changed: %q", ExecuteJourneyWorkflowName)
	}
	if DefaultTaskQueue != "fraud-fusion-task-queue" {
		t.Fatalf("task queue contract changed: %q", DefaultTaskQueue)
	}
}

// TestWorkflowInputMatchesWorkerContract serializes WorkflowInput the way the
// Temporal data converter will and asserts the exact JSON keys the worker's
// JourneyWorkflow/JourneyStep structs decode (journey_id, user_id, steps,
// context, snake_case step fields). A drift here previously meant the worker
// received zero steps and iterated nothing.
func TestWorkflowInputMatchesWorkerContract(t *testing.T) {
	input := WorkflowInput{
		JourneyID: "journey-34",
		UserID:    "user-1",
		Steps: []WorkflowStep{{
			ID:         "step-1",
			Name:       "Process documents",
			Service:    "land_verification_service",
			Method:     "ProcessDocumentsDeepseek",
			StepType:   "SEQUENTIAL",
			Parameters: map[string]interface{}{"doc": "abc"},
			Required:   true,
			Condition:  "${step-0.approved} == true",
			RetryPolicy: &WorkflowRetryPolicy{
				MaxAttempts:     5,
				BackoffInterval: 2 * time.Second,
			},
		}},
		Context: map[string]interface{}{"tenant": "t1"},
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"journey_id", "user_id", "steps", "context"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("workflow input missing contract key %q: %s", key, raw)
		}
	}
	steps, ok := decoded["steps"].([]interface{})
	if !ok || len(steps) != 1 {
		t.Fatalf("steps not serialized: %s", raw)
	}
	step, ok := steps[0].(map[string]interface{})
	if !ok {
		t.Fatalf("step not an object: %s", raw)
	}
	for _, key := range []string{"id", "name", "service", "method", "step_type", "parameters", "required", "condition", "retry_policy"} {
		if _, ok := step[key]; !ok {
			t.Fatalf("step missing contract key %q: %s", key, raw)
		}
	}
	rp, ok := step["retry_policy"].(map[string]interface{})
	if !ok {
		t.Fatalf("retry_policy missing: %s", raw)
	}
	if rp["max_attempts"].(float64) != 5 || rp["backoff_interval"].(float64) != float64(2*time.Second) {
		t.Fatalf("retry_policy fields wrong: %v", rp)
	}
	if step["service"] != "land_verification_service" || step["method"] != "ProcessDocumentsDeepseek" {
		t.Fatalf("service/method fields wrong: %v", step)
	}
}
