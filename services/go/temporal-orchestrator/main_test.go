package main

import (
	"encoding/json"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestWorkflowContractPinsNameAndQueue locks the cross-service contract: the
// orchestrator must start "ExecuteJourneyWorkflow" on "fraud-fusion-task-queue".
func TestWorkflowContractPinsNameAndQueue(t *testing.T) {
	fnName := runtime.FuncForPC(reflect.ValueOf(ExecuteJourneyWorkflow).Pointer()).Name()
	simpleName := fnName[strings.LastIndex(fnName, ".")+1:]
	if ExecuteJourneyWorkflowName != simpleName {
		t.Fatalf("workflow contract mismatch: constant %q != registered function name %q", ExecuteJourneyWorkflowName, simpleName)
	}
	if TaskQueue != "fraud-fusion-task-queue" {
		t.Fatalf("task queue contract changed: %q", TaskQueue)
	}
}

// TestWorkflowInputContractDecodesOrchestratorPayload ensures the JSON the
// orchestrator emits (journey_id / user_id / steps / context, snake_case step
// fields) decodes fully into the worker's workflow input struct — including
// Steps, which previously was never populated.
func TestWorkflowInputContractDecodesOrchestratorPayload(t *testing.T) {
	payload := `{
		"journey_id": "journey-34",
		"user_id": "user-1",
		"steps": [{
			"id": "step-1",
			"name": "Process documents",
			"service": "land_verification_service",
			"method": "ProcessDocumentsDeepseek",
			"step_type": "SEQUENTIAL",
			"parameters": {"doc": "abc"},
			"required": true,
			"condition": "${step-0.approved} == true",
			"retry_policy": {"max_attempts": 5, "backoff_interval": 2000000000}
		}],
		"context": {"tenant": "t1"}
	}`
	var input JourneyWorkflow
	if err := json.Unmarshal([]byte(payload), &input); err != nil {
		t.Fatalf("decode orchestrator payload: %v", err)
	}
	if input.JourneyID != "journey-34" || input.UserID != "user-1" {
		t.Fatalf("top-level fields not decoded: %+v", input)
	}
	if len(input.Steps) != 1 {
		t.Fatalf("steps not decoded: %+v", input)
	}
	step := input.Steps[0]
	if step.Service != "land_verification_service" || step.Method != "ProcessDocumentsDeepseek" ||
		step.StepType != "SEQUENTIAL" || !step.Required || step.Parameters["doc"] != "abc" {
		t.Fatalf("step fields not decoded: %+v", step)
	}
	if step.RetryPolicy == nil || step.RetryPolicy.MaxAttempts != 5 || step.RetryPolicy.BackoffInterval != 2*time.Second {
		t.Fatalf("retry policy not decoded: %+v", step.RetryPolicy)
	}
	if input.Context["tenant"] != "t1" {
		t.Fatalf("context not decoded: %+v", input.Context)
	}
}

// TestEvaluateCondition verifies conditions are actually evaluated instead of
// always returning true.
func TestEvaluateCondition(t *testing.T) {
	ctx := map[string]interface{}{
		"kyc": map[string]interface{}{"approved": true, "tier": "enhanced"},
		"empty": "",
	}
	cases := []struct {
		condition string
		want      bool
	}{
		{"", true},
		{"${kyc}", true},
		{"${missing}", false},
		{"${empty}", false},
		{"${kyc.approved} == true", true},
		{"${kyc.approved} == false", false},
		{"${kyc.tier} == enhanced", true},
		{"${kyc.tier} != premium", true},
		{"${kyc.tier} == premium", false},
		{"${missing.field} == true", false},
	}
	for _, tc := range cases {
		if got := evaluateCondition(tc.condition, ctx); got != tc.want {
			t.Errorf("evaluateCondition(%q) = %v, want %v", tc.condition, got, tc.want)
		}
	}
}
