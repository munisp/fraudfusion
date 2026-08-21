package main

import (
	"testing"
	"time"
)

func TestAccessRiskUsesTimeResourceAndVelocity(t *testing.T) {
	event := accessEvent{EmployeeID: "employee-1", Resource: "ledger", Timestamp: time.Date(2026, 8, 20, 23, 30, 0, 0, time.UTC)}
	score, factors := accessRisk(event, history{total: 20, privileged: 10})
	if score != 85 {
		t.Fatalf("score = %d, want 85", score)
	}
	if len(factors) != 4 {
		t.Fatalf("factor count = %d, want 4: %#v", len(factors), factors)
	}
	if riskLevel(score) != "critical" {
		t.Fatalf("riskLevel(%d) = %s, want critical", score, riskLevel(score))
	}
}

func TestUnusualAccessThresholdScalesWithWindow(t *testing.T) {
	if got := unusualAccessThreshold(1); got != 10 {
		t.Fatalf("unusualAccessThreshold(1) = %d, want 10", got)
	}
	if got := unusualAccessThreshold(8); got != 24 {
		t.Fatalf("unusualAccessThreshold(8) = %d, want 24", got)
	}
}

func TestExternalDestinationDetection(t *testing.T) {
	for _, destination := range []string{"external", "personal_email", "https://example.test/exfiltration"} {
		if !isExternalDestination(destination) {
			t.Errorf("isExternalDestination(%q) = false, want true", destination)
		}
	}
	if isExternalDestination("approved_internal_archive") {
		t.Fatal("approved internal destination must not be classified as external")
	}
}
