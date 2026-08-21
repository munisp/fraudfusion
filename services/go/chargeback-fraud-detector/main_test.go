package main

import "testing"

func TestCalculateTransactionRiskUsesHistoryAndTransactionAttributes(t *testing.T) {
	request := transactionRequest{
		TenantID: "tenant-a", TransactionID: "txn-1", CustomerID: "customer-1", MerchantID: "merchant-1",
		Amount: highValueThreshold, Currency: "USD",
	}
	score, factors := calculateTransactionRisk(request, 2, 3)
	if score != 75 {
		t.Fatalf("score = %d, want 75", score)
	}
	if len(factors) != 4 {
		t.Fatalf("factor count = %d, want 4: %#v", len(factors), factors)
	}
	if calculateRiskLevel(score) != "critical" {
		t.Fatalf("risk level = %s, want critical", calculateRiskLevel(score))
	}
}

func TestAbuseThresholdIsWindowSensitive(t *testing.T) {
	cases := []struct {
		window int
		want   int
	}{
		{window: 30, want: 3},
		{window: 31, want: 5},
		{window: 180, want: 5},
		{window: 181, want: 8},
	}
	for _, test := range cases {
		if got := abuseThreshold(test.window); got != test.want {
			t.Errorf("abuseThreshold(%d) = %d, want %d", test.window, got, test.want)
		}
	}
}

func TestDisputeRecommendationUsesLikelihoodBands(t *testing.T) {
	cases := []struct {
		likelihood float64
		want       string
	}{
		{likelihood: 0.10, want: "continue_standard_dispute_review"},
		{likelihood: 0.35, want: "request_additional_evidence"},
		{likelihood: 0.70, want: "escalate_for_fraud_review"},
	}
	for _, test := range cases {
		if got := disputeRecommendation(test.likelihood); got != test.want {
			t.Errorf("disputeRecommendation(%f) = %s, want %s", test.likelihood, got, test.want)
		}
	}
}
