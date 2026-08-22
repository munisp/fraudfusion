package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestTenantFromClaimsAndRequestContext(t *testing.T) {
	if tenant, ok := tenantFromClaims(map[string]interface{}{"tenant_id": "tenant-a"}); !ok || tenant != "tenant-a" {
		t.Fatalf("tenant claim = %q, %t; want tenant-a, true", tenant, ok)
	}
	if _, ok := tenantFromClaims(map[string]interface{}{"tenant_id": " "}); ok {
		t.Fatal("blank tenant claim must be rejected")
	}
	gin.SetMode(gin.TestMode)
	writer := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(writer)
	context.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	context.Set("tenant", "tenant-a")
	if tenant, ok := tenantFromHeader(context); !ok || tenant != "tenant-a" {
		t.Fatalf("authenticated tenant = %q, %t; want tenant-a, true", tenant, ok)
	}
	writer = httptest.NewRecorder()
	context, _ = gin.CreateTestContext(writer)
	context.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	context.Request.Header.Set("X-Tenant-ID", "tenant-b")
	context.Set("tenant", "tenant-a")
	if _, ok := tenantFromHeader(context); ok || writer.Code != http.StatusForbidden {
		t.Fatalf("mismatched X-Tenant-ID must be forbidden; ok=%t status=%d", ok, writer.Code)
	}
}

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
