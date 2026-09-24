package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// TestAnalysisFailsClosedOnDBOutage proves the risk-signal helpers propagate
// database errors instead of silently returning false, and that the analysis
// aborts (routing the event to manual review) when the DB is unavailable.
func TestAnalysisFailsClosedOnDBOutage(t *testing.T) {
	prevDB := db
	db = nil // simulate an uninitialized/unavailable database
	defer func() { db = prevDB }()

	event := SIMSwapEvent{
		EventID:       "evt-1",
		TenantID:      "tenant-a",
		UserID:        "user-1",
		PhoneNumber:   "+2348012345678",
		Telco:         "MTN",
		SwapTimestamp: time.Now(),
		Location:      "Lagos",
	}
	_, err := performSIMSwapAnalysis(context.Background(), event)
	if err == nil {
		t.Fatal("analysis must fail loudly when the database is unavailable")
	}
	if !strings.Contains(err.Error(), "database not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDetectSIMSwapManualReviewOnAnalysisFailure proves the HTTP handler
// responds 503/manual_review instead of returning a fabricated clean score
// when analysis dependencies fail.
func TestDetectSIMSwapManualReviewOnAnalysisFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	prevDB := db
	db = nil
	defer func() { db = prevDB }()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/sim-swap/detect",
		strings.NewReader(`{"event_id":"evt-1","user_id":"user-1","phone_number":"+2348012345678","telco":"MTN","swap_timestamp":"2026-01-01T10:00:00Z","location":"Lagos"}`))
	c.Request.Header.Set("Content-Type", "application/json")

	detectSIMSwap(c)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on analysis failure, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "manual_review") {
		t.Fatalf("expected manual_review disposition, got %s", w.Body.String())
	}
}

// TestRequestTenantResolution verifies tenant scoping prefers the
// authenticated principal over body-supplied values.
func TestRequestTenantResolution(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got := requestTenant(c, "body-tenant"); got != "body-tenant" {
		t.Fatalf("no principal: got %q", got)
	}
	c.Set("principal", &authPrincipal{TenantID: "token-tenant"})
	if got := requestTenant(c, "body-tenant"); got != "token-tenant" {
		t.Fatalf("principal tenant must win: got %q", got)
	}
	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got := requestTenant(c2, ""); got != "default" {
		t.Fatalf("empty tenant must default: got %q", got)
	}
}
