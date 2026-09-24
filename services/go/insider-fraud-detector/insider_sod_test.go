package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// SoD request normalization / gates
// ---------------------------------------------------------------------------

func TestNormalizeSoDRequestDefaults(t *testing.T) {
	req := sodCheckRequest{SubjectID: "u1", Duty: " Initiate_Payment "}
	if err := normalizeSoDRequest(&req); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if req.SubjectType != "user" || req.Mode != "check" || req.Duty != "initiate_payment" {
		t.Fatalf("bad normalization: %#v", req)
	}
}

func TestNormalizeSoDRequestRejectsBadValues(t *testing.T) {
	for _, req := range []sodCheckRequest{
		{SubjectID: "u1", Duty: "x", SubjectType: "group"},
		{SubjectID: "u1", Duty: "x", Mode: "delete"},
		{SubjectID: "u1", Duty: "  "},
	} {
		if err := normalizeSoDRequest(&req); err == nil {
			t.Fatalf("expected error for %#v", req)
		}
	}
}

// ---------------------------------------------------------------------------
// Collusion graph verdict (pure decision)
// ---------------------------------------------------------------------------

func TestCollusionGraphVerdictSharedResourcesOnly(t *testing.T) {
	gnn := gnnArtifactStatus{Available: false, NodeScores: map[string]float64{}}
	detected, score, factors := collusionGraphVerdict(2, 2, gnn, []string{"e1", "e2"})
	if !detected || score != 70 {
		t.Fatalf("detected=%v score=%d, want true/70", detected, score)
	}
	found := false
	for _, f := range factors {
		if strings.Contains(f, "artifact unavailable") {
			found = true
		}
	}
	if !found {
		t.Fatalf("must disclose degraded mode when GNN artifact missing: %#v", factors)
	}
}

func TestCollusionGraphVerdictGNNBoostAndHighScore(t *testing.T) {
	gnn := gnnArtifactStatus{Available: true,
		NodeScores: map[string]float64{"e1": 0.9, "e2": 0.5}}
	// no shared resources, but e1 has a high mule score -> flagged
	detected, score, _ := collusionGraphVerdict(0, 2, gnn, []string{"e1", "e2"})
	if !detected {
		t.Fatal("high GNN mule score alone must flag collusion review")
	}
	if score < 70 {
		t.Fatalf("score=%d, want >= 70", score)
	}
	// shared resources + boost
	detected, score, _ = collusionGraphVerdict(2, 2, gnn, []string{"e1", "e2"})
	if !detected || score <= 70 {
		t.Fatalf("GNN boost must raise the base score: detected=%v score=%d", detected, score)
	}
}

func TestCollusionGraphVerdictBelowThresholdNoGNNHits(t *testing.T) {
	gnn := gnnArtifactStatus{Available: true,
		NodeScores: map[string]float64{"other": 0.9}}
	detected, score, _ := collusionGraphVerdict(1, 2, gnn, []string{"e1", "e2"})
	if detected || score != 0 {
		t.Fatalf("single shared resource + no GNN hit must stay quiet: %v %d", detected, score)
	}
}

// ---------------------------------------------------------------------------
// Ghost vendor
// ---------------------------------------------------------------------------

func TestGhostVendorScore(t *testing.T) {
	score, indicators := ghostVendorScore(ghostVendorRequest{
		SharedBankAccount: true, SharedDevice: true, SharedAddress: true, SharedTaxID: true})
	if score != 100 || len(indicators) != 4 {
		t.Fatalf("score=%d indicators=%v, want 100/4", score, indicators)
	}
	score, _ = ghostVendorScore(ghostVendorRequest{SharedBankAccount: true})
	if score != 50 {
		t.Fatalf("shared bank account alone = %d, want 50", score)
	}
	score, indicators = ghostVendorScore(ghostVendorRequest{})
	if score != 0 || len(indicators) != 0 {
		t.Fatalf("no overlap = %d/%v, want 0/[]", score, indicators)
	}
}

// ---------------------------------------------------------------------------
// Payroll padding
// ---------------------------------------------------------------------------

func TestPayrollPaddingOutcome(t *testing.T) {
	cases := []struct {
		name      string
		pct       float64
		approvals int
		changedBy string
		employee  string
		flagged   bool
		minScore  int
	}{
		{"below threshold is clean", 10, 0, "mgr", "emp", false, 0},
		{"above threshold with dual approval by manager", 20, 2, "mgr", "emp", true, 40},
		{"above threshold single approval", 20, 1, "mgr", "emp", true, 80},
		{"self-modified no approval", 25, 0, "emp", "emp", true, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flagged, score, _ := payrollPaddingOutcome(tc.pct, tc.approvals,
				tc.changedBy, tc.employee, 15.0)
			if flagged != tc.flagged {
				t.Fatalf("flagged=%v, want %v", flagged, tc.flagged)
			}
			if score != tc.minScore {
				t.Fatalf("score=%d, want %d", score, tc.minScore)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Expense abuse velocity
// ---------------------------------------------------------------------------

func TestExpenseAbuseOutcome(t *testing.T) {
	score, factors := expenseAbuseOutcome(12, 6_000_000, 2, 5000, 10, 5_000_000)
	if score != 100 || len(factors) != 4 {
		t.Fatalf("all signals = %d/%v, want 100/4", score, factors)
	}
	score, _ = expenseAbuseOutcome(3, 100_000, 0, 500, 10, 5_000_000)
	if score != 0 {
		t.Fatalf("normal expense = %d, want 0", score)
	}
	score, factors = expenseAbuseOutcome(0, 0, 0, 5000, 10, 5_000_000)
	if score != 10 || len(factors) != 1 {
		t.Fatalf("round amount = %d/%v, want 10/[round_amount_claim]", score, factors)
	}
}

// ---------------------------------------------------------------------------
// Handler-level gates (no DB touched on these paths)
// ---------------------------------------------------------------------------

func TestSoDCheckRejectsBadJSONAndTenantMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := &app{} // handlers below fail before any DB access
	r := gin.New()
	r.POST("/v1/insider/sod-check", func(c *gin.Context) {
		c.Set("roles", map[string]struct{}{"admin": {}})
		a.sodCheck(c)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/insider/sod-check",
		strings.NewReader(`{"tenant_id": "t1"`)) // malformed JSON
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "t1")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON: got %d, want 400", w.Code)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/insider/sod-check",
		strings.NewReader(`{"tenant_id":"t2","subject_id":"u1","duty":"initiate_payment"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "t1")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant mismatch: got %d, want 403", w.Code)
	}
}

func TestSoDCheckGrantRequiresPrivilegedRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := &app{}
	r := gin.New()
	r.POST("/v1/insider/sod-check", func(c *gin.Context) {
		c.Set("roles", map[string]struct{}{"fraud_analyst": {}})
		a.sodCheck(c)
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/insider/sod-check",
		strings.NewReader(`{"tenant_id":"t1","subject_id":"u1","duty":"approve_payment","mode":"grant"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "t1")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("grant by fraud_analyst: got %d, want 403", w.Code)
	}
}

func TestGhostVendorRejectsSameIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := &app{}
	r := gin.New()
	r.POST("/v1/insider/ghost-vendor", a.ghostVendor)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/insider/ghost-vendor",
		strings.NewReader(`{"tenant_id":"t1","employee_id":"e1","vendor_id":"e1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "t1")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("same identity: got %d, want 400", w.Code)
	}
}
