package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Insider-threat program endpoints (docs/INSIDER_THREAT_PROGRAM.md):
//   POST /v1/insider/sod-check        - segregation-of-duties evaluation /
//                                       fail-closed grant (DB trigger enforces)
//   POST /v1/insider/collusion-graph  - GNN mule/collusion artifact scores
//                                       combined with shared-resource signals
//   POST /v1/insider/ghost-vendor     - employee/vendor identity overlap
//   POST /v1/insider/payroll-padding  - salary change without dual approval
//   POST /v1/insider/expense-abuse    - expense velocity / duplicate claims
//
// All endpoints require an authenticated principal (Keycloak introspection),
// tenant isolation via X-Tenant-ID, and fail closed on storage errors.

// ---------------------------------------------------------------------------
// SoD check
// ---------------------------------------------------------------------------

type sodCheckRequest struct {
	TenantID    string `json:"tenant_id" binding:"required"`
	SubjectType string `json:"subject_type"` // "user" (default) or "role"
	SubjectID   string `json:"subject_id" binding:"required"`
	Duty        string `json:"duty" binding:"required"`
	Mode        string `json:"mode"` // "check" (default) | "grant"
}

type sodConflict struct {
	ConflictDuty string `json:"conflict_duty"`
	RuleID       int64  `json:"rule_id"`
	Severity     string `json:"severity"`
	Reason       string `json:"reason"`
}

func normalizeSoDRequest(req *sodCheckRequest) error {
	req.SubjectType = strings.ToLower(strings.TrimSpace(req.SubjectType))
	if req.SubjectType == "" {
		req.SubjectType = "user"
	}
	if req.SubjectType != "user" && req.SubjectType != "role" {
		return fmt.Errorf("subject_type must be user or role")
	}
	req.Mode = strings.ToLower(strings.TrimSpace(req.Mode))
	if req.Mode == "" {
		req.Mode = "check"
	}
	if req.Mode != "check" && req.Mode != "grant" {
		return fmt.Errorf("mode must be check or grant")
	}
	req.Duty = strings.ToLower(strings.TrimSpace(req.Duty))
	if req.Duty == "" {
		return fmt.Errorf("duty is required")
	}
	return nil
}

func (a *app) sodCheck(c *gin.Context) {
	var req sodCheckRequest
	if !bindJSON(c, &req) || !tenantMatches(c, req.TenantID) {
		return
	}
	if err := normalizeSoDRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Mode == "grant" && !hasAnyRole(c, "admin", "sod_manager") {
		c.JSON(http.StatusForbidden, gin.H{"error": "grant mode requires admin or sod_manager role"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	conflicts, err := a.sodConflicts(ctx, req)
	if err != nil {
		internalError(c, err) // fail closed
		return
	}
	if len(conflicts) > 0 {
		// Deny on violation: record the denied attempt and return 409.
		if err := a.recordSoDViolation(ctx, req, conflicts[0], "denied by sod-check"); err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusConflict, gin.H{
			"allowed": false, "subject_id": req.SubjectID, "duty": req.Duty,
			"conflicts": conflicts, "decision": "deny",
			"evaluated_at": time.Now().UTC().Format(time.RFC3339),
		})
		return
	}
	if req.Mode == "grant" {
		// The DB trigger sod_assignments_enforce re-checks fail-closed and
		// skips the insert on violation (RETURN NULL), so rows-affected == 0
		// means a concurrent grant created a conflict after our read.
		tag, err := a.db.Exec(ctx,
			`INSERT INTO sod_assignments (tenant_id, subject_type, subject_id, duty, granted_by)
			 VALUES ($1,$2,$3,$4,$5)`,
			req.TenantID, req.SubjectType, req.SubjectID, req.Duty, actor(c))
		if err != nil {
			if isSoDEnforcementError(err) {
				c.JSON(http.StatusConflict, gin.H{"allowed": false,
					"decision": "deny", "detail": "database SoD trigger denied the assignment"})
				return
			}
			internalError(c, err)
			return
		}
		if tag.RowsAffected() == 0 {
			c.JSON(http.StatusConflict, gin.H{"allowed": false,
				"decision": "deny",
				"detail":   "database SoD trigger blocked the assignment (conflict created concurrently)"})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"allowed": true, "subject_id": req.SubjectID, "duty": req.Duty,
		"mode": req.Mode, "conflicts": []sodConflict{},
		"evaluated_at": time.Now().UTC().Format(time.RFC3339),
	})
}

func (a *app) sodConflicts(ctx context.Context, req sodCheckRequest) ([]sodConflict, error) {
	rows, err := a.db.Query(ctx,
		`SELECT conflict_duty, rule_id, severity, reason
		   FROM sod_check_assignment($1,$2,$3,$4)`,
		req.TenantID, req.SubjectType, req.SubjectID, req.Duty)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	conflicts := []sodConflict{}
	for rows.Next() {
		var conflict sodConflict
		if err := rows.Scan(&conflict.ConflictDuty, &conflict.RuleID,
			&conflict.Severity, &conflict.Reason); err != nil {
			return nil, err
		}
		conflicts = append(conflicts, conflict)
	}
	return conflicts, rows.Err()
}

func (a *app) recordSoDViolation(ctx context.Context, req sodCheckRequest, conflict sodConflict, notes string) error {
	dutyA, dutyB := req.Duty, conflict.ConflictDuty
	if dutyB < dutyA {
		dutyA, dutyB = dutyB, dutyA
	}
	_, err := a.db.Exec(ctx,
		`INSERT INTO sod_violations (tenant_id, subject_type, subject_id, duty_a, duty_b, rule_id, severity, notes)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (tenant_id, subject_type, subject_id, duty_a, duty_b) WHERE status = 'open'
		 DO UPDATE SET detected_at = now(), notes = EXCLUDED.notes`,
		req.TenantID, req.SubjectType, req.SubjectID, dutyA, dutyB,
		conflict.RuleID, conflict.Severity, notes)
	return err
}

func isSoDEnforcementError(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23000" || pgErr.SQLState() == "P0001" ||
			strings.Contains(err.Error(), "SoD violation")
	}
	return strings.Contains(err.Error(), "SoD violation")
}

// ---------------------------------------------------------------------------
// Collusion graph: GNN mule artifact + shared-resource signals
// ---------------------------------------------------------------------------

type collusionGraphRequest struct {
	TenantID    string   `json:"tenant_id" binding:"required"`
	EmployeeIDs []string `json:"employee_ids" binding:"required,min=2,max=50"`
}

// gnnArtifactStatus is a read-only probe of the GNN mule/collusion artifact
// directory (default ml/artifacts/gnn_mule/<version>). The artifact carries
// graph-level metrics; optional per-node scores are consumed from
// node_scores.csv (columns: account_id,mule_score) when present.
type gnnArtifactStatus struct {
	Available    bool               `json:"available"`
	ArtifactDir  string             `json:"artifact_dir"`
	Version      string             `json:"version"`
	MetricsAUCPr float64            `json:"metrics_auc_pr,omitempty"`
	NodeScores   map[string]float64 `json:"-"`
	NodesScored  int                `json:"nodes_scored"`
}

func gnnArtifactDir() (string, string) {
	dir := envOr("GNN_ARTIFACT_DIR", "ml/artifacts/gnn_mule")
	version := envOr("GNN_MODEL_VERSION", "v2")
	return filepath.Join(dir, version), version
}

// probeGNNArtifact never writes; missing artifacts degrade the endpoint to
// shared-resource-only scoring (gnn_available=false) rather than failing.
func probeGNNArtifact() gnnArtifactStatus {
	dir, version := gnnArtifactDir()
	status := gnnArtifactStatus{ArtifactDir: dir, Version: version,
		NodeScores: map[string]float64{}}
	metricsRaw, err := os.ReadFile(filepath.Join(dir, "metrics.json"))
	if err != nil {
		return status
	}
	var metrics struct {
		AUCPr float64 `json:"auc_pr"`
	}
	if err := json.Unmarshal(metricsRaw, &metrics); err != nil {
		return status
	}
	status.Available = true
	status.MetricsAUCPr = metrics.AUCPr
	if f, err := os.Open(filepath.Join(dir, "node_scores.csv")); err == nil {
		defer f.Close()
		reader := csv.NewReader(f)
		records, err := reader.ReadAll()
		if err == nil {
			for i, rec := range records {
				if i == 0 && len(rec) > 1 && rec[0] == "account_id" {
					continue // header
				}
				if len(rec) < 2 {
					continue
				}
				if score, err := strconv.ParseFloat(strings.TrimSpace(rec[1]), 64); err == nil {
					status.NodeScores[strings.TrimSpace(rec[0])] = score
				}
			}
		}
	}
	status.NodesScored = len(status.NodeScores)
	return status
}

// collusionGraphVerdict is the pure decision combining the shared-resource
// signal (existing collusion logic) with GNN mule scores for the queried
// employees. GNN scores in [0,1] contribute up to +40 on top of the
// shared-resource score; a high GNN score alone (>= 0.8) is itself a flag.
func collusionGraphVerdict(sharedResourceCount, minShared int,
	gnn gnnArtifactStatus, employeeIDs []string) (detected bool, score int, factors []string) {
	factors = []string{}
	baseDetected, baseScore, baseFactors := collusionOutcome(sharedResourceCount, minShared)
	factors = append(factors, baseFactors...)
	score = baseScore
	detected = baseDetected

	gnnSum := 0.0
	gnnHits := 0
	highGNN := []string{}
	for _, id := range employeeIDs {
		if s, ok := gnn.NodeScores[id]; ok {
			gnnSum += s
			gnnHits++
			if s >= 0.8 {
				highGNN = append(highGNN, id)
			}
		}
	}
	if gnnHits > 0 {
		avg := gnnSum / float64(gnnHits)
		boost := int(math.Round(avg * 40))
		score = min(100, score+boost)
		factors = append(factors, fmt.Sprintf(
			"gnn_mule_scores: %d/%d employees scored, mean=%.3f (+%d risk)",
			gnnHits, len(employeeIDs), avg, boost))
		if len(highGNN) > 0 {
			detected = true
			score = max(score, 70)
			factors = append(factors, fmt.Sprintf(
				"high_gnn_mule_score (>=0.8): %s", strings.Join(highGNN, ",")))
		}
	} else if gnn.Available {
		factors = append(factors, "gnn_mule_artifact present but no node scores for queried employees")
	} else {
		factors = append(factors, "gnn_mule artifact unavailable - shared-resource signal only")
	}
	if detected && score == 0 {
		score = 70
	}
	return detected, score, factors
}

func (a *app) collusionGraph(c *gin.Context) {
	var req collusionGraphRequest
	if !bindJSON(c, &req) || !tenantMatches(c, req.TenantID) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	var sharedResourceCount int
	if err := a.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM (
		   SELECT resource FROM privileged_access_logs
		    WHERE tenant_id=$1 AND employee_id = ANY($2)
		      AND created_at >= NOW() - INTERVAL '72 hours'
		    GROUP BY resource HAVING COUNT(DISTINCT employee_id) >= 2
		 ) AS shared_resources`, req.TenantID, req.EmployeeIDs).Scan(&sharedResourceCount); err != nil {
		internalError(c, err) // fail closed
		return
	}
	gnn := probeGNNArtifact()
	minShared := collusionMinSharedResources()
	detected, score, factors := collusionGraphVerdict(sharedResourceCount, minShared, gnn, req.EmployeeIDs)
	if detected {
		for _, employeeID := range req.EmployeeIDs {
			if err := a.persistEventAndAlert(ctx, req.TenantID, employeeID,
				"collusion_graph", score, factors, actor(c)); err != nil {
				internalError(c, err)
				return
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"employees": req.EmployeeIDs, "collusion_detected": detected,
		"risk_score": score, "risk_level": riskLevel(score),
		"shared_resource_count":          sharedResourceCount,
		"collusion_min_shared_resources": minShared,
		"gnn_available":                  gnn.Available, "gnn_artifact_dir": gnn.ArtifactDir,
		"gnn_version": gnn.Version, "gnn_metrics_auc_pr": gnn.MetricsAUCPr,
		"gnn_nodes_scored": gnn.NodesScored,
		"factors":          factors,
		"evaluated_at":     time.Now().UTC().Format(time.RFC3339),
	})
}

// ---------------------------------------------------------------------------
// Ghost-vendor / ghost-employee overlap
// ---------------------------------------------------------------------------

type ghostVendorRequest struct {
	TenantID          string `json:"tenant_id" binding:"required"`
	EmployeeID        string `json:"employee_id" binding:"required"`
	VendorID          string `json:"vendor_id" binding:"required"`
	SharedBankAccount bool   `json:"shared_bank_account"`
	SharedDevice      bool   `json:"shared_device"`
	SharedAddress     bool   `json:"shared_address"`
	SharedTaxID       bool   `json:"shared_tax_id"`
}

// ghostVendorScore weights identity-artefact overlaps; a shared bank account
// or tax ID is near-conclusive alone.
func ghostVendorScore(req ghostVendorRequest) (int, []string) {
	score := 0
	indicators := []string{}
	if req.SharedBankAccount {
		score += 50
		indicators = append(indicators, "shared_bank_account")
	}
	if req.SharedTaxID {
		score += 25
		indicators = append(indicators, "shared_tax_id")
	}
	if req.SharedDevice {
		score += 20
		indicators = append(indicators, "shared_device")
	}
	if req.SharedAddress {
		score += 15
		indicators = append(indicators, "shared_address")
	}
	return min(100, score), indicators
}

func ghostVendorThreshold() int {
	return intEnvOr("GHOST_VENDOR_ALERT_THRESHOLD", 50)
}

func (a *app) ghostVendor(c *gin.Context) {
	var req ghostVendorRequest
	if !bindJSON(c, &req) || !tenantMatches(c, req.TenantID) {
		return
	}
	if req.EmployeeID == req.VendorID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "employee_id and vendor_id must differ"})
		return
	}
	score, indicators := ghostVendorScore(req)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	status := "open"
	if score < ghostVendorThreshold() {
		status = "cleared"
	}
	_, err := a.db.Exec(ctx,
		`INSERT INTO employee_vendor_overlap
		   (tenant_id, employee_id, vendor_id, shared_bank_account, shared_device,
		    shared_address, shared_tax_id, overlap_score, status)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (tenant_id, employee_id, vendor_id)
		 DO UPDATE SET shared_bank_account = EXCLUDED.shared_bank_account,
		               shared_device = EXCLUDED.shared_device,
		               shared_address = EXCLUDED.shared_address,
		               shared_tax_id = EXCLUDED.shared_tax_id,
		               overlap_score = EXCLUDED.overlap_score,
		               status = EXCLUDED.status,
		               detected_at = now()`,
		req.TenantID, req.EmployeeID, req.VendorID, req.SharedBankAccount,
		req.SharedDevice, req.SharedAddress, req.SharedTaxID, score, status)
	if err != nil {
		internalError(c, err) // fail closed
		return
	}
	ghost := score >= ghostVendorThreshold()
	if ghost {
		if err := a.persistEventAndAlert(ctx, req.TenantID, req.EmployeeID,
			"ghost_vendor_overlap", score, indicators, actor(c)); err != nil {
			internalError(c, err)
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"employee_id": req.EmployeeID, "vendor_id": req.VendorID,
		"overlap_score": score, "risk_level": riskLevel(score),
		"ghost_suspected": ghost, "indicators": indicators,
		"threshold":    ghostVendorThreshold(),
		"evaluated_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// ---------------------------------------------------------------------------
// Payroll padding: salary changes above threshold without dual approval
// ---------------------------------------------------------------------------

type payrollPaddingRequest struct {
	TenantID          string  `json:"tenant_id" binding:"required"`
	EmployeeID        string  `json:"employee_id" binding:"required"`
	ChangedBy         string  `json:"changed_by" binding:"required"`
	SalaryChangePct   float64 `json:"salary_change_pct" binding:"gte=0"`
	DualApprovalCount int     `json:"dual_approval_count" binding:"gte=0"` // distinct approver events
}

// payrollPaddingOutcome: a salary change above the threshold is only clean
// with >=2 distinct approver events AND someone other than the beneficiary
// making the change.
func payrollPaddingOutcome(changePct float64, dualApprovals int,
	changedBy, employeeID string, thresholdPct float64) (flagged bool, score int, factors []string) {
	factors = []string{}
	if changePct < thresholdPct {
		return false, 0, factors
	}
	factors = append(factors, fmt.Sprintf(
		"salary_change_above_threshold: %.1f%% >= %.1f%%", changePct, thresholdPct))
	score = 40
	if dualApprovals < 2 {
		score += 40
		factors = append(factors, fmt.Sprintf(
			"missing_dual_approval: %d distinct approver events (< 2 required)", dualApprovals))
	}
	if changedBy == employeeID {
		score += 20
		factors = append(factors, "self_modified_salary")
	}
	return true, min(100, score), factors
}

func payrollPaddingThresholdPct() float64 {
	if raw := strings.TrimSpace(os.Getenv("PAYROLL_PADDING_THRESHOLD_PCT")); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil && v > 0 {
			return v
		}
	}
	return 15.0
}

func (a *app) payrollPadding(c *gin.Context) {
	var req payrollPaddingRequest
	if !bindJSON(c, &req) || !tenantMatches(c, req.TenantID) {
		return
	}
	flagged, score, factors := payrollPaddingOutcome(req.SalaryChangePct,
		req.DualApprovalCount, req.ChangedBy, req.EmployeeID,
		payrollPaddingThresholdPct())
	if flagged {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		if err := a.persistEventAndAlert(ctx, req.TenantID, req.EmployeeID,
			"payroll_padding", score, factors, actor(c)); err != nil {
			internalError(c, err)
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"employee_id": req.EmployeeID, "flagged": flagged,
		"risk_score": score, "risk_level": riskLevel(score),
		"factors": factors, "threshold_pct": payrollPaddingThresholdPct(),
		"evaluated_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// ---------------------------------------------------------------------------
// Expense-abuse velocity
// ---------------------------------------------------------------------------

type expenseAbuseRequest struct {
	TenantID   string    `json:"tenant_id" binding:"required"`
	EmployeeID string    `json:"employee_id" binding:"required"`
	Amount     float64   `json:"amount" binding:"required,gt=0"`
	Merchant   string    `json:"merchant" binding:"required"`
	Timestamp  time.Time `json:"timestamp" binding:"required"`
}

// expenseAbuseOutcome scores velocity, duplicate-merchant bursts and
// round-amount claims.
func expenseAbuseOutcome(claims24h int, amount30d float64, duplicates24h int,
	amount float64, maxClaims24h int, maxAmount30d float64) (int, []string) {
	score := 0
	factors := []string{}
	if claims24h >= maxClaims24h {
		score += 35
		factors = append(factors, fmt.Sprintf(
			"expense_velocity: %d claims in 24h (threshold %d)", claims24h, maxClaims24h))
	}
	if amount30d >= maxAmount30d {
		score += 30
		factors = append(factors, fmt.Sprintf(
			"expense_volume_30d: %.0f (threshold %.0f)", amount30d, maxAmount30d))
	}
	if duplicates24h > 0 {
		score += 25
		factors = append(factors, fmt.Sprintf(
			"duplicate_merchant_claims_24h: %d", duplicates24h))
	}
	if amount >= 1000 && math.Mod(amount, 1000) == 0 {
		score += 10
		factors = append(factors, "round_amount_claim")
	}
	return min(100, score), factors
}

func (a *app) expenseAbuse(c *gin.Context) {
	var req expenseAbuseRequest
	if !bindJSON(c, &req) || !tenantMatches(c, req.TenantID) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	if _, err := a.db.Exec(ctx,
		`INSERT INTO expense_claims (tenant_id, employee_id, amount, merchant, created_at)
		 VALUES ($1,$2,$3,$4,$5)`,
		req.TenantID, req.EmployeeID, req.Amount, req.Merchant, req.Timestamp.UTC()); err != nil {
		internalError(c, err) // fail closed
		return
	}
	var claims24h, duplicates24h int
	var amount30d float64
	if err := a.db.QueryRow(ctx,
		`SELECT
		   (SELECT COUNT(*) FROM expense_claims
		     WHERE tenant_id=$1 AND employee_id=$2
		       AND created_at >= NOW() - INTERVAL '24 hours'),
		   (SELECT COUNT(*) FROM expense_claims
		     WHERE tenant_id=$1 AND employee_id=$2 AND merchant=$3
		       AND ABS(amount - $4) < 0.01
		       AND created_at >= NOW() - INTERVAL '24 hours') - 1,
		   (SELECT COALESCE(SUM(amount),0) FROM expense_claims
		     WHERE tenant_id=$1 AND employee_id=$2
		       AND created_at >= NOW() - INTERVAL '30 days')`,
		req.TenantID, req.EmployeeID, req.Merchant, req.Amount).
		Scan(&claims24h, &duplicates24h, &amount30d); err != nil {
		internalError(c, err)
		return
	}
	maxClaims := intEnvOr("EXPENSE_MAX_CLAIMS_24H", 10)
	maxAmount := floatEnvOr("EXPENSE_MAX_AMOUNT_30D", 5_000_000)
	score, factors := expenseAbuseOutcome(claims24h, amount30d, duplicates24h,
		req.Amount, maxClaims, maxAmount)
	if score >= 50 {
		if err := a.persistEventAndAlert(ctx, req.TenantID, req.EmployeeID,
			"expense_abuse", score, factors, actor(c)); err != nil {
			internalError(c, err)
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"employee_id": req.EmployeeID, "risk_score": score,
		"risk_level": riskLevel(score), "abuse_suspected": score >= 50,
		"factors": factors, "claims_last_24h": claims24h,
		"amount_last_30d": amount30d, "duplicates_last_24h": duplicates24h,
		"evaluated_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func hasAnyRole(c *gin.Context, roles ...string) bool {
	value, _ := c.Get("roles")
	held, _ := value.(map[string]struct{})
	for _, role := range roles {
		if _, ok := held[role]; ok {
			return true
		}
	}
	return false
}

func intEnvOr(key string, fallback int) int {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 {
			return n
		}
	}
	return fallback
}

func floatEnvOr(key string, fallback float64) float64 {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil && v > 0 {
			return v
		}
	}
	return fallback
}
