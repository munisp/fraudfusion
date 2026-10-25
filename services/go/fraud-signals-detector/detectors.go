// Package detectors is the Go port of the FraudFusion fraud-signal detectors.
//
// Line-for-line port of services/python/fraud-signals/detectors.py. All four
// language ports (Python, TypeScript, Go, Rust) are pinned to the same parity
// contract: services/python/fraud-signals/fixtures/detector_cases.json.
// Any threshold change must land in all ports and regenerate the fixture.
package detectors

import (
	"encoding/json"
	"math"
	"time"
)

const (
	BlockMin   = 0.70
	ReviewMin  = 0.35

	StructuringBelowNgn      = 50_000.0
	AgentVelocitySpike       = 3.0
	LoanStackingLenders      = 3
	LoanStackingWindowDays   = 14
	MulePassThroughMin       = 0.85
	MuleFanInMin             = 5
	MuleHighRiskFanInMin     = 3
	GhostSharedAccountMin    = 2
	IssuanceOfficerZ         = 3.0
	IssuanceBeneficiaryBurstMin = 3
	HighValueSingleApprovalNgn  = 10_000_000.0
	SimStepupWindowHours     = 168.0
	SimStepupAmountMinNgn    = 100_000.0
	SubsidyMaxNgnPerHectare  = 150_000.0
)

// Payload is a free-form detector input map.
type Payload map[string]any

// HistoryEvent is one stored fact about a subject.
type HistoryEvent struct {
	Payload   Payload `json:"payload"`
	CreatedAt string  `json:"created_at"`
}

// Factor is one explainable additive score contribution.
type Factor struct {
	Code   string  `json:"code"`
	Detail string  `json:"detail"`
	Weight float64 `json:"weight"`
}

// Result is the detector output: capped score, verdict band, factors.
type Result struct {
	Score   float64  `json:"score"`
	Verdict string   `json:"verdict"`
	Factors []Factor `json:"factors"`
}

func verdictOf(score float64) string {
	if score >= BlockMin {
		return "block"
	}
	if score >= ReviewMin {
		return "review"
	}
	return "clear"
}

func cap1(score float64) float64 {
	return math.Round(math.Min(score, 1.0)*1000) / 1000
}

func mkresult(score float64, factors []Factor) Result {
	s := cap1(score)
	return Result{Score: s, Verdict: verdictOf(s), Factors: factors}
}

func num(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func truthy(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

func windowDays(events []HistoryEvent, days int, now time.Time) []HistoryEvent {
	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour)
	out := make([]HistoryEvent, 0, len(events))
	for _, e := range events {
		t, err := time.Parse(time.RFC3339, e.CreatedAt)
		if err != nil || !t.Before(cutoff) {
			out = append(out, e)
		}
	}
	return out
}

func payloadOf(events []HistoryEvent) []Payload {
	out := make([]Payload, 0, len(events))
	for _, e := range events {
		out = append(out, e.Payload)
	}
	return out
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

// Detector evaluates one fraud pattern.
type Detector func(payload Payload, history []HistoryEvent, now time.Time) Result

// AppScam — authorized-push-payment / social-engineering scam.
func AppScam(p Payload, history []HistoryEvent, now time.Time) Result {
	f := []Factor{}
	score := 0.05
	if truthy(p["payee_is_new"]) {
		score += 0.20
		f = append(f, Factor{"new_payee", "first-ever transfer to this payee", 0.20})
	}
	if hours, ok := num(p["payee_age_hours"]); ok && hours < 1 {
		score += 0.15
		f = append(f, Factor{"payee_just_added", "payee added <1h before transfer", 0.15})
	}
	avg, hasAvg := num(p["customer_avg_amount"])
	amount, _ := num(p["amount_ngn"])
	if hasAvg && avg != 0 && amount > 8*avg {
		score += 0.20
		f = append(f, Factor{"amount_outlier", "amount >8x customer average", 0.20})
	}
	if s, ok := num(p["session_seconds"]); ok && s < 45 {
		score += 0.15
		f = append(f, Factor{"rushed_session", "transfer completed in <45s — coercion pattern", 0.15})
	}
	if truthy(p["device_is_new"]) {
		score += 0.10
		f = append(f, Factor{"new_device", "unrecognised device", 0.10})
	}
	if m, ok := num(p["payee_mule_score"]); ok && m >= ReviewMin {
		score += 0.25
		f = append(f, Factor{"payee_mule_like", "payee mule score elevated", 0.25})
	}
	if len(history) == 0 && !hasAvg {
		f = append(f, Factor{"history_unavailable", "no spending history supplied — amount-outlier signal skipped", 0})
	}
	return mkresult(score, f)
}

// Mule — money-mule account behaviour.
func Mule(p Payload, history []HistoryEvent, now time.Time) Result {
	f := []Factor{}
	score := 0.05
	txs := payloadOf(windowDays(history, 7, now))
	var inSum, outSum float64
	senders := map[string]bool{}
	risky := map[string]bool{}
	for _, t := range txs {
		amt, _ := num(t["amount_ngn"])
		switch t["direction"] {
		case "in":
			inSum += amt
			if cp := strOf(t["counterparty"]); cp != "" {
				senders[cp] = true
				if r, ok := num(t["counterparty_risk"]); ok && r >= ReviewMin {
					risky[cp] = true
				}
			}
		case "out":
			outSum += amt
		}
	}
	if inSum > 0 && outSum/inSum >= MulePassThroughMin {
		score += 0.35
		f = append(f, Factor{"pass_through", "most inbound funds forwarded within the window", 0.35})
	}
	if len(senders) >= MuleFanInMin {
		score += 0.25
		f = append(f, Factor{"fan_in", "many distinct senders in 7d", 0.25})
	}
	if len(risky) >= MuleHighRiskFanInMin {
		score += 0.30
		f = append(f, Factor{"high_risk_fan_in", "distinct senders with elevated own-risk scores", 0.30})
	}
	if d, ok := num(p["dormant_days_before"]); ok && d >= 90 && len(txs) > 0 {
		score += 0.20
		f = append(f, Factor{"dormancy_burst", "long dormancy then sudden activity", 0.20})
	}
	if s, ok := num(p["shared_device_accounts"]); ok && s >= 3 {
		score += 0.20
		f = append(f, Factor{"shared_device_cluster", "device shared with several accounts", 0.20})
	}
	if len(txs) == 0 {
		f = append(f, Factor{"history_unavailable", "no recent transfer events — behavioural signals skipped", 0})
	}
	return mkresult(score, f)
}

// Agent — agent-banking / mobile-money agent fraud.
func Agent(p Payload, history []HistoryEvent, now time.Time) Result {
	f := []Factor{}
	score := 0.05
	txs := payloadOf(windowDays(history, 1, now))
	baseline, _ := num(p["baseline_tx_per_day"])
	if baseline > 0 && float64(len(txs)) > AgentVelocitySpike*baseline {
		score += 0.25
		f = append(f, Factor{"velocity_spike", "transaction count far above baseline", 0.25})
	}
	near := 0
	for _, t := range txs {
		if t["type"] == "cash_out" {
			if a, ok := num(t["amount_ngn"]); ok &&
				a >= StructuringBelowNgn*0.9 && a < StructuringBelowNgn {
				near++
			}
		}
	}
	if near >= 3 {
		score += 0.35
		f = append(f, Factor{"structuring", "cash-outs clustered just below the reporting threshold", 0.35})
	}
	if d, ok := num(p["distance_from_registered_km"]); ok && d > 5 {
		score += 0.20
		f = append(f, Factor{"off_location", "operating far from registered location", 0.20})
	}
	if m, ok := num(p["float_mismatch_ngn"]); ok && math.Abs(m) > 100_000 {
		score += 0.25
		f = append(f, Factor{"float_diversion", "float/ledger mismatch", 0.25})
	}
	if len(txs) == 0 && baseline == 0 {
		f = append(f, Factor{"history_unavailable", "no agent activity history — velocity/structuring skipped", 0})
	}
	return mkresult(score, f)
}

// LoanStacking — cross-lender loan stacking / bust-out.
func LoanStacking(p Payload, history []HistoryEvent, now time.Time) Result {
	f := []Factor{}
	score := 0.05
	apps := payloadOf(windowDays(history, LoanStackingWindowDays, now))
	lenders := map[string]bool{}
	for _, a := range apps {
		if l := strOf(a["lender_id"]); l != "" {
			lenders[l] = true
		}
	}
	if len(lenders) >= LoanStackingLenders {
		score += 0.40
		f = append(f, Factor{"multi_lender_stack", "applications at many lenders in the window", 0.40})
	}
	if truthy(p["first_payment_default"]) {
		score += 0.35
		f = append(f, Factor{"first_payment_default", "prior loan defaulted on first payment (bust-out signal)", 0.35})
	}
	if truthy(p["thin_file"]) {
		score += 0.10
		f = append(f, Factor{"thin_file", "no credit history — synthetic-identity risk", 0.10})
	}
	if d, ok := num(p["document_authenticity_score"]); ok && d >= 50 {
		score += 0.25
		f = append(f, Factor{"forged_income_docs", "document engine authenticity score elevated (forgery suspected)", 0.25})
	}
	return mkresult(score, f)
}

// Issuance — insider-issued GENUINE documents (registry anomaly).
func Issuance(p Payload, history []HistoryEvent, now time.Time) Result {
	f := []Factor{}
	score := 0.05
	officerToday := len(windowDays(history, 1, now))
	peerMean, hasMean := num(p["peer_officer_mean_per_day"])
	peerStd, hasStd := num(p["peer_officer_std_per_day"])
	if hasMean && hasStd && peerStd != 0 {
		z := (float64(officerToday) - peerMean) / math.Max(peerStd, 0.1)
		if z >= IssuanceOfficerZ {
			score += 0.35
			f = append(f, Factor{"officer_velocity_outlier", "officer issuance velocity far above peers", 0.35})
		}
	}
	if h, ok := num(p["issued_hour_local"]); ok && (h < 6 || h >= 22) {
		score += 0.15
		f = append(f, Factor{"after_hours_issuance", "issued outside business hours", 0.15})
	}
	if truthy(p["sequence_gap"]) {
		score += 0.20
		f = append(f, Factor{"certificate_sequence_gap", "certificate number falls in a skipped sequence block", 0.20})
	}
	if truthy(p["registry_survey_mismatch"]) {
		score += 0.30
		f = append(f, Factor{"registry_survey_mismatch", "registry record's survey hash != physical survey plan", 0.30})
	}
	if b, ok := num(p["beneficiary_certificates_30d"]); ok && b >= IssuanceBeneficiaryBurstMin {
		score += 0.25
		f = append(f, Factor{"beneficiary_issuance_burst", "beneficiary received many certificates in 30d", 0.25})
	}
	value, _ := num(p["certificate_value_ngn"])
	approvals, hasApprovals := num(p["approvals"])
	if !hasApprovals {
		approvals = 1
	}
	if value >= HighValueSingleApprovalNgn && approvals < 2 {
		score += 0.20
		f = append(f, Factor{"high_value_single_approval", "high-value certificate approved by a single officer — four-eyes required", 0.20})
	}
	if len(history) == 0 && !hasMean {
		f = append(f, Factor{"history_unavailable", "no officer issuance baseline — velocity signal skipped", 0})
	}
	return mkresult(score, f)
}

// Channel — USSD / feature-phone channel fraud.
func Channel(p Payload, _ []HistoryEvent, _ time.Time) Result {
	f := []Factor{}
	score := 0.05
	simHours, hasSim := num(p["sim_change_hours"])
	if p["channel"] == "ussd" && hasSim && simHours < 24 {
		score += 0.40
		f = append(f, Factor{"ussd_after_sim_change", "USSD session <24h after SIM swap/change", 0.40})
	}
	amt, _ := num(p["amount_ngn"])
	if hasSim && simHours >= 24 && simHours < SimStepupWindowHours && amt >= SimStepupAmountMinNgn {
		score += 0.30
		f = append(f, Factor{"sim_age_high_value_stepup", "high-value transaction within the SIM-age step-up window", 0.30})
	}
	if truthy(p["imei_is_new"]) && amt > 100_000 {
		score += 0.25
		f = append(f, Factor{"new_imei_high_value", "high-value transaction from an unrecognised handset", 0.25})
	}
	if truthy(p["alert_integrity_fail"]) {
		score += 0.35
		f = append(f, Factor{"bank_alert_integrity_fail", "SMS alert failed authenticity check — fake-alert pattern", 0.35})
	}
	if t, ok := num(p["phone_tenure_days"]); ok && t < 30 {
		score += 0.15
		f = append(f, Factor{"low_phone_tenure", "number tenure under 30d", 0.15})
	}
	return mkresult(score, f)
}

// GhostPayroll — ghost workers / benefit diversion.
func GhostPayroll(p Payload, history []HistoryEvent, _ time.Time) Result {
	f := []Factor{}
	score := 0.05
	rows := payloadOf(history)
	if account := strOf(p["bank_account_hash"]); account != "" {
		sharing := map[string]bool{}
		for _, r := range rows {
			if r["bank_account_hash"] == account && r["employee_id"] != p["employee_id"] {
				sharing[strOf(r["employee_id"])] = true
			}
		}
		if len(sharing) >= GhostSharedAccountMin-1 && len(sharing) > 0 {
			score += 0.40
			f = append(f, Factor{"shared_salary_account", "salary account shared with other 'employees'", 0.40})
		}
	}
	if nid := strOf(p["identity_hash"]); nid != "" {
		dupes := map[string]bool{}
		for _, r := range rows {
			if r["identity_hash"] == nid && r["employee_id"] != p["employee_id"] {
				dupes[strOf(r["employee_id"])] = true
			}
		}
		if len(dupes) > 0 {
			score += 0.45
			f = append(f, Factor{"duplicate_identity", "identity hash appears under other payroll ids", 0.45})
		}
	}
	if truthy(p["account_dormant_except_salary"]) {
		score += 0.15
		f = append(f, Factor{"salary_only_account", "account shows salary credits but no living-pattern spend", 0.15})
	}
	if truthy(p["deceased_registry_hit"]) {
		score += 0.65
		f = append(f, Factor{"deceased_registry_hit", "identity matched a death registry record", 0.65})
	}
	return mkresult(score, f)
}

// Subsidy — agricultural subsidy / phantom-farmer fraud.
func Subsidy(p Payload, history []HistoryEvent, _ time.Time) Result {
	f := []Factor{}
	score := 0.05
	hectares, _ := num(p["farm_hectares"])
	claim, _ := num(p["claim_ngn"])
	if hectares > 0 && claim/hectares > SubsidyMaxNgnPerHectare {
		score += 0.30
		f = append(f, Factor{"implausible_claim_ratio", "claim per hectare above plausibility ceiling", 0.30})
	}
	if truthy(p["farm_geocode_outside_lga"]) {
		score += 0.25
		f = append(f, Factor{"farm_outside_lga", "farm geolocation falls outside the registered LGA", 0.25})
	}
	rows := payloadOf(history)
	if nid := strOf(p["identity_hash"]); nid != "" {
		dupes := map[string]bool{}
		for _, r := range rows {
			if r["identity_hash"] == nid && r["claim_id"] != p["claim_id"] {
				dupes[strOf(r["claim_id"])] = true
			}
		}
		if len(dupes) > 0 {
			score += 0.35
			f = append(f, Factor{"duplicate_claimant", "identity appears on other claims", 0.35})
		}
	}
	if truthy(p["no_field_activity_evidence"]) {
		score += 0.20
		f = append(f, Factor{"no_field_activity", "no planting/input-purchase evidence for the claimed acreage", 0.20})
	}
	return mkresult(score, f)
}

// Detectors maps the canonical detector names to their implementations.
var Detectors = map[string]Detector{
	"app_scam":      AppScam,
	"mule":          Mule,
	"agent":         Agent,
	"loan_stacking": LoanStacking,
	"issuance":      Issuance,
	"channel":       Channel,
	"ghost_payroll": GhostPayroll,
	"subsidy":       Subsidy,
}
