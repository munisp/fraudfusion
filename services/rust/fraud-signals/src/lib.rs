//! Fraud signal detectors — Rust port.
//!
//! Line-for-line port of `services/python/fraud-signals/detectors.py`. All
//! four language ports (Python, TypeScript, Go, Rust) are pinned to the same
//! parity contract:
//! `services/python/fraud-signals/fixtures/detector_cases.json`.
//! Any threshold change must land in all ports and regenerate the fixture.

use chrono::{DateTime, Duration, Utc};
use serde_json::{Map, Value};
use std::collections::HashSet;

pub const BLOCK_MIN: f64 = 0.70;
pub const REVIEW_MIN: f64 = 0.35;

pub const STRUCTURING_BELOW_NGN: f64 = 50_000.0;
pub const AGENT_VELOCITY_SPIKE: f64 = 3.0;
pub const LOAN_STACKING_LENDERS: usize = 3;
pub const LOAN_STACKING_WINDOW_DAYS: i64 = 14;
pub const MULE_PASS_THROUGH_MIN: f64 = 0.85;
pub const MULE_FAN_IN_MIN: usize = 5;
pub const GHOST_SHARED_ACCOUNT_MIN: usize = 2;
pub const ISSUANCE_OFFICER_Z: f64 = 3.0;
pub const SUBSIDY_MAX_NGN_PER_HECTARE: f64 = 150_000.0;

pub type Payload = Map<String, Value>;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct HistoryEvent {
    pub payload: Payload,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Factor {
    pub code: String,
    pub detail: String,
    pub weight: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DetectorResult {
    pub score: f64,
    pub verdict: String,
    pub factors: Vec<Factor>,
}

fn verdict_of(score: f64) -> String {
    if score >= BLOCK_MIN {
        "block".into()
    } else if score >= REVIEW_MIN {
        "review".into()
    } else {
        "clear".into()
    }
}

fn cap1(score: f64) -> f64 {
    (score.min(1.0) * 1000.0).round() / 1000.0
}

fn mkresult(score: f64, factors: Vec<Factor>) -> DetectorResult {
    let s = cap1(score);
    DetectorResult { score: s, verdict: verdict_of(s), factors }
}

fn num(v: Option<&Value>) -> Option<f64> {
    v.and_then(|v| v.as_f64())
}

fn truthy(v: Option<&Value>) -> bool {
    v.and_then(|v| v.as_bool()).unwrap_or(false)
}

fn s(v: Option<&Value>) -> &str {
    v.and_then(|v| v.as_str()).unwrap_or("")
}

fn window_days(events: &[HistoryEvent], days: i64, now: DateTime<Utc>) -> Vec<&HistoryEvent> {
    let cutoff = now - Duration::days(days);
    events
        .iter()
        .filter(|e| match DateTime::parse_from_rfc3339(&e.created_at) {
            Ok(t) => t.with_timezone(&Utc) >= cutoff,
            Err(_) => true, // unparseable timestamps are kept, like the Python port
        })
        .collect()
}

fn factor(code: &str, detail: &str, weight: f64) -> Factor {
    Factor { code: code.into(), detail: detail.into(), weight }
}

/// 1. Authorized-push-payment / social-engineering scam.
pub fn app_scam(p: &Payload, history: &[HistoryEvent], _now: DateTime<Utc>) -> DetectorResult {
    let mut f = vec![];
    let mut score = 0.05;
    if truthy(p.get("payee_is_new")) {
        score += 0.20;
        f.push(factor("new_payee", "first-ever transfer to this payee", 0.20));
    }
    if let Some(h) = num(p.get("payee_age_hours")) {
        if h < 1.0 {
            score += 0.15;
            f.push(factor("payee_just_added", "payee added <1h before transfer", 0.15));
        }
    }
    let avg = num(p.get("customer_avg_amount"));
    let amount = num(p.get("amount_ngn")).unwrap_or(0.0);
    if let Some(a) = avg {
        if a != 0.0 && amount > 8.0 * a {
            score += 0.20;
            f.push(factor("amount_outlier", "amount >8x customer average", 0.20));
        }
    }
    if let Some(sec) = num(p.get("session_seconds")) {
        if sec < 45.0 {
            score += 0.15;
            f.push(factor("rushed_session", "transfer completed in <45s — coercion pattern", 0.15));
        }
    }
    if truthy(p.get("device_is_new")) {
        score += 0.10;
        f.push(factor("new_device", "unrecognised device", 0.10));
    }
    if let Some(m) = num(p.get("payee_mule_score")) {
        if m >= REVIEW_MIN {
            score += 0.25;
            f.push(factor("payee_mule_like", "payee mule score elevated", 0.25));
        }
    }
    if history.is_empty() && avg.is_none() {
        f.push(factor("history_unavailable",
                      "no spending history supplied — amount-outlier signal skipped", 0.0));
    }
    mkresult(score, f)
}

/// 2. Money-mule account behaviour.
pub fn mule(p: &Payload, history: &[HistoryEvent], now: DateTime<Utc>) -> DetectorResult {
    let mut f = vec![];
    let mut score = 0.05;
    let txs = window_days(history, 7, now);
    let mut in_sum = 0.0;
    let mut out_sum = 0.0;
    let mut senders: HashSet<&str> = HashSet::new();
    for e in &txs {
        let t = &e.payload;
        let amt = num(t.get("amount_ngn")).unwrap_or(0.0);
        match s(t.get("direction")) {
            "in" => {
                in_sum += amt;
                let cp = s(t.get("counterparty"));
                if !cp.is_empty() {
                    senders.insert(cp);
                }
            }
            "out" => out_sum += amt,
            _ => {}
        }
    }
    if in_sum > 0.0 && out_sum / in_sum >= MULE_PASS_THROUGH_MIN {
        score += 0.35;
        f.push(factor("pass_through", "most inbound funds forwarded within the window", 0.35));
    }
    if senders.len() >= MULE_FAN_IN_MIN {
        score += 0.25;
        f.push(factor("fan_in", "many distinct senders in 7d", 0.25));
    }
    if let Some(d) = num(p.get("dormant_days_before")) {
        if d >= 90.0 && !txs.is_empty() {
            score += 0.20;
            f.push(factor("dormancy_burst", "long dormancy then sudden activity", 0.20));
        }
    }
    if let Some(n) = num(p.get("shared_device_accounts")) {
        if n >= 3.0 {
            score += 0.20;
            f.push(factor("shared_device_cluster", "device shared with several accounts", 0.20));
        }
    }
    if txs.is_empty() {
        f.push(factor("history_unavailable",
                      "no recent transfer events — behavioural signals skipped", 0.0));
    }
    mkresult(score, f)
}

/// 3. Agent-banking / mobile-money agent fraud.
pub fn agent(p: &Payload, history: &[HistoryEvent], now: DateTime<Utc>) -> DetectorResult {
    let mut f = vec![];
    let mut score = 0.05;
    let txs = window_days(history, 1, now);
    let baseline = num(p.get("baseline_tx_per_day")).unwrap_or(0.0);
    if baseline > 0.0 && (txs.len() as f64) > AGENT_VELOCITY_SPIKE * baseline {
        score += 0.25;
        f.push(factor("velocity_spike", "transaction count far above baseline", 0.25));
    }
    let near = txs
        .iter()
        .filter(|e| {
            let t = &e.payload;
            s(t.get("type")) == "cash_out"
                && matches!(num(t.get("amount_ngn")),
                    Some(a) if a >= STRUCTURING_BELOW_NGN * 0.9 && a < STRUCTURING_BELOW_NGN)
        })
        .count();
    if near >= 3 {
        score += 0.35;
        f.push(factor("structuring",
                      "cash-outs clustered just below the reporting threshold", 0.35));
    }
    if let Some(d) = num(p.get("distance_from_registered_km")) {
        if d > 5.0 {
            score += 0.20;
            f.push(factor("off_location", "operating far from registered location", 0.20));
        }
    }
    if let Some(m) = num(p.get("float_mismatch_ngn")) {
        if m.abs() > 100_000.0 {
            score += 0.25;
            f.push(factor("float_diversion", "float/ledger mismatch", 0.25));
        }
    }
    if txs.is_empty() && baseline == 0.0 {
        f.push(factor("history_unavailable",
                      "no agent activity history — velocity/structuring skipped", 0.0));
    }
    mkresult(score, f)
}

/// 4. Cross-lender loan stacking / bust-out.
pub fn loan_stacking(p: &Payload, history: &[HistoryEvent], now: DateTime<Utc>) -> DetectorResult {
    let mut f = vec![];
    let mut score = 0.05;
    let apps = window_days(history, LOAN_STACKING_WINDOW_DAYS, now);
    let mut lenders: HashSet<&str> = HashSet::new();
    for e in &apps {
        let l = s(e.payload.get("lender_id"));
        if !l.is_empty() {
            lenders.insert(l);
        }
    }
    if lenders.len() >= LOAN_STACKING_LENDERS {
        score += 0.40;
        f.push(factor("multi_lender_stack", "applications at many lenders in the window", 0.40));
    }
    if truthy(p.get("first_payment_default")) {
        score += 0.35;
        f.push(factor("first_payment_default",
                      "prior loan defaulted on first payment (bust-out signal)", 0.35));
    }
    if truthy(p.get("thin_file")) {
        score += 0.10;
        f.push(factor("thin_file", "no credit history — synthetic-identity risk", 0.10));
    }
    if let Some(d) = num(p.get("document_authenticity_score")) {
        if d >= 50.0 {
            score += 0.25;
            f.push(factor("forged_income_docs",
                          "document engine authenticity score elevated (forgery suspected)", 0.25));
        }
    }
    mkresult(score, f)
}

/// 5. Insider-issued GENUINE documents (registry issuance anomaly).
pub fn issuance(p: &Payload, history: &[HistoryEvent], now: DateTime<Utc>) -> DetectorResult {
    let mut f = vec![];
    let mut score = 0.05;
    let officer_today = window_days(history, 1, now).len() as f64;
    let peer_mean = num(p.get("peer_officer_mean_per_day"));
    let peer_std = num(p.get("peer_officer_std_per_day"));
    if let (Some(mean), Some(std)) = (peer_mean, peer_std) {
        if std != 0.0 {
            let z = (officer_today - mean) / std.max(0.1);
            if z >= ISSUANCE_OFFICER_Z {
                score += 0.35;
                f.push(factor("officer_velocity_outlier",
                              "officer issuance velocity far above peers", 0.35));
            }
        }
    }
    if let Some(h) = num(p.get("issued_hour_local")) {
        if h < 6.0 || h >= 22.0 {
            score += 0.15;
            f.push(factor("after_hours_issuance", "issued outside business hours", 0.15));
        }
    }
    if truthy(p.get("sequence_gap")) {
        score += 0.20;
        f.push(factor("certificate_sequence_gap",
                      "certificate number falls in a skipped sequence block", 0.20));
    }
    if truthy(p.get("registry_survey_mismatch")) {
        score += 0.30;
        f.push(factor("registry_survey_mismatch",
                      "registry record's survey hash != physical survey plan", 0.30));
    }
    if history.is_empty() && peer_mean.is_none() {
        f.push(factor("history_unavailable",
                      "no officer issuance baseline — velocity signal skipped", 0.0));
    }
    mkresult(score, f)
}

/// 6. USSD / feature-phone channel fraud.
pub fn channel(p: &Payload, _history: &[HistoryEvent], _now: DateTime<Utc>) -> DetectorResult {
    let mut f = vec![];
    let mut score = 0.05;
    if s(p.get("channel")) == "ussd" {
        if let Some(h) = num(p.get("sim_change_hours")) {
            if h < 24.0 {
                score += 0.40;
                f.push(factor("ussd_after_sim_change",
                              "USSD session <24h after SIM swap/change", 0.40));
            }
        }
    }
    if truthy(p.get("imei_is_new")) && num(p.get("amount_ngn")).unwrap_or(0.0) > 100_000.0 {
        score += 0.25;
        f.push(factor("new_imei_high_value",
                      "high-value transaction from an unrecognised handset", 0.25));
    }
    if truthy(p.get("alert_integrity_fail")) {
        score += 0.35;
        f.push(factor("bank_alert_integrity_fail",
                      "SMS alert failed authenticity check — fake-alert pattern", 0.35));
    }
    if let Some(t) = num(p.get("phone_tenure_days")) {
        if t < 30.0 {
            score += 0.15;
            f.push(factor("low_phone_tenure", "number tenure under 30d", 0.15));
        }
    }
    mkresult(score, f)
}

/// 7. Ghost workers / benefit diversion.
pub fn ghost_payroll(p: &Payload, history: &[HistoryEvent], _now: DateTime<Utc>) -> DetectorResult {
    let mut f = vec![];
    let mut score = 0.05;
    let rows: Vec<&Payload> = history.iter().map(|e| &e.payload).collect();
    let account = s(p.get("bank_account_hash"));
    if !account.is_empty() {
        let mut sharing: HashSet<&str> = HashSet::new();
        for r in &rows {
            if s(r.get("bank_account_hash")) == account
                && r.get("employee_id") != p.get("employee_id")
            {
                sharing.insert(s(r.get("employee_id")));
            }
        }
        if sharing.len() >= GHOST_SHARED_ACCOUNT_MIN - 1 && !sharing.is_empty() {
            score += 0.40;
            f.push(factor("shared_salary_account",
                          "salary account shared with other 'employees'", 0.40));
        }
    }
    let nid = s(p.get("identity_hash"));
    if !nid.is_empty() {
        let mut dupes: HashSet<&str> = HashSet::new();
        for r in &rows {
            if s(r.get("identity_hash")) == nid && r.get("employee_id") != p.get("employee_id") {
                dupes.insert(s(r.get("employee_id")));
            }
        }
        if !dupes.is_empty() {
            score += 0.45;
            f.push(factor("duplicate_identity",
                          "identity hash appears under other payroll ids", 0.45));
        }
    }
    if truthy(p.get("account_dormant_except_salary")) {
        score += 0.15;
        f.push(factor("salary_only_account",
                      "account shows salary credits but no living-pattern spend", 0.15));
    }
    if truthy(p.get("deceased_registry_hit")) {
        score += 0.65;
        f.push(factor("deceased_registry_hit", "identity matched a death registry record", 0.65));
    }
    mkresult(score, f)
}

/// 8. Agricultural subsidy / phantom-farmer fraud.
pub fn subsidy(p: &Payload, history: &[HistoryEvent], _now: DateTime<Utc>) -> DetectorResult {
    let mut f = vec![];
    let mut score = 0.05;
    let hectares = num(p.get("farm_hectares")).unwrap_or(0.0);
    let claim = num(p.get("claim_ngn")).unwrap_or(0.0);
    if hectares > 0.0 && claim / hectares > SUBSIDY_MAX_NGN_PER_HECTARE {
        score += 0.30;
        f.push(factor("implausible_claim_ratio",
                      "claim per hectare above plausibility ceiling", 0.30));
    }
    if truthy(p.get("farm_geocode_outside_lga")) {
        score += 0.25;
        f.push(factor("farm_outside_lga",
                      "farm geolocation falls outside the registered LGA", 0.25));
    }
    let rows: Vec<&Payload> = history.iter().map(|e| &e.payload).collect();
    let nid = s(p.get("identity_hash"));
    if !nid.is_empty() {
        let mut dupes: HashSet<&str> = HashSet::new();
        for r in &rows {
            if s(r.get("identity_hash")) == nid && r.get("claim_id") != p.get("claim_id") {
                dupes.insert(s(r.get("claim_id")));
            }
        }
        if !dupes.is_empty() {
            score += 0.35;
            f.push(factor("duplicate_claimant", "identity appears on other claims", 0.35));
        }
    }
    if truthy(p.get("no_field_activity_evidence")) {
        score += 0.20;
        f.push(factor("no_field_activity",
                      "no planting/input-purchase evidence for the claimed acreage", 0.20));
    }
    mkresult(score, f)
}

/// Look up a detector by canonical name.
pub fn detect(
    name: &str, p: &Payload, history: &[HistoryEvent], now: DateTime<Utc>,
) -> Option<DetectorResult> {
    let f: fn(&Payload, &[HistoryEvent], DateTime<Utc>) -> DetectorResult = match name {
        "app_scam" => app_scam,
        "mule" => mule,
        "agent" => agent,
        "loan_stacking" => loan_stacking,
        "issuance" => issuance,
        "channel" => channel,
        "ghost_payroll" => ghost_payroll,
        "subsidy" => subsidy,
        _ => return None,
    };
    Some(f(p, history, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::path::PathBuf;

    #[derive(Deserialize)]
    struct Expected {
        score: f64,
        verdict: String,
        factor_codes: Vec<String>,
    }

    #[derive(Deserialize)]
    struct Case {
        detector: String,
        payload: Payload,
        history: Vec<HistoryEvent>,
        expected: Expected,
    }

    #[derive(Deserialize)]
    struct Fixture {
        generated_at: String,
        cases: Vec<Case>,
    }

    /// Parity contract: reproduce the Python reference exactly.
    #[test]
    fn parity_with_python_reference() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../python/fraud-signals/fixtures/detector_cases.json");
        let raw = std::fs::read_to_string(&path).expect("read fixture");
        let fx: Fixture = serde_json::from_str(&raw).expect("decode fixture");
        let now = DateTime::parse_from_rfc3339(&fx.generated_at)
            .expect("parse generated_at")
            .with_timezone(&Utc);
        for (i, c) in fx.cases.iter().enumerate() {
            let r = detect(&c.detector, &c.payload, &c.history, now)
                .unwrap_or_else(|| panic!("case {i}: unknown detector {}", c.detector));
            assert_eq!(r.score, c.expected.score, "case {i} score");
            assert_eq!(r.verdict, c.expected.verdict, "case {i} verdict");
            let codes: Vec<&str> = r.factors.iter().map(|f| f.code.as_str()).collect();
            assert_eq!(codes, c.expected.factor_codes, "case {i} factor codes");
        }
    }
}
