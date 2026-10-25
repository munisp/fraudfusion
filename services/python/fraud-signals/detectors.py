"""Eight deterministic fraud-signal detectors for developing-market patterns.

Design contract (shared across all eight):
  * pure functions over (payload, history) -> (score 0..1, verdict, factors)
  * verdict bands: score >= BLOCK_MIN -> "block", >= REVIEW_MIN -> "review",
    else "clear"
  * every factor is {code, detail, weight} — explainable, additive, capped
  * NO signal is fabricated: when history is missing the factor is skipped
    and the factor list says so ("history_unavailable" note), never assumed

Detectors:
  1. app_scam        — authorized-push-payment / social-engineering scams
  2. mule            — money-mule account behaviour
  3. agent           — agent-banking / mobile-money agent fraud
  4. loan_stacking   — cross-lender loan stacking & bust-out
  5. issuance        — insider-issued GENUINE documents (registry anomaly)
  6. channel         — USSD / feature-phone channel fraud
  7. ghost_payroll   — ghost workers / benefit diversion
  8. subsidy         — agricultural subsidy / phantom-farmer fraud
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

BLOCK_MIN = 0.70
REVIEW_MIN = 0.35

# Nigeria-specific calibration constants (documented, tunable via payload
# overrides where noted).
STRUCTURING_BELOW_NGN = 50_000.0       # common reporting-threshold dodge
AGENT_VELOCITY_SPIKE = 3.0             # x baseline tx/day
LOAN_STACKING_LENDERS = 3              # distinct lenders in window
LOAN_STACKING_WINDOW_DAYS = 14
MULE_PASS_THROUGH_MIN = 0.85           # in->out ratio within 72h
MULE_FAN_IN_MIN = 5                    # distinct senders in window
MULE_HIGH_RISK_FAN_IN_MIN = 3          # distinct HIGH-RISK senders in window
GHOST_SHARED_ACCOUNT_MIN = 2           # employees paid into one account
ISSUANCE_OFFICER_Z = 3.0               # officer velocity z-score
ISSUANCE_BENEFICIARY_BURST_MIN = 3     # certs to one beneficiary in 30d
HIGH_VALUE_SINGLE_APPROVAL_NGN = 10_000_000  # four-eyes threshold
SUBSIDY_MAX_NGN_PER_HECTARE = 150_000  # plausibility ceiling
SIM_STEPUP_WINDOW_HOURS = 168          # SIM-age step-up window (7d)
SIM_STEPUP_AMOUNT_MIN_NGN = 100_000    # step-up applies to high value


def _verdict(score: float) -> str:
    return "block" if score >= BLOCK_MIN else ("review" if score >= REVIEW_MIN
                                               else "clear")


def _cap(score: float) -> float:
    return round(min(score, 1.0), 3)


def _parse_ts(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _window(events: list[dict], days: int, now: Optional[datetime] = None):
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    return [e for e in events
            if (_parse_ts(e["created_at"]) or now) >= cutoff]


# ---------------------------------------------------------------------------
# 1. APP / social-engineering scam detection
# ---------------------------------------------------------------------------

def app_scam(payload: dict[str, Any], history: list[dict]) -> tuple[float, str, list[dict]]:
    """Context: payee novelty, amount vs habit, session haste, device age,
    payee mule score (fed by the mule detector via the mesh)."""
    f: list[dict] = []
    score = 0.05
    if payload.get("payee_is_new"):
        score += 0.20
        f.append({"code": "new_payee", "detail": "first-ever transfer to this payee", "weight": 0.20})
    hours = payload.get("payee_age_hours")
    if hours is not None and hours < 1:
        score += 0.15
        f.append({"code": "payee_just_added", "detail": "payee added <1h before transfer", "weight": 0.15})
    avg = payload.get("customer_avg_amount")
    amount = float(payload.get("amount_ngn") or 0)
    if avg and amount > 8 * float(avg):
        score += 0.20
        f.append({"code": "amount_outlier", "detail": f"amount {amount:.0f} >8x customer average", "weight": 0.20})
    if payload.get("session_seconds") is not None and payload["session_seconds"] < 45:
        score += 0.15
        f.append({"code": "rushed_session", "detail": "transfer completed in <45s — coercion pattern", "weight": 0.15})
    if payload.get("device_is_new"):
        score += 0.10
        f.append({"code": "new_device", "detail": "unrecognised device", "weight": 0.10})
    mule = payload.get("payee_mule_score")
    if mule is not None and float(mule) >= REVIEW_MIN:
        score += 0.25
        f.append({"code": "payee_mule_like", "detail": f"payee mule score {mule}", "weight": 0.25})
    if not history and payload.get("customer_avg_amount") is None:
        f.append({"code": "history_unavailable", "detail": "no spending history supplied — amount-outlier signal skipped", "weight": 0.0})
    return _cap(score), _verdict(_cap(score)), f


# ---------------------------------------------------------------------------
# 2. Money-mule behaviour
# ---------------------------------------------------------------------------

def mule(payload: dict[str, Any], history: list[dict]) -> tuple[float, str, list[dict]]:
    """History: the account's recent transfer events (in/out, counterparty)."""
    f: list[dict] = []
    score = 0.05
    txs = [e["payload"] for e in _window(history, 7)]
    incoming = [t for t in txs if t.get("direction") == "in"]
    outgoing = [t for t in txs if t.get("direction") == "out"]
    in_sum = sum(float(t.get("amount_ngn") or 0) for t in incoming)
    out_sum = sum(float(t.get("amount_ngn") or 0) for t in outgoing)
    if in_sum > 0 and out_sum / in_sum >= MULE_PASS_THROUGH_MIN:
        score += 0.35
        f.append({"code": "pass_through", "detail": f"{out_sum/in_sum:.0%} of inbound funds forwarded within the window", "weight": 0.35})
    senders = {t.get("counterparty") for t in incoming if t.get("counterparty")}
    if len(senders) >= MULE_FAN_IN_MIN:
        score += 0.25
        f.append({"code": "fan_in", "detail": f"{len(senders)} distinct senders in 7d", "weight": 0.25})
    # Sender-risk propagation: even a SMALL fan-in is damning when the
    # senders themselves score high (each sender's own mule/scam score is
    # annotated onto the event by the caller — mesh composition makes this
    # cross-account rather than single-account detection).
    risky = {t.get("counterparty") for t in incoming
             if t.get("counterparty")
             and float(t.get("counterparty_risk") or 0) >= REVIEW_MIN}
    if len(risky) >= MULE_HIGH_RISK_FAN_IN_MIN:
        score += 0.30
        f.append({"code": "high_risk_fan_in",
                  "detail": f"{len(risky)} distinct senders with elevated own-risk scores",
                  "weight": 0.30})
    if payload.get("dormant_days_before") is not None and payload["dormant_days_before"] >= 90 and txs:
        score += 0.20
        f.append({"code": "dormancy_burst", "detail": f"{payload['dormant_days_before']}d dormant, sudden activity", "weight": 0.20})
    if payload.get("shared_device_accounts") is not None and payload["shared_device_accounts"] >= 3:
        score += 0.20
        f.append({"code": "shared_device_cluster", "detail": f"device shared with {payload['shared_device_accounts']} accounts", "weight": 0.20})
    if not txs:
        f.append({"code": "history_unavailable", "detail": "no recent transfer events — behavioural signals skipped", "weight": 0.0})
    return _cap(score), _verdict(_cap(score)), f


# ---------------------------------------------------------------------------
# 3. Agent-banking / mobile-money agent fraud
# ---------------------------------------------------------------------------

def agent(payload: dict[str, Any], history: list[dict]) -> tuple[float, str, list[dict]]:
    """History: the agent's transaction events (amount, type, location)."""
    f: list[dict] = []
    score = 0.05
    txs = [e["payload"] for e in _window(history, 1)]
    baseline = float(payload.get("baseline_tx_per_day") or 0)
    if baseline > 0 and len(txs) > AGENT_VELOCITY_SPIKE * baseline:
        score += 0.25
        f.append({"code": "velocity_spike", "detail": f"{len(txs)} tx today vs {baseline:.0f} baseline", "weight": 0.25})
    cashouts = [float(t.get("amount_ngn") or 0) for t in txs if t.get("type") == "cash_out"]
    near = [a for a in cashouts if STRUCTURING_BELOW_NGN * 0.9 <= a < STRUCTURING_BELOW_NGN]
    if len(near) >= 3:
        score += 0.35
        f.append({"code": "structuring", "detail": f"{len(near)} cash-outs clustered just below N{STRUCTURING_BELOW_NGN:,.0f}", "weight": 0.35})
    dist = payload.get("distance_from_registered_km")
    if dist is not None and float(dist) > 5:
        score += 0.20
        f.append({"code": "off_location", "detail": f"operating {dist}km from registered location", "weight": 0.20})
    if payload.get("float_mismatch_ngn") is not None and abs(float(payload["float_mismatch_ngn"])) > 100_000:
        score += 0.25
        f.append({"code": "float_diversion", "detail": f"float/ledger mismatch N{payload['float_mismatch_ngn']:,.0f}", "weight": 0.25})
    if not txs and baseline == 0:
        f.append({"code": "history_unavailable", "detail": "no agent activity history — velocity/structuring skipped", "weight": 0.0})
    return _cap(score), _verdict(_cap(score)), f


# ---------------------------------------------------------------------------
# 4. Loan stacking / bust-out
# ---------------------------------------------------------------------------

def loan_stacking(payload: dict[str, Any], history: list[dict]) -> tuple[float, str, list[dict]]:
    """History: the applicant's loan-application events across lenders."""
    f: list[dict] = []
    score = 0.05
    apps = [e["payload"] for e in _window(history, LOAN_STACKING_WINDOW_DAYS)]
    lenders = {a.get("lender_id") for a in apps if a.get("lender_id")}
    if len(lenders) >= LOAN_STACKING_LENDERS:
        score += 0.40
        f.append({"code": "multi_lender_stack", "detail": f"applications at {len(lenders)} lenders in {LOAN_STACKING_WINDOW_DAYS}d", "weight": 0.40})
    if payload.get("first_payment_default"):
        score += 0.35
        f.append({"code": "first_payment_default", "detail": "prior loan defaulted on first payment (bust-out signal)", "weight": 0.35})
    if payload.get("thin_file"):
        score += 0.10
        f.append({"code": "thin_file", "detail": "no credit history — synthetic-identity risk", "weight": 0.10})
    doc_score = payload.get("document_authenticity_score")
    if doc_score is not None and float(doc_score) >= 50:
        score += 0.25
        f.append({"code": "forged_income_docs", "detail": f"document engine authenticity score {doc_score} (forgery suspected)", "weight": 0.25})
    return _cap(score), _verdict(_cap(score)), f


# ---------------------------------------------------------------------------
# 5. Insider-issued genuine documents (registry issuance anomaly)
# ---------------------------------------------------------------------------

def issuance(payload: dict[str, Any], history: list[dict]) -> tuple[float, str, list[dict]]:
    """A genuine document can still be fraudulently ISSUED. History: the
    issuing officer's issuance events; payload carries the record under
    review plus peer-officer baselines."""
    f: list[dict] = []
    score = 0.05
    officer_today = len(_window(history, 1))
    peer_mean = payload.get("peer_officer_mean_per_day")
    peer_std = payload.get("peer_officer_std_per_day")
    if peer_mean is not None and peer_std:
        z = (officer_today - float(peer_mean)) / max(float(peer_std), 0.1)
        if z >= ISSUANCE_OFFICER_Z:
            score += 0.35
            f.append({"code": "officer_velocity_outlier", "detail": f"officer issued {officer_today} today (z={z:.1f} vs peers)", "weight": 0.35})
    hour = payload.get("issued_hour_local")
    if hour is not None and (int(hour) < 6 or int(hour) >= 22):
        score += 0.15
        f.append({"code": "after_hours_issuance", "detail": f"issued at {hour}:00 local", "weight": 0.15})
    if payload.get("sequence_gap"):
        score += 0.20
        f.append({"code": "certificate_sequence_gap", "detail": "certificate number falls in a skipped sequence block", "weight": 0.20})
    if payload.get("registry_survey_mismatch"):
        score += 0.30
        f.append({"code": "registry_survey_mismatch", "detail": "registry record's survey hash != physical survey plan", "weight": 0.30})
    # Beneficiary-side anomaly: a slow insider evades officer velocity, but
    # the RECEIVER can't hide accumulating certificates fast (land-grab via
    # patient insider).
    burst = payload.get("beneficiary_certificates_30d")
    if burst is not None and int(burst) >= ISSUANCE_BENEFICIARY_BURST_MIN:
        score += 0.25
        f.append({"code": "beneficiary_issuance_burst",
                  "detail": f"beneficiary received {burst} certificates in 30d",
                  "weight": 0.25})
    # Four-eyes: a single approval on a high-value certificate is a control
    # violation regardless of officer velocity.
    value = float(payload.get("certificate_value_ngn") or 0)
    if value >= HIGH_VALUE_SINGLE_APPROVAL_NGN and int(payload.get("approvals") or 1) < 2:
        score += 0.20
        f.append({"code": "high_value_single_approval",
                  "detail": f"certificate value N{value:,.0f} approved by a single officer — four-eyes required",
                  "weight": 0.20})
    if not history and peer_mean is None:
        f.append({"code": "history_unavailable", "detail": "no officer issuance baseline — velocity signal skipped", "weight": 0.0})
    return _cap(score), _verdict(_cap(score)), f


# ---------------------------------------------------------------------------
# 6. USSD / feature-phone channel fraud
# ---------------------------------------------------------------------------

def channel(payload: dict[str, Any], history: list[dict]) -> tuple[float, str, list[dict]]:
    f: list[dict] = []
    score = 0.05
    sim_hours = payload.get("sim_change_hours")
    if payload.get("channel") == "ussd" and sim_hours is not None \
            and float(sim_hours) < 24:
        score += 0.40
        f.append({"code": "ussd_after_sim_change", "detail": "USSD session <24h after SIM swap/change", "weight": 0.40})
    # SIM-age step-up: the 24h hard cliff let patient swappers wait a day.
    # High-value transactions within a WEEK of a SIM change still escalate —
    # scrutiny scales with SIM age and amount, not a fixed cliff.
    if sim_hours is not None and 24 <= float(sim_hours) < SIM_STEPUP_WINDOW_HOURS \
            and float(payload.get("amount_ngn") or 0) >= SIM_STEPUP_AMOUNT_MIN_NGN:
        score += 0.30
        f.append({"code": "sim_age_high_value_stepup",
                  "detail": f"high-value transaction {float(sim_hours):.0f}h after SIM change (step-up window {SIM_STEPUP_WINDOW_HOURS}h)",
                  "weight": 0.30})
    if payload.get("imei_is_new") and float(payload.get("amount_ngn") or 0) > 100_000:
        score += 0.25
        f.append({"code": "new_imei_high_value", "detail": "high-value transaction from an unrecognised handset", "weight": 0.25})
    if payload.get("alert_integrity_fail"):
        score += 0.35
        f.append({"code": "bank_alert_integrity_fail", "detail": "SMS alert failed authenticity check — fake-alert pattern", "weight": 0.35})
    tenure_days = payload.get("phone_tenure_days")
    if tenure_days is not None and int(tenure_days) < 30:
        score += 0.15
        f.append({"code": "low_phone_tenure", "detail": f"number tenure {tenure_days}d", "weight": 0.15})
    return _cap(score), _verdict(_cap(score)), f


# ---------------------------------------------------------------------------
# 7. Ghost workers / benefit diversion
# ---------------------------------------------------------------------------

def ghost_payroll(payload: dict[str, Any], history: list[dict]) -> tuple[float, str, list[dict]]:
    """Payload: the payroll row under review. History: the employer's payroll
    rows (used for shared-account / duplicate-identity detection)."""
    f: list[dict] = []
    score = 0.05
    rows = [e["payload"] for e in history]
    account = payload.get("bank_account_hash")
    if account:
        sharing = {r.get("employee_id") for r in rows
                   if r.get("bank_account_hash") == account
                   and r.get("employee_id") != payload.get("employee_id")}
        if len(sharing) >= GHOST_SHARED_ACCOUNT_MIN - 1 and sharing:
            score += 0.40
            f.append({"code": "shared_salary_account", "detail": f"salary account shared with {len(sharing)} other 'employees'", "weight": 0.40})
    nid = payload.get("identity_hash")
    if nid:
        dupes = {r.get("employee_id") for r in rows
                 if r.get("identity_hash") == nid
                 and r.get("employee_id") != payload.get("employee_id")}
        if dupes:
            score += 0.45
            f.append({"code": "duplicate_identity", "detail": f"identity hash appears under {len(dupes)} other payroll ids", "weight": 0.45})
    if payload.get("account_dormant_except_salary"):
        score += 0.15
        f.append({"code": "salary_only_account", "detail": "account shows salary credits but no living-pattern spend", "weight": 0.15})
    if payload.get("deceased_registry_hit"):
        score += 0.65
        f.append({"code": "deceased_registry_hit", "detail": "identity matched a death registry record", "weight": 0.65})
    return _cap(score), _verdict(_cap(score)), f


# ---------------------------------------------------------------------------
# 8. Agricultural subsidy / phantom-farmer fraud
# ---------------------------------------------------------------------------

def subsidy(payload: dict[str, Any], history: list[dict]) -> tuple[float, str, list[dict]]:
    f: list[dict] = []
    score = 0.05
    hectares = float(payload.get("farm_hectares") or 0)
    claim = float(payload.get("claim_ngn") or 0)
    if hectares > 0 and claim / hectares > SUBSIDY_MAX_NGN_PER_HECTARE:
        score += 0.30
        f.append({"code": "implausible_claim_ratio", "detail": f"N{claim/hectares:,.0f}/ha claimed (ceiling N{SUBSIDY_MAX_NGN_PER_HECTARE:,.0f})", "weight": 0.30})
    if payload.get("farm_geocode_outside_lga"):
        score += 0.25
        f.append({"code": "farm_outside_lga", "detail": "farm geolocation falls outside the registered LGA", "weight": 0.25})
    rows = [e["payload"] for e in history]
    nid = payload.get("identity_hash")
    if nid:
        dupes = {r.get("claim_id") for r in rows
                 if r.get("identity_hash") == nid
                 and r.get("claim_id") != payload.get("claim_id")}
        if dupes:
            score += 0.35
            f.append({"code": "duplicate_claimant", "detail": f"identity appears on {len(dupes)} other claims", "weight": 0.35})
    if payload.get("no_field_activity_evidence"):
        score += 0.20
        f.append({"code": "no_field_activity", "detail": "no planting/input-purchase evidence for the claimed acreage", "weight": 0.20})
    return _cap(score), _verdict(_cap(score)), f


DETECTORS = {
    "app_scam": app_scam,
    "mule": mule,
    "agent": agent,
    "loan_stacking": loan_stacking,
    "issuance": issuance,
    "channel": channel,
    "ghost_payroll": ghost_payroll,
    "subsidy": subsidy,
}
