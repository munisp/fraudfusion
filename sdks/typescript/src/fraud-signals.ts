/**
 * Fraud signal detectors — TypeScript port.
 *
 * Line-for-line port of services/python/fraud-signals/detectors.py. All four
 * language ports (Python, TypeScript, Go, Rust) are pinned to the same parity
 * contract: services/python/fraud-signals/fixtures/detector_cases.json.
 * Any threshold change must land in all ports and regenerate the fixture.
 */

export const BLOCK_MIN = 0.70;
export const REVIEW_MIN = 0.35;

export const STRUCTURING_BELOW_NGN = 50_000;
export const AGENT_VELOCITY_SPIKE = 3.0;
export const LOAN_STACKING_LENDERS = 3;
export const LOAN_STACKING_WINDOW_DAYS = 14;
export const MULE_PASS_THROUGH_MIN = 0.85;
export const MULE_FAN_IN_MIN = 5;
export const GHOST_SHARED_ACCOUNT_MIN = 2;
export const ISSUANCE_OFFICER_Z = 3.0;
export const SUBSIDY_MAX_NGN_PER_HECTARE = 150_000;
export const MULE_HIGH_RISK_FAN_IN_MIN = 3;
export const ISSUANCE_BENEFICIARY_BURST_MIN = 3;
export const HIGH_VALUE_SINGLE_APPROVAL_NGN = 10_000_000;
export const SIM_STEPUP_WINDOW_HOURS = 168;
export const SIM_STEPUP_AMOUNT_MIN_NGN = 100_000;
export const POST_SWAP_CUMULATIVE_MIN_NGN = 250_000;
export const BEHAVIORAL_Z_REVIEW = 3.0;
export const BEHAVIORAL_Z_BLOCK = 4.5;
export const BEHAVIORAL_MIN_BASELINE = 10;

export type Payload = Record<string, unknown>;
export interface HistoryEvent { payload: Payload; created_at: string }
export interface Factor { code: string; detail: string; weight: number }
export type Verdict = "block" | "review" | "clear";
export interface Result { score: number; verdict: Verdict; factors: Factor[] }

function verdictOf(score: number): Verdict {
  return score >= BLOCK_MIN ? "block" : score >= REVIEW_MIN ? "review" : "clear";
}

function cap(score: number): number {
  return Math.round(Math.min(score, 1.0) * 1000) / 1000;
}

function result(score: number, factors: Factor[]): Result {
  const s = cap(score);
  return { score: s, verdict: verdictOf(s), factors };
}

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function windowDays(events: HistoryEvent[], days: number, now?: Date): HistoryEvent[] {
  const ref = now ?? new Date();
  const cutoff = ref.getTime() - days * 86_400_000;
  return events.filter((e) => {
    const t = Date.parse(e.created_at);
    return Number.isNaN(t) || t >= cutoff;
  });
}

/** 1. Authorized-push-payment / social-engineering scam. */
export function appScam(payload: Payload, history: HistoryEvent[], now?: Date): Result {
  const f: Factor[] = [];
  let score = 0.05;
  if (payload.payee_is_new) {
    score += 0.20;
    f.push({ code: "new_payee", detail: "first-ever transfer to this payee", weight: 0.20 });
  }
  const hours = num(payload.payee_age_hours);
  if (hours !== null && hours < 1) {
    score += 0.15;
    f.push({ code: "payee_just_added", detail: "payee added <1h before transfer", weight: 0.15 });
  }
  const avg = num(payload.customer_avg_amount);
  const amount = num(payload.amount_ngn) ?? 0;
  if (avg && amount > 8 * avg) {
    score += 0.20;
    f.push({ code: "amount_outlier", detail: `amount ${amount} >8x customer average`, weight: 0.20 });
  }
  const session = num(payload.session_seconds);
  if (session !== null && session < 45) {
    score += 0.15;
    f.push({ code: "rushed_session", detail: "transfer completed in <45s — coercion pattern", weight: 0.15 });
  }
  if (payload.device_is_new) {
    score += 0.10;
    f.push({ code: "new_device", detail: "unrecognised device", weight: 0.10 });
  }
  const mule = num(payload.payee_mule_score);
  if (mule !== null && mule >= REVIEW_MIN) {
    score += 0.25;
    f.push({ code: "payee_mule_like", detail: `payee mule score ${mule}`, weight: 0.25 });
  }
  if (history.length === 0 && avg === null) {
    f.push({ code: "history_unavailable", detail: "no spending history supplied — amount-outlier signal skipped", weight: 0 });
  }
  return result(score, f);
}

/** 2. Money-mule account behaviour. */
export function mule(payload: Payload, history: HistoryEvent[], now?: Date): Result {
  const f: Factor[] = [];
  let score = 0.05;
  const txs = windowDays(history, 7, now).map((e) => e.payload);
  const incoming = txs.filter((t) => t.direction === "in");
  const outgoing = txs.filter((t) => t.direction === "out");
  const inSum = incoming.reduce((a, t) => a + (num(t.amount_ngn) ?? 0), 0);
  const outSum = outgoing.reduce((a, t) => a + (num(t.amount_ngn) ?? 0), 0);
  if (inSum > 0 && outSum / inSum >= MULE_PASS_THROUGH_MIN) {
    score += 0.35;
    f.push({ code: "pass_through", detail: `${Math.round((outSum / inSum) * 100)}% of inbound funds forwarded within the window`, weight: 0.35 });
  }
  const senders = new Set(incoming.map((t) => t.counterparty).filter(Boolean));
  if (senders.size >= MULE_FAN_IN_MIN) {
    score += 0.25;
    f.push({ code: "fan_in", detail: `${senders.size} distinct senders in 7d`, weight: 0.25 });
  }
  const risky = new Set(incoming.filter((t) => t.counterparty && (num(t.counterparty_risk) ?? 0) >= REVIEW_MIN).map((t) => t.counterparty));
  if (risky.size >= MULE_HIGH_RISK_FAN_IN_MIN) {
    score += 0.30;
    f.push({ code: "high_risk_fan_in", detail: `${risky.size} distinct senders with elevated own-risk scores`, weight: 0.30 });
  }
  const dormant = num(payload.dormant_days_before);
  if (dormant !== null && dormant >= 90 && txs.length > 0) {
    score += 0.20;
    f.push({ code: "dormancy_burst", detail: `${dormant}d dormant, sudden activity`, weight: 0.20 });
  }
  const shared = num(payload.shared_device_accounts);
  if (shared !== null && shared >= 3) {
    score += 0.20;
    f.push({ code: "shared_device_cluster", detail: `device shared with ${shared} accounts`, weight: 0.20 });
  }
  if (txs.length === 0) {
    f.push({ code: "history_unavailable", detail: "no recent transfer events — behavioural signals skipped", weight: 0 });
  }
  return result(score, f);
}

/** 3. Agent-banking / mobile-money agent fraud. */
export function agent(payload: Payload, history: HistoryEvent[], now?: Date): Result {
  const f: Factor[] = [];
  let score = 0.05;
  const txs = windowDays(history, 1, now).map((e) => e.payload);
  const baseline = num(payload.baseline_tx_per_day) ?? 0;
  if (baseline > 0 && txs.length > AGENT_VELOCITY_SPIKE * baseline) {
    score += 0.25;
    f.push({ code: "velocity_spike", detail: `${txs.length} tx today vs ${baseline} baseline`, weight: 0.25 });
  }
  const near = txs.filter((t) => t.type === "cash_out")
    .map((t) => num(t.amount_ngn) ?? 0)
    .filter((a) => a >= STRUCTURING_BELOW_NGN * 0.9 && a < STRUCTURING_BELOW_NGN);
  if (near.length >= 3) {
    score += 0.35;
    f.push({ code: "structuring", detail: `${near.length} cash-outs clustered just below N${STRUCTURING_BELOW_NGN}`, weight: 0.35 });
  }
  const dist = num(payload.distance_from_registered_km);
  if (dist !== null && dist > 5) {
    score += 0.20;
    f.push({ code: "off_location", detail: `operating ${dist}km from registered location`, weight: 0.20 });
  }
  const floatMismatch = num(payload.float_mismatch_ngn);
  if (floatMismatch !== null && Math.abs(floatMismatch) > 100_000) {
    score += 0.25;
    f.push({ code: "float_diversion", detail: `float/ledger mismatch N${floatMismatch}`, weight: 0.25 });
  }
  if (txs.length === 0 && baseline === 0) {
    f.push({ code: "history_unavailable", detail: "no agent activity history — velocity/structuring skipped", weight: 0 });
  }
  return result(score, f);
}

/** 4. Cross-lender loan stacking / bust-out. */
export function loanStacking(payload: Payload, history: HistoryEvent[], now?: Date): Result {
  const f: Factor[] = [];
  let score = 0.05;
  const apps = windowDays(history, LOAN_STACKING_WINDOW_DAYS, now).map((e) => e.payload);
  const lenders = new Set(apps.map((a) => a.lender_id).filter(Boolean));
  if (lenders.size >= LOAN_STACKING_LENDERS) {
    score += 0.40;
    f.push({ code: "multi_lender_stack", detail: `applications at ${lenders.size} lenders in ${LOAN_STACKING_WINDOW_DAYS}d`, weight: 0.40 });
  }
  if (payload.first_payment_default) {
    score += 0.35;
    f.push({ code: "first_payment_default", detail: "prior loan defaulted on first payment (bust-out signal)", weight: 0.35 });
  }
  if (payload.thin_file) {
    score += 0.10;
    f.push({ code: "thin_file", detail: "no credit history — synthetic-identity risk", weight: 0.10 });
  }
  const docScore = num(payload.document_authenticity_score);
  if (docScore !== null && docScore >= 50) {
    score += 0.25;
    f.push({ code: "forged_income_docs", detail: `document engine authenticity score ${docScore} (forgery suspected)`, weight: 0.25 });
  }
  return result(score, f);
}

/** 5. Insider-issued GENUINE documents (registry issuance anomaly). */
export function issuance(payload: Payload, history: HistoryEvent[], now?: Date): Result {
  const f: Factor[] = [];
  let score = 0.05;
  const officerToday = windowDays(history, 1, now).length;
  const peerMean = num(payload.peer_officer_mean_per_day);
  const peerStd = num(payload.peer_officer_std_per_day);
  if (peerMean !== null && peerStd) {
    const z = (officerToday - peerMean) / Math.max(peerStd, 0.1);
    if (z >= ISSUANCE_OFFICER_Z) {
      score += 0.35;
      f.push({ code: "officer_velocity_outlier", detail: `officer issued ${officerToday} today (z=${z.toFixed(1)} vs peers)`, weight: 0.35 });
    }
  }
  const hour = num(payload.issued_hour_local);
  if (hour !== null && (hour < 6 || hour >= 22)) {
    score += 0.15;
    f.push({ code: "after_hours_issuance", detail: `issued at ${hour}:00 local`, weight: 0.15 });
  }
  if (payload.sequence_gap) {
    score += 0.20;
    f.push({ code: "certificate_sequence_gap", detail: "certificate number falls in a skipped sequence block", weight: 0.20 });
  }
  if (payload.registry_survey_mismatch) {
    score += 0.30;
    f.push({ code: "registry_survey_mismatch", detail: "registry record's survey hash != physical survey plan", weight: 0.30 });
  }
  const burst = num(payload.beneficiary_certificates_30d);
  if (burst !== null && burst >= ISSUANCE_BENEFICIARY_BURST_MIN) {
    score += 0.25;
    f.push({ code: "beneficiary_issuance_burst", detail: `beneficiary received ${burst} certificates in 30d`, weight: 0.25 });
  }
  const value = num(payload.certificate_value_ngn) ?? 0;
  if (value >= HIGH_VALUE_SINGLE_APPROVAL_NGN && (num(payload.approvals) ?? 1) < 2) {
    score += 0.20;
    f.push({ code: "high_value_single_approval", detail: "high-value certificate approved by a single officer — four-eyes required", weight: 0.20 });
  }
  if (history.length === 0 && peerMean === null) {
    f.push({ code: "history_unavailable", detail: "no officer issuance baseline — velocity signal skipped", weight: 0 });
  }
  return result(score, f);
}

/** 6. USSD / feature-phone channel fraud. */
export function channel(payload: Payload, history: HistoryEvent[], now?: Date): Result {
  const f: Factor[] = [];
  let score = 0.05;
  const simHours = num(payload.sim_change_hours);
  if (payload.channel === "ussd" && simHours !== null && simHours < 24) {
    score += 0.40;
    f.push({ code: "ussd_after_sim_change", detail: "USSD session <24h after SIM swap/change", weight: 0.40 });
  }
  const chanAmount = num(payload.amount_ngn) ?? 0;
  if (simHours !== null && simHours >= 24 && simHours < SIM_STEPUP_WINDOW_HOURS && chanAmount >= SIM_STEPUP_AMOUNT_MIN_NGN) {
    score += 0.30;
    f.push({ code: "sim_age_high_value_stepup", detail: `high-value transaction ${simHours}h after SIM change (step-up window ${SIM_STEPUP_WINDOW_HOURS}h)`, weight: 0.30 });
  }
  if (simHours !== null && simHours < SIM_STEPUP_WINDOW_HOURS) {
    const cutoff = (now ?? new Date()).getTime() - simHours * 3_600_000;
    const postSwap = history.reduce((a, e) => {
      const t = Date.parse(e.created_at);
      return a + ((Number.isNaN(t) || t >= cutoff) ? (num(e.payload.amount_ngn) ?? 0) : 0);
    }, 0);
    const total = postSwap + chanAmount;
    if (total >= POST_SWAP_CUMULATIVE_MIN_NGN) {
      score += 0.25;
      f.push({ code: "post_swap_cumulative_stepup", detail: `N${total} moved within ${simHours}h of SIM change (cumulative step-up)`, weight: 0.25 });
    }
  }
  if (payload.imei_is_new && chanAmount > 100_000) {
    score += 0.25;
    f.push({ code: "new_imei_high_value", detail: "high-value transaction from an unrecognised handset", weight: 0.25 });
  }
  if (payload.alert_integrity_fail) {
    score += 0.35;
    f.push({ code: "bank_alert_integrity_fail", detail: "SMS alert failed authenticity check — fake-alert pattern", weight: 0.35 });
  }
  const tenure = num(payload.phone_tenure_days);
  if (tenure !== null && tenure < 30) {
    score += 0.15;
    f.push({ code: "low_phone_tenure", detail: `number tenure ${tenure}d`, weight: 0.15 });
  }
  return result(score, f);
}

/** 7. Ghost workers / benefit diversion. */
export function ghostPayroll(payload: Payload, history: HistoryEvent[], _now?: Date): Result {
  const f: Factor[] = [];
  let score = 0.05;
  const rows = history.map((e) => e.payload);
  const account = payload.bank_account_hash;
  if (account) {
    const sharing = new Set(rows.filter((r) => r.bank_account_hash === account && r.employee_id !== payload.employee_id).map((r) => r.employee_id));
    if (sharing.size >= GHOST_SHARED_ACCOUNT_MIN - 1 && sharing.size > 0) {
      score += 0.40;
      f.push({ code: "shared_salary_account", detail: `salary account shared with ${sharing.size} other 'employees'`, weight: 0.40 });
    }
  }
  const nid = payload.identity_hash;
  if (nid) {
    const dupes = new Set(rows.filter((r) => r.identity_hash === nid && r.employee_id !== payload.employee_id).map((r) => r.employee_id));
    if (dupes.size > 0) {
      score += 0.45;
      f.push({ code: "duplicate_identity", detail: `identity hash appears under ${dupes.size} other payroll ids`, weight: 0.45 });
    }
  }
  if (payload.account_dormant_except_salary) {
    score += 0.15;
    f.push({ code: "salary_only_account", detail: "account shows salary credits but no living-pattern spend", weight: 0.15 });
  }
  if (payload.deceased_registry_hit) {
    score += 0.65;
    f.push({ code: "deceased_registry_hit", detail: "identity matched a death registry record", weight: 0.65 });
  }
  return result(score, f);
}

/** 8. Agricultural subsidy / phantom-farmer fraud. */
export function subsidy(payload: Payload, history: HistoryEvent[], _now?: Date): Result {
  const f: Factor[] = [];
  let score = 0.05;
  const hectares = num(payload.farm_hectares) ?? 0;
  const claim = num(payload.claim_ngn) ?? 0;
  if (hectares > 0 && claim / hectares > SUBSIDY_MAX_NGN_PER_HECTARE) {
    score += 0.30;
    f.push({ code: "implausible_claim_ratio", detail: `N${Math.round(claim / hectares)}/ha claimed (ceiling N${SUBSIDY_MAX_NGN_PER_HECTARE})`, weight: 0.30 });
  }
  if (payload.farm_geocode_outside_lga) {
    score += 0.25;
    f.push({ code: "farm_outside_lga", detail: "farm geolocation falls outside the registered LGA", weight: 0.25 });
  }
  const rows = history.map((e) => e.payload);
  const nid = payload.identity_hash;
  if (nid) {
    const dupes = new Set(rows.filter((r) => r.identity_hash === nid && r.claim_id !== payload.claim_id).map((r) => r.claim_id));
    if (dupes.size > 0) {
      score += 0.35;
      f.push({ code: "duplicate_claimant", detail: `identity appears on ${dupes.size} other claims`, weight: 0.35 });
    }
  }
  if (payload.no_field_activity_evidence) {
    score += 0.20;
    f.push({ code: "no_field_activity", detail: "no planting/input-purchase evidence for the claimed acreage", weight: 0.20 });
  }
  return result(score, f);
}

export type DetectorName =
  | "app_scam" | "mule" | "agent" | "loan_stacking"
  | "issuance" | "channel" | "ghost_payroll" | "subsidy" | "behavioral";

export const DETECTORS: Record<DetectorName, (p: Payload, h: HistoryEvent[], now?: Date) => Result> = {
  app_scam: appScam,
  mule,
  agent,
  loan_stacking: loanStacking,
  issuance,
  channel,
  ghost_payroll: ghostPayroll,
  subsidy,
  behavioral,
};

/** 9. Behavioral baseline anomaly (lightweight, dependency-free z-scores). */
export function behavioral(payload: Payload, history: HistoryEvent[], _now?: Date): Result {
  const f: Factor[] = [];
  let score = 0.05;
  const metrics = Object.keys(payload).filter((k) => {
    const v = payload[k];
    return typeof v === "number" && Number.isFinite(v);
  }).sort();
  if (metrics.length === 0) {
    f.push({ code: "history_unavailable", detail: "no numeric metrics in payload — behavioral scoring skipped", weight: 0 });
    return result(score, f);
  }
  let fired = 0;
  for (const metric of metrics) {
    const values = history
      .map((e) => e.payload[metric])
      .filter((v): v is number => typeof v === "number" && Number.isFinite(v));
    if (values.length < BEHAVIORAL_MIN_BASELINE) continue;
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / values.length;
    const std = Math.max(Math.sqrt(variance), mean * 0.01, 1e-9);
    const z = Math.abs((payload[metric] as number) - mean) / std;
    if (z >= BEHAVIORAL_Z_BLOCK) {
      score += 0.35;
      fired += 1;
      f.push({ code: "behavioral_outlier_block", detail: `${metric} z=${z.toFixed(1)} vs subject baseline (mean ${mean}, n=${values.length})`, weight: 0.35 });
    } else if (z >= BEHAVIORAL_Z_REVIEW) {
      score += 0.20;
      fired += 1;
      f.push({ code: "behavioral_outlier_review", detail: `${metric} z=${z.toFixed(1)} vs subject baseline (mean ${mean}, n=${values.length})`, weight: 0.20 });
    }
  }
  if (fired === 0 && !metrics.some((m) =>
    history.filter((e) => typeof e.payload[m] === "number").length >= BEHAVIORAL_MIN_BASELINE)) {
    f.push({ code: "history_unavailable", detail: `fewer than ${BEHAVIORAL_MIN_BASELINE} baseline points per metric — behavioral scoring skipped`, weight: 0 });
  }
  return result(score, f);
}
