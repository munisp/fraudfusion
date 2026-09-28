/**
 * FraudFusion API types — mirrored from the FastAPI services:
 *   kyc-api            (services/python/kyc-api/app/schemas.py, main.py)
 *   onboarding-service (services/python/onboarding-service/app/schemas.py)
 *   intel-service      (services/python/intel-service/app/main.py, cultural.py,
 *                       request_legitimacy.py)
 *   webhook-service    (services/python/webhook-service — signing scheme)
 *
 * Snake_case keys are used by kyc-api / intel-service; onboarding-service
 * serialises camelCase aliases (response_model_by_alias=True) — mirrored
 * faithfully below.
 */

// ---------------------------------------------------------------- KYC ----

export type KycLevel = "basic" | "enhanced" | "premium";
export type KycDecision = "approved" | "manual_review" | "rejected" | "pending";

export interface AddressEvidence {
  method: "physical_visit" | "utility_bill" | "agent_confirmation" | "electronic";
  /** ISO-8601 date/datetime the address was verified. */
  verified_at: string;
}

export interface KycVerifyRequest {
  customer_id: string;
  first_name: string;
  last_name: string;
  bvn?: string;
  nin?: string;
  phone?: string;
  email?: string;
  date_of_birth?: string;
  address_evidence?: AddressEvidence;
  /** enhanced/premium only */
  check_pep?: boolean;
  /** enhanced/premium only */
  check_sanctions?: boolean;
  /** enhanced/premium only */
  nationality?: string;
  /** premium only */
  check_credit_bureau?: boolean;
  /** premium only (default "crc") */
  credit_bureau_provider?: string;
}

export interface KycResponse {
  request_id: string;
  customer_id: string;
  status: string;
  verification_level: string;
  risk_score: number;
  risk_level: "low" | "medium" | "high" | "critical";
  decision: KycDecision;
  verification_results: Record<string, unknown>;
  timestamp: string;
  processing_time_ms: number;
}

export interface KycStatusResponse {
  request_id: string;
  customer_id: string;
  status: string;
  verification_level: string;
  tier: string;
  decision: KycDecision;
  risk_score: number;
  risk_level: string;
  verification_results: Record<string, unknown>;
  address_verification: Record<string, unknown>;
  timestamp: string;
}

// ------------------------------------------------- document / biometric --

export interface DocumentCheck {
  check: string;
  passed: boolean;
}

export interface DocumentVerifyResponse {
  verification_id: string;
  document_type: string;
  detected_format: string;
  size_bytes: number;
  checks: DocumentCheck[];
  forgery: Record<string, unknown>;
  structurally_valid: boolean;
  status: "verified" | "manual_review" | "rejected" | string;
  /** layered-pipeline verdict with per-layer provenance (image payloads). */
  pipeline?: Record<string, unknown>;
  timestamp: string;
}

export interface BiometricVerifyResponse {
  verification_id: string;
  status: "verified" | "manual_review" | "rejected" | string;
  selfie_format: string;
  reference_format?: string;
  face_match: {
    performed: boolean;
    score: number | null;
    match: boolean | null;
    reason?: string;
    [k: string]: unknown;
  };
  liveness: {
    performed: boolean;
    result: string;
    reason?: string;
    score?: number | null;
    [k: string]: unknown;
  };
  rejection_reason?: string;
  timestamp: string;
}

// ---------------------------------------------------------------- KYB ----

export type KybDocumentType =
  | "cac_certificate"
  | "memart"
  | "utility_bill"
  | "board_resolution";

export interface KybDocument {
  type: KybDocumentType;
  /** Pointer to the document (e.g. s3://...). Always required. */
  reference: string;
  /** OPTIONAL base64 document bytes — verified but never persisted
   *  server-side (hash-only storage). */
  content?: string;
}

export type KybBusinessType =
  | "business_name"
  | "limited_liability"
  | "plc"
  | "ngo"
  | "partnership";

export interface KybVerificationSummary {
  verdict: "verified" | "manual_review" | "rejected" | "engine_unavailable" | "skipped";
  verifiedAt?: string | null;
  engines: string[];
  documentsWithContent: number;
}

export interface KybApplicationView {
  applicationId: string;
  businessName: string;
  cacNumber: string;
  businessType: string;
  status: "submitted" | "under_review" | "approved" | "rejected";
  submittedBy: string;
  reviewedBy?: string | null;
  approvedBy?: string | null;
  rejectionReason?: string | null;
  createdAt?: string | null;
  verification?: KybVerificationSummary | null;
}

/** Full per-document content-verification verdict
 *  (GET /api/v1/onboarding/kyb/{id}/verification). The verdict JSON is
 *  engine-driven; the stable top-level keys are typed, the rest preserved. */
export interface KybVerificationResult {
  verdict: string;
  documents?: Array<Record<string, unknown>>;
  [k: string]: unknown;
}

// --------------------------------------------------------------- intel ---

export interface NationalSummary {
  data_period_weeks: number;
  provenance: string;
  national_fraud_rate: { posterior_mean: number; ci95: [number, number] };
  week_trend: { direction: string; delta_last4_vs_prior4: number };
  top_typologies: Array<{ typology: string; share: number }>;
  totals: { txn_year: number; fraud_year: number };
  forecast_4wk: Record<string, unknown>;
  model_version?: string;
}

export interface IntelStateRow {
  code: string;
  name: string;
  suppressed: boolean;
  reason?: string;
  zone?: string;
  posterior_mean?: number;
  ci95?: [number, number];
  weekly_txn_mean?: number;
  [k: string]: unknown;
}

export interface IntelStatesResponse {
  states: IntelStateRow[];
  national_posterior_mean: number;
  suppression_min_weekly_n: number;
  provenance: string;
}

export interface IntelHotspotsResponse {
  k: number;
  threshold: number;
  hotspots: Array<{
    code: string;
    name: string;
    zone: string;
    posterior_mean: number;
    ci95: [number, number];
    p_exceeds_threshold: number;
  }>;
  provenance: string;
}

export interface CulturalCalendarResponse {
  date: string;
  state: string;
  zone: string;
  active_events: Array<{
    id: string;
    name: string;
    lunar_approx: boolean;
    uplift_mean: number;
    ci95: [number, number];
    applied: boolean;
  }>;
  applied_event: string | null;
  precedence_note: string;
  provenance: string;
}

export interface AjoAssessRequest {
  n_members: number;
  contribution_cv: number;
  cadence_cv: number;
  rotation_coverage: number;
  payout_ratio: number;
  tenure_days: number;
}

export interface AjoAssessResponse {
  p_legitimate_mean: number;
  ci95: [number, number];
  assessment: "likely_legitimate_ajo" | "likely_fraud" | "uncertain";
  uncertain: boolean;
  uncertain_rule: string;
  top_discriminating_features: Array<Record<string, unknown>>;
  model_auc_test: number;
  note: string;
  provenance: string;
}

export interface CulturalScoreRequest {
  indicators: Record<string, number>;
  claimed_event?: string;
  date?: string;
  state?: string;
  network_consistent_with_claimed_norm?: boolean;
  ajo_pattern?: AjoAssessRequest;
}

export interface CulturalScoreResponse {
  cultural_fraud_score: number;
  risk_band: string;
  indicator_breakdown: Record<
    string,
    { severity: number; weight: number; contribution: number }
  >;
  authenticity_discount: number;
  authenticity_notes: string[];
  weights_source: string;
  provenance: string;
}

export interface LegitimacyAssessRequest {
  /** Entity TYPE only (road_safety, bank, fintech, telco, employer, unknown)
   *  — never a specific company name. */
  requesting_entity_type: string;
  /** e.g. bvn, nin, dob, phone, plate_number, otp, voters_card, passport,
   *  address, email */
  fields_requested: string[];
  /** sms, email, web_form, in_person, ussd */
  channel: string;
  link_present?: boolean;
}

export interface LegitimacyAssessResponse {
  score: number;
  risk_band: string;
  requesting_entity_type: string;
  channel: string;
  link_present: boolean;
  field_verdicts: Array<{ field: string; verdict: string; reason: string }>;
  rule_bonuses: string[];
  explanation: string;
  safe_action: string;
  matrix_version: string;
  note: string;
}

// ------------------------------------------------------------ webhooks ---

/** Event envelope posted to your endpoint by the webhook service. */
export interface WebhookEventEnvelope<T = Record<string, unknown>> {
  id: string;
  type:
    | "kyc.verification.completed"
    | "kyb.verification.completed"
    | "identity.exposure.detected"
    | string;
  created_at: string;
  tenant_id: string;
  data: T;
}

/** A registered webhook endpoint. The signing secret (whsec_...) appears
 *  ONLY in the creation response — it is stored hash-only server-side. */
export interface WebhookEndpoint {
  id: string;
  url: string;
  event_types: string[];
  active?: boolean;
  created_at?: string;
  /** Present ONLY on the create response. */
  secret?: string;
  [k: string]: unknown;
}

export interface WebhookDelivery {
  id: string;
  endpoint_id?: string;
  event_id?: string;
  status?: string;
  attempts?: number;
  [k: string]: unknown;
}
