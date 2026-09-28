/**
 * FraudFusion TypeScript SDK — zero-runtime-dependency fetch client
 * (Node 18+ and modern browsers).
 *
 * Auth: every request carries `X-API-Key: ffk_live_...` / `ffk_test_...`.
 * Retry: 429/5xx and network errors retried up to maxRetries (default 3)
 * with exponential backoff + full jitter; a Retry-After header on 429 is
 * honoured when longer than the computed backoff.
 * Idempotency: every POST carries an Idempotency-Key (random UUID) unless
 * you pass `idempotencyKey` (replay deliberately) or `idempotencyKey: false`
 * (opt out). kyc-api replays the first response for 24h on a repeated key
 * and returns 409 on same-key-different-payload.
 */

import { errorForStatus, FraudFusionError } from "./errors.js";
import type {
  AjoAssessRequest,
  AjoAssessResponse,
  BiometricVerifyResponse,
  CulturalCalendarResponse,
  CulturalScoreRequest,
  CulturalScoreResponse,
  DocumentVerifyResponse,
  IntelHotspotsResponse,
  IntelStateRow,
  IntelStatesResponse,
  KycLevel,
  KycResponse,
  KycStatusResponse,
  KycVerifyRequest,
  KybApplicationView,
  KybBusinessType,
  KybDocument,
  KybVerificationResult,
  LegitimacyAssessRequest,
  LegitimacyAssessResponse,
  NationalSummary,
  WebhookDelivery,
  WebhookEndpoint,
} from "./types.js";

/** The sandbox service (services/python/sandbox) mirrors the data-plane
 *  shapes with deterministic synthetic fixtures; accepts only ffk_test_ keys. */
export const SANDBOX_BASE_URL = "http://localhost:8091";
export const DEFAULT_BASE_URL = SANDBOX_BASE_URL;
export const USER_AGENT = "fraudfusion-typescript/0.1.0";

export interface ClientOptions {
  apiKey: string;
  /** Deployment base URL. Defaults to the local sandbox (:8091); pass your
   *  live gateway URL for production. */
  baseUrl?: string;
  /** Per-request timeout in ms (default 30000). */
  timeoutMs?: number;
  /** Number of RETRIES (not total attempts) on 429/5xx/network errors. */
  maxRetries?: number;
  /** Backoff base in ms; attempt i waits ~base * 2**i with full jitter. */
  retryBaseDelayMs?: number;
  /** Attach a fresh Idempotency-Key to POSTs automatically (default true). */
  autoIdempotency?: boolean;
  /** Inject a fetch implementation (tests, exotic runtimes). */
  fetch?: typeof fetch;
  /** Sleep hook (tests). */
  sleep?: (ms: number) => Promise<void>;
}

export interface RequestOptions {
  /** Idempotency-Key override: string to replay deliberately, false to opt
   *  out, undefined for the auto-generated UUID. */
  idempotencyKey?: string | false;
}

export interface DocumentVerifyOptions extends RequestOptions {
  checkForgery?: boolean;
  filename?: string;
  contentType?: string;
}

export function newIdempotencyKey(): string {
  const c = globalThis.crypto as { randomUUID?: () => string } | undefined;
  if (c?.randomUUID) return c.randomUUID();
  // RFC4122 v4 fallback for runtimes without crypto.randomUUID.
  return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, (m) =>
    (Number(m) ^ ((Math.random() * 16) | 0)).toString(16));
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  // eslint-disable-next-line no-undef
  return btoa(bin);
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

type QueryValue = string | number | boolean | undefined;

export class FraudFusionClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly retryBaseDelayMs: number;
  private readonly autoIdempotency: boolean;
  private readonly fetchImpl: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(options: ClientOptions) {
    if (!options.apiKey) {
      throw new Error("apiKey is required (ffk_live_... or ffk_test_...)");
    }
    this.apiKey = options.apiKey;
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.maxRetries = Math.max(0, options.maxRetries ?? 3);
    this.retryBaseDelayMs = options.retryBaseDelayMs ?? 500;
    this.autoIdempotency = options.autoIdempotency ?? true;
    this.fetchImpl = options.fetch ?? fetch;
    this.sleep = options.sleep ?? defaultSleep;
  }

  // ---------------------------------------------------------------
  // core request machinery
  // ---------------------------------------------------------------
  private backoffDelay(attempt: number, retryAfter?: number): number {
    const cap = this.retryBaseDelayMs * 2 ** attempt;
    let delay = cap > 0 ? Math.random() * cap : 0;
    if (retryAfter !== undefined && retryAfter * 1000 > delay) {
      delay = retryAfter * 1000;
    }
    return delay;
  }

  private async request<T>(
    method: string,
    path: string,
    init: {
      json?: unknown;
      query?: Record<string, QueryValue>;
      form?: FormData;
      idempotencyKey?: string | false;
    } = {},
  ): Promise<T> {
    const url = new URL(this.baseUrl + path);
    if (init.query) {
      for (const [k, v] of Object.entries(init.query)) {
        if (v !== undefined) url.searchParams.set(k, String(v));
      }
    }

    const headers: Record<string, string> = {
      "X-API-Key": this.apiKey,
      Accept: "application/json",
      "User-Agent": USER_AGENT,
    };
    let body: BodyInit | undefined;
    if (init.form) {
      body = init.form; // fetch sets the multipart boundary itself
    } else if (init.json !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(init.json);
    }
    if (method === "POST") {
      if (typeof init.idempotencyKey === "string") {
        headers["Idempotency-Key"] = init.idempotencyKey;
      } else if (init.idempotencyKey !== false && this.autoIdempotency) {
        headers["Idempotency-Key"] = newIdempotencyKey();
      }
    }

    let lastError: unknown;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      let response: Response;
      try {
        response = await this.fetchImpl(url.toString(), {
          method, headers, body, signal: controller.signal,
        });
      } catch (err) {
        // Network failure: safe to retry (idempotency key protects mutating
        // endpoints against double-application).
        lastError = err;
        if (attempt < this.maxRetries) {
          await this.sleep(this.backoffDelay(attempt));
          continue;
        }
        throw new FraudFusionError(
          `connection to ${this.baseUrl} failed after ${this.maxRetries + 1} attempts: ${String(err)}`);
      } finally {
        clearTimeout(timer);
      }

      if (response.status < 400) {
        if (response.status === 204) return undefined as T;
        const ctype = response.headers.get("Content-Type") ?? "";
        if (ctype.includes("application/json")) {
          return (await response.json()) as T;
        }
        return (await response.text()) as unknown as T;
      }

      const retryable = response.status === 429 || response.status >= 500;
      if (retryable && attempt < this.maxRetries) {
        const raw = response.headers.get("Retry-After");
        const retryAfter = raw !== null ? Number(raw) : undefined;
        await this.sleep(
          this.backoffDelay(attempt,
            retryAfter !== undefined && Number.isFinite(retryAfter) && retryAfter >= 0
              ? retryAfter
              : undefined));
        continue;
      }

      const text = await response.text();
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { detail: text.slice(0, 500) };
      }
      throw errorForStatus(response.status, parsed);
    }
    throw new FraudFusionError(`request to ${path} failed: ${String(lastError)}`);
  }

  // ---------------------------------------------------------------
  // KYC (kyc-api)
  // ---------------------------------------------------------------

  /** POST /api/v1/kyc/verify/{basic|enhanced|premium}. */
  kycVerify(
    request: KycVerifyRequest & { level?: KycLevel },
    options: RequestOptions = {},
  ): Promise<KycResponse> {
    const { level = "basic", ...fields } = request;
    if (!["basic", "enhanced", "premium"].includes(level)) {
      throw new Error(`level must be basic|enhanced|premium, got ${level}`);
    }
    const payload: Record<string, unknown> = { ...fields };
    if (level === "basic") {
      delete payload.check_pep;
      delete payload.check_sanctions;
      delete payload.nationality;
      delete payload.check_credit_bureau;
      delete payload.credit_bureau_provider;
    } else if (level === "enhanced") {
      delete payload.check_credit_bureau;
      delete payload.credit_bureau_provider;
    }
    return this.request("POST", `/api/v1/kyc/verify/${level}`, {
      json: payload, idempotencyKey: options.idempotencyKey,
    });
  }

  /** GET /api/v1/kyc/status/{requestId}. */
  kycStatus(requestId: string): Promise<KycStatusResponse> {
    return this.request("GET", `/api/v1/kyc/status/${encodeURIComponent(requestId)}`);
  }

  /** Multipart upload to POST /api/v1/document/verify. Accepts a Blob
   *  (browser/Node 18+) or raw bytes. */
  documentVerify(
    document: Blob | Uint8Array | ArrayBuffer,
    documentType: string,
    options: DocumentVerifyOptions = {},
  ): Promise<DocumentVerifyResponse> {
    const bytes =
      document instanceof Uint8Array ? document
      : document instanceof ArrayBuffer ? new Uint8Array(document)
      : undefined;
    const blob = bytes
      ? new Blob([bytes as Uint8Array<ArrayBuffer>],
          options.contentType ? { type: options.contentType } : undefined)
      : (document as Blob);
    const form = new FormData();
    form.set("document", blob, options.filename ?? "document.bin");
    form.set("document_type", documentType);
    form.set("check_forgery", options.checkForgery === false ? "false" : "true");
    return this.request("POST", "/api/v1/document/verify", {
      form, idempotencyKey: options.idempotencyKey,
    });
  }

  /** POST /api/v1/biometric/verify (JSON, base64 images). Accepts base64
   *  strings or raw bytes (bytes are base64-encoded for you). */
  biometricVerify(
    selfie: string | Uint8Array,
    options: {
      reference?: string | Uint8Array;
      checkLiveness?: boolean;
    } & RequestOptions = {},
  ): Promise<BiometricVerifyResponse> {
    const payload: Record<string, unknown> = {
      selfie_image_base64:
        typeof selfie === "string" ? selfie : bytesToBase64(selfie),
      check_liveness: options.checkLiveness ?? true,
    };
    if (options.reference !== undefined) {
      payload.reference_image_base64 =
        typeof options.reference === "string"
          ? options.reference
          : bytesToBase64(options.reference);
    }
    return this.request("POST", "/api/v1/biometric/verify", {
      json: payload, idempotencyKey: options.idempotencyKey,
    });
  }

  // ---------------------------------------------------------------
  // KYB (onboarding-service — camelCase wire format)
  // ---------------------------------------------------------------

  /** POST /api/v1/onboarding/kyb. Document `content` (base64) is verified
   *  but never persisted server-side (hash-only storage). */
  kybSubmit(
    submission: {
      businessName: string;
      /** e.g. RC1234567 */
      cacNumber: string;
      contactEmail: string;
      documents: KybDocument[];
      businessType?: KybBusinessType;
    },
    options: RequestOptions = {},
  ): Promise<KybApplicationView> {
    return this.request("POST", "/api/v1/onboarding/kyb", {
      json: {
        businessName: submission.businessName,
        cacNumber: submission.cacNumber,
        businessType: submission.businessType ?? "limited_liability",
        contactEmail: submission.contactEmail,
        documents: submission.documents,
      },
      idempotencyKey: options.idempotencyKey,
    });
  }

  /** GET /api/v1/onboarding/kyb/{applicationId}. */
  kybGet(applicationId: string): Promise<KybApplicationView> {
    return this.request("GET",
      `/api/v1/onboarding/kyb/${encodeURIComponent(applicationId)}`);
  }

  /** GET /api/v1/onboarding/kyb/{applicationId}/verification — full
   *  per-document verdict (404 when no verification has run). */
  kybGetVerification(applicationId: string): Promise<KybVerificationResult> {
    return this.request("GET",
      `/api/v1/onboarding/kyb/${encodeURIComponent(applicationId)}/verification`);
  }

  // ---------------------------------------------------------------
  // Intelligence (intel-service)
  // ---------------------------------------------------------------

  /** GET /v1/intel/national/summary. */
  intelNationalSummary(): Promise<NationalSummary> {
    return this.request("GET", "/v1/intel/national/summary");
  }

  /** GET /v1/intel/states (k-anonymity suppressed cells flagged). */
  intelStates(): Promise<IntelStatesResponse> {
    return this.request("GET", "/v1/intel/states");
  }

  /** GET /v1/intel/states/{code}. */
  intelState(code: string): Promise<IntelStateRow> {
    return this.request("GET", `/v1/intel/states/${encodeURIComponent(code)}`);
  }

  /** GET /v1/intel/hotspots?k=&threshold=. */
  intelHotspots(options: { k?: number; threshold?: number } = {}): Promise<IntelHotspotsResponse> {
    return this.request("GET", "/v1/intel/hotspots", {
      query: { k: options.k ?? 10, threshold: options.threshold },
    });
  }

  /** GET /v1/intel/typology-mix. */
  intelTypologyMix(): Promise<Record<string, unknown>> {
    return this.request("GET", "/v1/intel/typology-mix");
  }

  /** GET /v1/intel/cultural/calendar?date=YYYY-MM-DD&state=. */
  intelCulturalCalendar(date: string, state = "lagos"): Promise<CulturalCalendarResponse> {
    return this.request("GET", "/v1/intel/cultural/calendar", {
      query: { date, state },
    });
  }

  /** POST /v1/intel/cultural/ajo/assess — ajo/esusu legitimacy posterior
   *  (PATTERN-LEVEL features only). */
  intelCulturalAjoAssess(req: AjoAssessRequest): Promise<AjoAssessResponse> {
    return this.request("POST", "/v1/intel/cultural/ajo/assess", { json: req });
  }

  /** POST /v1/intel/cultural/score — weighted cultural-fraud indicators. */
  intelCulturalScore(req: CulturalScoreRequest): Promise<CulturalScoreResponse> {
    return this.request("POST", "/v1/intel/cultural/score", { json: req });
  }

  /** POST /v1/intel/request-legitimacy/assess. */
  intelLegitimacyAssess(req: LegitimacyAssessRequest): Promise<LegitimacyAssessResponse> {
    return this.request("POST", "/v1/intel/request-legitimacy/assess", {
      json: { link_present: false, ...req },
    });
  }

  /** GET /v1/intel/request-legitimacy/matrix. */
  intelLegitimacyMatrix(): Promise<Record<string, unknown>> {
    return this.request("GET", "/v1/intel/request-legitimacy/matrix");
  }

  // ---------------------------------------------------------------
  // Webhooks (webhook-service)
  // ---------------------------------------------------------------

  /** GET /v1/webhooks — the tenant's registered endpoints. */
  webhooksList(): Promise<{ endpoints: WebhookEndpoint[] } | WebhookEndpoint[]> {
    return this.request("GET", "/v1/webhooks");
  }

  /** POST /v1/webhooks — the signing secret (whsec_...) is returned ONCE in
   *  this response; store it immediately. */
  webhookCreate(
    url: string,
    eventTypes: string[],
    options: { description?: string } & RequestOptions = {},
  ): Promise<WebhookEndpoint> {
    const payload: Record<string, unknown> = { url, event_types: eventTypes };
    if (options.description !== undefined) payload.description = options.description;
    return this.request("POST", "/v1/webhooks", {
      json: payload, idempotencyKey: options.idempotencyKey,
    });
  }

  /** DELETE /v1/webhooks/{endpointId}. */
  webhookDelete(endpointId: string): Promise<void> {
    return this.request("DELETE", `/v1/webhooks/${encodeURIComponent(endpointId)}`);
  }

  /** GET /v1/webhooks/{endpointId}/deliveries. */
  webhookDeliveries(
    endpointId: string,
  ): Promise<{ deliveries: WebhookDelivery[] } | WebhookDelivery[]> {
    return this.request("GET",
      `/v1/webhooks/${encodeURIComponent(endpointId)}/deliveries`);
  }
}
