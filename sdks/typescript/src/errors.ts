/**
 * FraudFusion TypeScript SDK — typed errors.
 *
 * HTTP status mapping (thrown for every non-2xx response after retries):
 *   400/422 -> ValidationError
 *   401     -> AuthenticationError  (missing/invalid/revoked X-API-Key)
 *   403     -> PermissionError      (valid key, missing scope / wrong tenant)
 *   404     -> NotFoundError
 *   409     -> ConflictError        (idempotency-key conflict, state conflicts)
 *   429     -> RateLimitError       (carries retryAfter when the server sends it)
 *   5xx     -> ServerError          (retried first; thrown after exhaustion)
 */

export interface ErrorInit {
  statusCode?: number;
  detail?: string;
  body?: unknown;
}

export class FraudFusionError extends Error {
  readonly statusCode?: number;
  readonly detail?: string;
  readonly body?: unknown;

  constructor(message: string, init: ErrorInit = {}) {
    super(message);
    this.name = new.target.name;
    this.statusCode = init.statusCode;
    this.detail = init.detail;
    this.body = init.body;
  }
}

export class AuthenticationError extends FraudFusionError {}
export class PermissionError extends FraudFusionError {}
export class NotFoundError extends FraudFusionError {}
export class ConflictError extends FraudFusionError {}
export class ValidationError extends FraudFusionError {}

export class RateLimitError extends FraudFusionError {
  readonly retryAfter?: number;
  constructor(message: string, init: ErrorInit & { retryAfter?: number } = {}) {
    super(message, init);
    this.retryAfter = init.retryAfter;
  }
}

export class ServerError extends FraudFusionError {}

/** Malformed webhook signature header (a mismatch/expiry returns false instead). */
export class WebhookSignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WebhookSignatureError";
  }
}

function detailFrom(body: unknown): string | undefined {
  if (body && typeof body === "object") {
    const rec = body as Record<string, unknown>;
    const raw = rec.detail ?? rec.error ?? rec.message;
    if (typeof raw === "string") return raw;
    if (raw != null) return String(raw);
  }
  return undefined;
}

export function errorForStatus(statusCode: number, body: unknown): FraudFusionError {
  const detail = detailFrom(body);
  const message = detail ?? `HTTP ${statusCode}`;
  const init: ErrorInit = { statusCode, detail, body };
  if (statusCode >= 500) return new ServerError(message, init);
  switch (statusCode) {
    case 400:
    case 422:
      return new ValidationError(message, init);
    case 401:
      return new AuthenticationError(message, init);
    case 403:
      return new PermissionError(message, init);
    case 404:
      return new NotFoundError(message, init);
    case 409:
      return new ConflictError(message, init);
    case 429: {
      const retryAfter =
        body && typeof body === "object" &&
        typeof (body as Record<string, unknown>).retry_after === "number"
          ? ((body as Record<string, unknown>).retry_after as number)
          : undefined;
      return new RateLimitError(message, { ...init, retryAfter });
    }
    default:
      return new FraudFusionError(message, init);
  }
}
