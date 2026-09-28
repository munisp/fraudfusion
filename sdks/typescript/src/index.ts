/**
 * fraudfusion — official zero-dependency TypeScript SDK for the FraudFusion
 * API (KYC/KYB, fraud intelligence, webhooks). Node 18+ and browsers.
 *
 * Quickstart:
 *   import { FraudFusionClient } from "fraudfusion";
 *   const client = new FraudFusionClient({
 *     apiKey: "ffk_test_...",
 *     baseUrl: "http://localhost:8091",  // sandbox; live URL in production
 *   });
 *   const result = await client.kycVerify({
 *     customer_id: "cust_001", first_name: "Ada", last_name: "Lovelace",
 *     bvn: "12345678900",
 *   });
 */

export { FraudFusionClient, newIdempotencyKey, SANDBOX_BASE_URL, DEFAULT_BASE_URL } from "./client.js";
export type { ClientOptions, RequestOptions, DocumentVerifyOptions } from "./client.js";

export {
  FraudFusionError,
  AuthenticationError,
  PermissionError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  ValidationError,
  ServerError,
  WebhookSignatureError,
  errorForStatus,
} from "./errors.js";

export {
  SIGNATURE_HEADER,
  DEFAULT_TOLERANCE_SECONDS,
  parseSignatureHeader,
  deriveSigningKey,
  computeSignature,
  verifyWebhookSignature,
} from "./webhook.js";
export type { VerifyOptions } from "./webhook.js";

export * from "./types.js";
