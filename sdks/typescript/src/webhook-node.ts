/**
 * Node-only SYNCHRONOUS webhook signature verification.
 *
 * This module statically imports node:crypto — do NOT import it from
 * browser/edge bundles (use the async API in "fraudfusion" instead, which
 * falls back to Web Crypto). Exposed as the "fraudfusion/node" subpath.
 *
 * Same scheme as webhook.ts:
 *   key = sha256(secret).hexdigest().encode("utf-8")
 *   v1  = HMAC-SHA256(key, "<t>.<raw body>")
 *   ±300s tolerance, timingSafeEqual comparison.
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import { WebhookSignatureError } from "./errors.js";
import {
  DEFAULT_TOLERANCE_SECONDS,
  parseSignatureHeader,
  type VerifyOptions,
} from "./webhook.js";

function toBytes(value: string | Uint8Array, what: string): Uint8Array<ArrayBuffer> {
  if (typeof value === "string") return new TextEncoder().encode(value);
  if (value instanceof Uint8Array) return new Uint8Array(value);
  throw new TypeError(`${what} must be a string or Uint8Array`);
}

/** Synchronous key derivation: sha256(secret).hexdigest().encode("utf-8"). */
export function deriveSigningKeySync(secret: string | Uint8Array): Uint8Array<ArrayBuffer> {
  const hex = createHash("sha256").update(toBytes(secret, "secret")).digest("hex");
  return new TextEncoder().encode(hex);
}

/** Synchronous hex HMAC-SHA256 of "<t>.<raw body>" keyed by the derived key. */
export function computeSignatureSync(
  secret: string | Uint8Array,
  timestamp: number,
  body: string | Uint8Array,
): string {
  const key = deriveSigningKeySync(secret);
  const bodyBytes = toBytes(body, "body");
  const payload = new Uint8Array(String(timestamp).length + 1 + bodyBytes.length);
  payload.set(new TextEncoder().encode(String(timestamp)), 0);
  payload.set([0x2e], String(timestamp).length);
  payload.set(bodyBytes, String(timestamp).length + 1);
  return createHmac("sha256", key).update(payload).digest("hex");
}

/**
 * Synchronous verify (Node only). Returns true only when the timestamp is
 * within tolerance AND the v1 HMAC matches under timingSafeEqual. Throws
 * WebhookSignatureError only for an unparseable header.
 */
export function verifyWebhookSignatureSync(
  secret: string | Uint8Array,
  body: string | Uint8Array,
  header: string,
  options: VerifyOptions = {},
): boolean {
  const { t, v1 } = parseSignatureHeader(header);
  const tolerance = options.tolerance ?? DEFAULT_TOLERANCE_SECONDS;
  const now = options.now ?? Date.now() / 1000;
  if (Math.abs(now - t) > tolerance) return false;
  if (!/^[0-9a-fA-F]+$/.test(v1)) return false;
  const actual = computeSignatureSync(secret, t, body);
  const a = new TextEncoder().encode(actual);
  const b = new TextEncoder().encode(v1.toLowerCase());
  return a.length === b.length && timingSafeEqual(a, b);
}

export { DEFAULT_TOLERANCE_SECONDS, parseSignatureHeader, WebhookSignatureError };
