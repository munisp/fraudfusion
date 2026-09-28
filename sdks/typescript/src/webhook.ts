/**
 * Webhook signature verification — universal (Node 18+ / browsers / edge).
 *
 * Implements the FraudFusion shared signing scheme exactly:
 *   Header:         X-FraudFusion-Signature: t=<unix_ts>,v1=<hex hmac-sha256>
 *   Key derivation: webhook secrets are stored hash-only server-side, so the
 *                   HMAC key is DERIVED from the secret:
 *                       key = sha256(secret).hexdigest().encode("utf-8")
 *   Signed payload: HMAC-SHA256(key, "<t>.<raw request body>")
 *   Tolerance:      |now - t| <= 300 seconds (replay protection)
 *   Comparison:     constant-time (node:crypto timingSafeEqual when running
 *                   on Node; an equivalent constant-time byte compare on
 *                   Web Crypto runtimes)
 *
 * The primary API is async: it prefers node:crypto and transparently falls
 * back to globalThis.crypto.subtle (edge/browser). A synchronous Node-only
 * variant lives in the "fraudfusion/node" subpath (src/webhook-node.ts).
 *
 * ALWAYS verify against the RAW request body bytes, before JSON parsing —
 * re-serialisation would change the HMAC.
 */

import { WebhookSignatureError } from "./errors.js";

export const SIGNATURE_HEADER = "X-FraudFusion-Signature";
export const DEFAULT_TOLERANCE_SECONDS = 300;

export interface VerifyOptions {
  /** Replay tolerance in seconds (default 300). */
  tolerance?: number;
  /** Override the current time (unix seconds) — used by tests. */
  now?: number;
  /** Crypto backend: "auto" (node:crypto, else Web Crypto), "node"
   *  (node:crypto or throw), "webcrypto" (force the Web Crypto path). */
  backend?: "auto" | "node" | "webcrypto";
}

type Backend = NonNullable<VerifyOptions["backend"]>;

export function parseSignatureHeader(header: string): { t: number; v1: string } {
  if (!header || typeof header !== "string") {
    throw new WebhookSignatureError("signature header is empty or not a string");
  }
  let tRaw: string | undefined;
  let v1: string | undefined;
  for (const part of header.split(",")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue; // tolerate stray segments
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === "t") tRaw = value;
    else if (key === "v1") v1 = value;
  }
  if (tRaw === undefined || v1 === undefined) {
    throw new WebhookSignatureError(
      "signature header must contain t=<unix_ts> and v1=<hex> components");
  }
  const t = Number.parseInt(tRaw, 10);
  if (!Number.isFinite(t) || String(t) !== tRaw.replace(/^\+/, "")) {
    throw new WebhookSignatureError(`signature timestamp is not an integer: ${tRaw}`);
  }
  return { t, v1 };
}

function toBytes(value: string | Uint8Array, what: string): Uint8Array<ArrayBuffer> {
  if (typeof value === "string") return new TextEncoder().encode(value);
  if (value instanceof Uint8Array) return new Uint8Array(value); // copy: normalises ArrayBufferLike
  throw new TypeError(`${what} must be a string or Uint8Array`);
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Constant-time hex-string comparison (Web Crypto has no timingSafeEqual). */
function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

interface NodeCrypto {
  createHash: (alg: string) => { update: (d: Uint8Array) => { digest: (enc: string) => string } };
  createHmac: (alg: string, key: Uint8Array) => {
    update: (d: Uint8Array) => { digest: (enc: string) => string };
  };
  timingSafeEqual: (a: Uint8Array, b: Uint8Array) => boolean;
}

async function loadNodeCrypto(): Promise<NodeCrypto | null> {
  try {
    return (await import("node:crypto")) as unknown as NodeCrypto;
  } catch {
    return null; // browser / edge runtime
  }
}

async function pickBackend(backend: Backend): Promise<NodeCrypto | null> {
  if (backend === "webcrypto") return null;
  const node = await loadNodeCrypto();
  if (!node && backend === "node") {
    throw new WebhookSignatureError(
      "node:crypto is unavailable in this runtime; use backend 'auto' or 'webcrypto'");
  }
  return node;
}

function webCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new WebhookSignatureError(
      "no crypto backend available: node:crypto import failed and " +
        "globalThis.crypto.subtle is absent");
  }
  return subtle;
}

/**
 * Derive the HMAC key from a webhook signing secret:
 * sha256(secret).hexdigest().encode("utf-8").
 */
export async function deriveSigningKey(
  secret: string | Uint8Array,
  backend: Backend = "auto",
): Promise<Uint8Array<ArrayBuffer>> {
  const node = await pickBackend(backend);
  const secretBytes = toBytes(secret, "secret");
  if (node) {
    const hex = node.createHash("sha256").update(secretBytes).digest("hex");
    return new TextEncoder().encode(hex);
  }
  const digest = new Uint8Array(await webCrypto().digest("SHA-256", secretBytes));
  return new TextEncoder().encode(toHex(digest));
}

/** Hex HMAC-SHA256 of "<t>.<raw body>" keyed by the derived key. */
export async function computeSignature(
  secret: string | Uint8Array,
  timestamp: number,
  body: string | Uint8Array,
  backend: Backend = "auto",
): Promise<string> {
  const key = await deriveSigningKey(secret, backend);
  const bodyBytes = toBytes(body, "body");
  const payload = new Uint8Array(
    String(timestamp).length + 1 + bodyBytes.length);
  payload.set(new TextEncoder().encode(String(timestamp)), 0);
  payload.set([0x2e], String(timestamp).length); // "."
  payload.set(bodyBytes, String(timestamp).length + 1);

  const node = await pickBackend(backend);
  if (node) {
    return node.createHmac("sha256", key).update(payload).digest("hex");
  }
  const subtle = webCrypto();
  const cryptoKey = await subtle.importKey(
    "raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await subtle.sign("HMAC", cryptoKey, payload));
  return toHex(sig);
}

/**
 * Verify an X-FraudFusion-Signature header against the raw request body.
 *
 * Resolves true only when the timestamp is within tolerance (±300s default)
 * AND the v1 HMAC matches (constant-time compare). Resolves false for an
 * expired/future timestamp or a mismatched signature. Throws
 * WebhookSignatureError only for a header that cannot be parsed at all.
 */
export async function verifyWebhookSignature(
  secret: string | Uint8Array,
  body: string | Uint8Array,
  header: string,
  options: VerifyOptions = {},
): Promise<boolean> {
  const { t, v1 } = parseSignatureHeader(header);
  const tolerance = options.tolerance ?? DEFAULT_TOLERANCE_SECONDS;
  const now = options.now ?? Date.now() / 1000;
  if (Math.abs(now - t) > tolerance) return false;
  const actual = await computeSignature(secret, t, body, options.backend ?? "auto");

  const node = await pickBackend(options.backend ?? "auto");
  if (node) {
    const a = new TextEncoder().encode(actual);
    const b = new TextEncoder().encode(v1);
    return a.length === b.length && node.timingSafeEqual(a, b);
  }
  return constantTimeEqualHex(actual, v1);
}
