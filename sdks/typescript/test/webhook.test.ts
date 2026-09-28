/**
 * Known-answer + behaviour tests for the webhook signature verifier.
 *
 * The KAT vector is identical to the Python SDK's (sdks/python/tests/
 * test_webhook.py) — both are pinned to the same bytes:
 *   key = sha256("whsec_testsecret").hexdigest().encode("utf-8")
 *       = "e2ba7a07c32c49c4ac02192da58827a38284fa93d08ab4632af87b25e1f5c8be"
 *   v1  = HMAC-SHA256(key, "<t>.<body>")
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  computeSignature,
  deriveSigningKey,
  parseSignatureHeader,
  verifyWebhookSignature,
  WebhookSignatureError,
} from "../src/index.js";
import {
  computeSignatureSync,
  deriveSigningKeySync,
  verifyWebhookSignatureSync,
} from "../src/webhook-node.js";

const SECRET = "whsec_testsecret";
const T = 1700000000; // 2023-11-14T22:13:20Z
const BODY =
  '{"id":"evt_01JTEST","type":"kyc.verification.completed",' +
  '"created_at":"2023-11-14T22:13:20+00:00","tenant_id":"ten_demo",' +
  '"data":{"verification_id":"ver_abc123","status":"verified"}}';
const DERIVED_KEY =
  "e2ba7a07c32c49c4ac02192da58827a38284fa93d08ab4632af87b25e1f5c8be";
const EXPECTED_V1 =
  "ededc70731f82ecc4ba7f338def73b8d5fecc42d662d33106cccf2525bbd8202";
const HEADER = `t=${T},v1=${EXPECTED_V1}`;

test("key derivation (node + webcrypto + sync all agree)", async () => {
  const hexOf = (b: Uint8Array) => Buffer.from(b).toString();
  assert.equal(hexOf(await deriveSigningKey(SECRET)), DERIVED_KEY);
  assert.equal(hexOf(await deriveSigningKey(SECRET, "webcrypto")), DERIVED_KEY);
  assert.equal(hexOf(deriveSigningKeySync(SECRET)), DERIVED_KEY);
});

test("known-answer vector (async node backend)", async () => {
  assert.equal(await computeSignature(SECRET, T, BODY), EXPECTED_V1);
  assert.equal(await verifyWebhookSignature(SECRET, BODY, HEADER, { now: T }), true);
});

test("known-answer vector (forced Web Crypto backend)", async () => {
  assert.equal(await computeSignature(SECRET, T, BODY, "webcrypto"), EXPECTED_V1);
  assert.equal(
    await verifyWebhookSignature(SECRET, BODY, HEADER, { now: T, backend: "webcrypto" }),
    true);
});

test("known-answer vector (sync node:crypto)", () => {
  assert.equal(computeSignatureSync(SECRET, T, BODY), EXPECTED_V1);
  assert.equal(verifyWebhookSignatureSync(SECRET, BODY, HEADER, { now: T }), true);
});

test("Uint8Array body and secret accepted", async () => {
  const enc = new TextEncoder();
  assert.equal(
    await verifyWebhookSignature(enc.encode(SECRET), enc.encode(BODY), HEADER, { now: T }),
    true);
  assert.equal(
    verifyWebhookSignatureSync(enc.encode(SECRET), enc.encode(BODY), HEADER, { now: T }),
    true);
});

test("tolerance edges accepted (±300s)", async () => {
  assert.equal(await verifyWebhookSignature(SECRET, BODY, HEADER, { now: T + 300 }), true);
  assert.equal(await verifyWebhookSignature(SECRET, BODY, HEADER, { now: T - 300 }), true);
  assert.equal(verifyWebhookSignatureSync(SECRET, BODY, HEADER, { now: T + 300 }), true);
});

test("expired and future timestamps rejected", async () => {
  assert.equal(await verifyWebhookSignature(SECRET, BODY, HEADER, { now: T + 301 }), false);
  assert.equal(await verifyWebhookSignature(SECRET, BODY, HEADER, { now: T - 301 }), false);
  assert.equal(verifyWebhookSignatureSync(SECRET, BODY, HEADER, { now: T + 301 }), false);
});

test("custom tolerance", async () => {
  assert.equal(
    await verifyWebhookSignature(SECRET, BODY, HEADER, { now: T + 60, tolerance: 30 }),
    false);
});

test("wrong secret rejected", async () => {
  assert.equal(await verifyWebhookSignature("whsec_wrong", BODY, HEADER, { now: T }), false);
  assert.equal(verifyWebhookSignatureSync("whsec_wrong", BODY, HEADER, { now: T }), false);
});

test("tampered body rejected", async () => {
  const tampered = BODY.replace("verified", "rejected");
  assert.equal(await verifyWebhookSignature(SECRET, tampered, HEADER, { now: T }), false);
  assert.equal(verifyWebhookSignatureSync(SECRET, tampered, HEADER, { now: T }), false);
});

test("tampered timestamp rejected", async () => {
  const header = `t=${T + 1},v1=${EXPECTED_V1}`;
  assert.equal(await verifyWebhookSignature(SECRET, BODY, header, { now: T }), false);
  assert.equal(verifyWebhookSignatureSync(SECRET, BODY, header, { now: T }), false);
});

test("extra header segments tolerated", async () => {
  const header = `t=${T},v1=${EXPECTED_V1},v0=ignored`;
  assert.equal(await verifyWebhookSignature(SECRET, BODY, header, { now: T }), true);
});

test("malformed headers throw WebhookSignatureError", async () => {
  const bad = [
    "",
    "garbage",
    `v1=${EXPECTED_V1}`,
    `t=${T}`,
    "t=notanumber,v1=deadbeef",
  ];
  for (const header of bad) {
    await assert.rejects(
      verifyWebhookSignature(SECRET, BODY, header, { now: T }),
      WebhookSignatureError);
    assert.throws(
      () => verifyWebhookSignatureSync(SECRET, BODY, header, { now: T }),
      WebhookSignatureError);
  }
});

test("parseSignatureHeader", () => {
  const { t, v1 } = parseSignatureHeader(HEADER);
  assert.equal(t, T);
  assert.equal(v1, EXPECTED_V1);
});
