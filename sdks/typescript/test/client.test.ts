/** Client tests — fully offline via an injected mock fetch (no network). */

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  AuthenticationError,
  ConflictError,
  FraudFusionClient,
  FraudFusionError,
  newIdempotencyKey,
  NotFoundError,
  PermissionError,
  RateLimitError,
  ServerError,
  ValidationError,
} from "../src/index.js";

const API_KEY = "ffk_test_" + "ab".repeat(16);
const BASE = "http://sandbox.test";

interface Captured {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  if (status === 204) return new Response(null, { status });
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function mockClient(
  handler: (call: Captured, index: number) => Response | Promise<Response>,
  options: Partial<ConstructorParameters<typeof FraudFusionClient>[0]> = {},
) {
  const calls: Captured[] = [];
  const fetchImpl: typeof fetch = (async (url: unknown, init: RequestInit = {}) => {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(init.headers ?? {})) {
      headers[k] = String(v);
    }
    const call: Captured = {
      url: String(url),
      method: init.method ?? "GET",
      headers,
      body: init.body,
    };
    calls.push(call);
    return handler(call, calls.length - 1);
  }) as typeof fetch;
  const client = new FraudFusionClient({
    apiKey: API_KEY,
    baseUrl: BASE,
    retryBaseDelayMs: 0,
    fetch: fetchImpl,
    ...options,
  });
  return { client, calls };
}

function routeClient(routes: Record<string, [unknown, number?] | unknown>) {
  return mockClient((call) => {
    const key = `${call.method} ${new URL(call.url).pathname}`;
    assert.ok(key in routes, `no route for ${key}`);
    const out = routes[key];
    const [body, status] = Array.isArray(out) ? out : [out, 200];
    return jsonResponse(body, status as number);
  });
}

// ---------------------------------------------------------------
// auth header + idempotency
// ---------------------------------------------------------------

test("X-API-Key header and auto Idempotency-Key on POST", async () => {
  const { client, calls } = routeClient({
    "POST /api/v1/kyc/verify/basic": { request_id: "r1" },
  });
  await client.kycVerify({ customer_id: "c1", first_name: "Ada", last_name: "Lovelace" });
  assert.equal(calls[0].headers["X-API-Key"], API_KEY);
  assert.ok(calls[0].headers["Idempotency-Key"]);
  assert.deepEqual(JSON.parse(calls[0].body as string), {
    customer_id: "c1", first_name: "Ada", last_name: "Lovelace",
  });
});

test("explicit idempotencyKey passed through; false opts out", async () => {
  const key = newIdempotencyKey();
  const { client, calls } = routeClient({
    "POST /api/v1/kyc/verify/basic": {},
  });
  await client.kycVerify(
    { customer_id: "c", first_name: "a", last_name: "b" },
    { idempotencyKey: key });
  assert.equal(calls[0].headers["Idempotency-Key"], key);
  await client.kycVerify(
    { customer_id: "c", first_name: "a", last_name: "b" },
    { idempotencyKey: false });
  assert.ok(!("Idempotency-Key" in calls[1].headers));
});

// ---------------------------------------------------------------
// KYC
// ---------------------------------------------------------------

test("kycVerify levels: screening flags stripped on basic, kept on enhanced/premium", async () => {
  const { client, calls } = routeClient({
    "POST /api/v1/kyc/verify/basic": {},
    "POST /api/v1/kyc/verify/enhanced": {},
    "POST /api/v1/kyc/verify/premium": {},
  });
  const base = { customer_id: "c", first_name: "a", last_name: "b" };
  await client.kycVerify({ ...base, check_pep: true });
  await client.kycVerify({ ...base, level: "enhanced", check_pep: true, nationality: "NG" });
  await client.kycVerify({
    ...base, level: "premium", check_credit_bureau: true,
    credit_bureau_provider: "crc",
  });
  const basic = JSON.parse(calls[0].body as string);
  assert.ok(!("check_pep" in basic));
  assert.equal(new URL(calls[0].url).pathname, "/api/v1/kyc/verify/basic");
  const enhanced = JSON.parse(calls[1].body as string);
  assert.equal(enhanced.check_pep, true);
  assert.equal(enhanced.nationality, "NG");
  const premium = JSON.parse(calls[2].body as string);
  assert.equal(premium.check_credit_bureau, true);
  assert.equal(premium.credit_bureau_provider, "crc");
});

test("kycVerify rejects an unknown level", async () => {
  const { client } = routeClient({});
  assert.throws(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    () => client.kycVerify({ customer_id: "c", first_name: "a", last_name: "b", level: "gold" as any }),
    /level must be/);
});

test("kycStatus path", async () => {
  const { client, calls } = routeClient({
    "GET /api/v1/kyc/status/req123": { decision: "approved" },
  });
  const out = await client.kycStatus("req123");
  assert.equal(out.decision, "approved");
  assert.equal(new URL(calls[0].url).pathname, "/api/v1/kyc/status/req123");
});

// ---------------------------------------------------------------
// document / biometric
// ---------------------------------------------------------------

test("documentVerify sends multipart FormData", async () => {
  const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const { client, calls } = routeClient({
    "POST /api/v1/document/verify": { status: "verified", detected_format: "png" },
  });
  const out = await client.documentVerify(png, "national_id", {
    filename: "id.png", contentType: "image/png", checkForgery: true,
  });
  assert.equal(out.status, "verified");
  const form = calls[0].body as FormData;
  assert.ok(form instanceof FormData);
  assert.equal(form.get("document_type"), "national_id");
  assert.equal(form.get("check_forgery"), "true");
  const file = form.get("document") as File;
  assert.equal(file.name, "id.png");
  assert.equal(file.size, png.length);
});

test("documentVerify checkForgery=false", async () => {
  const { client, calls } = routeClient({
    "POST /api/v1/document/verify": {},
  });
  await client.documentVerify(new Uint8Array([1, 2, 3]), "cac_certificate",
    { checkForgery: false });
  assert.equal((calls[0].body as FormData).get("check_forgery"), "false");
});

test("biometricVerify base64-encodes raw bytes", async () => {
  const selfie = new Uint8Array([0xff, 0xd8, 0xff, 0x41]);
  const { client, calls } = routeClient({
    "POST /api/v1/biometric/verify": { status: "verified" },
  });
  await client.biometricVerify(selfie, { reference: new Uint8Array([1]) });
  const body = JSON.parse(calls[0].body as string);
  assert.equal(body.selfie_image_base64, Buffer.from(selfie).toString("base64"));
  assert.equal(body.reference_image_base64, Buffer.from([1]).toString("base64"));
  assert.equal(body.check_liveness, true);
});

// ---------------------------------------------------------------
// KYB
// ---------------------------------------------------------------

test("kybSubmit sends camelCase payload with default businessType", async () => {
  const { client, calls } = routeClient({
    "POST /api/v1/onboarding/kyb": [{ applicationId: "app_1", status: "submitted" }, 201],
  });
  const out = await client.kybSubmit({
    businessName: "Acme Ltd",
    cacNumber: "RC1234567",
    contactEmail: "ops@acme.example",
    documents: [{ type: "cac_certificate", reference: "s3://bucket/cac.pdf" }],
  });
  assert.equal(out.applicationId, "app_1");
  const body = JSON.parse(calls[0].body as string);
  assert.deepEqual(body, {
    businessName: "Acme Ltd",
    cacNumber: "RC1234567",
    businessType: "limited_liability",
    contactEmail: "ops@acme.example",
    documents: [{ type: "cac_certificate", reference: "s3://bucket/cac.pdf" }],
  });
});

test("kybGet / kybGetVerification paths", async () => {
  const { client } = routeClient({
    "GET /api/v1/onboarding/kyb/app_1": { applicationId: "app_1" },
    "GET /api/v1/onboarding/kyb/app_1/verification": { verdict: "verified" },
  });
  assert.equal((await client.kybGet("app_1")).applicationId, "app_1");
  assert.equal((await client.kybGetVerification("app_1")).verdict, "verified");
});

// ---------------------------------------------------------------
// intel
// ---------------------------------------------------------------

test("intel national/states/hotspots/typology paths and params", async () => {
  const { client, calls } = routeClient({
    "GET /v1/intel/national/summary": { national_fraud_rate: { posterior_mean: 0.042 } },
    "GET /v1/intel/states": { states: [] },
    "GET /v1/intel/states/lagos": { code: "lagos" },
    "GET /v1/intel/hotspots": { hotspots: [] },
    "GET /v1/intel/typology-mix": { zones: {} },
  });
  await client.intelNationalSummary();
  await client.intelStates();
  await client.intelState("lagos");
  await client.intelHotspots({ k: 5, threshold: 0.05 });
  await client.intelTypologyMix();
  const url = new URL(calls[3].url);
  assert.equal(url.searchParams.get("k"), "5");
  assert.equal(url.searchParams.get("threshold"), "0.05");
});

test("intel cultural endpoints", async () => {
  const { client, calls } = routeClient({
    "GET /v1/intel/cultural/calendar": { active_events: [] },
    "POST /v1/intel/cultural/ajo/assess": { p_legitimate_mean: 0.9 },
    "POST /v1/intel/cultural/score": { cultural_fraud_score: 0.31 },
  });
  await client.intelCulturalCalendar("2026-03-20", "kano");
  const url = new URL(calls[0].url);
  assert.equal(url.searchParams.get("date"), "2026-03-20");
  assert.equal(url.searchParams.get("state"), "kano");
  const ajo = await client.intelCulturalAjoAssess({
    n_members: 12, contribution_cv: 0.1, cadence_cv: 0.2,
    rotation_coverage: 1.0, payout_ratio: 1.0, tenure_days: 400,
  });
  assert.equal(ajo.p_legitimate_mean, 0.9);
  const score = await client.intelCulturalScore({
    indicators: { event_window_mismatch: 0.8 },
    claimed_event: "ramadan",
    date: "2026-03-01",
  });
  assert.equal(score.cultural_fraud_score, 0.31);
});

test("intel legitimacy assess + matrix", async () => {
  const { client, calls } = routeClient({
    "POST /v1/intel/request-legitimacy/assess": { score: 0.95, risk_band: "critical" },
    "GET /v1/intel/request-legitimacy/matrix": { matrix_version: "1.0" },
  });
  const out = await client.intelLegitimacyAssess({
    requesting_entity_type: "road_safety",
    fields_requested: ["bvn", "otp"],
    channel: "sms",
    link_present: true,
  });
  assert.equal(out.risk_band, "critical");
  assert.deepEqual(JSON.parse(calls[0].body as string), {
    requesting_entity_type: "road_safety",
    fields_requested: ["bvn", "otp"],
    channel: "sms",
    link_present: true,
  });
  const matrix = await client.intelLegitimacyMatrix();
  assert.equal(matrix.matrix_version, "1.0");
});

// ---------------------------------------------------------------
// webhooks
// ---------------------------------------------------------------

test("webhooks list/create/delete/deliveries", async () => {
  const { client, calls } = routeClient({
    "GET /v1/webhooks": { endpoints: [] },
    "POST /v1/webhooks": [{ id: "we_1", secret: "whsec_shown_once" }, 201],
    "DELETE /v1/webhooks/we_1": [{}, 204],
    "GET /v1/webhooks/we_1/deliveries": { deliveries: [] },
  });
  await client.webhooksList();
  const created = await client.webhookCreate(
    "https://me.example/hook", ["kyc.verification.completed"],
    { description: "primary" });
  assert.equal(created.secret, "whsec_shown_once");
  const body = JSON.parse(calls[1].body as string);
  assert.deepEqual(body, {
    url: "https://me.example/hook",
    event_types: ["kyc.verification.completed"],
    description: "primary",
  });
  await client.webhookDelete("we_1");
  await client.webhookDeliveries("we_1");
  assert.equal(new URL(calls[3].url).pathname, "/v1/webhooks/we_1/deliveries");
});

// ---------------------------------------------------------------
// error mapping
// ---------------------------------------------------------------

const ERROR_CASES: Array<[number, typeof FraudFusionError]> = [
  [400, ValidationError],
  [401, AuthenticationError],
  [403, PermissionError],
  [404, NotFoundError],
  [409, ConflictError],
  [422, ValidationError],
];

for (const [status, excClass] of ERROR_CASES) {
  test(`HTTP ${status} maps to ${excClass.name}`, async () => {
    const { client } = mockClient(() => jsonResponse({ detail: "boom" }, status));
    await assert.rejects(client.kycStatus("x"), (err: unknown) => {
      assert.ok(err instanceof excClass, `expected ${excClass.name}, got ${String(err)}`);
      const fe = err as FraudFusionError;
      assert.equal(fe.statusCode, status);
      assert.equal(fe.detail, "boom");
      return true;
    });
  });
}

test("non-JSON error body surfaced as detail", async () => {
  const { client } = mockClient(
    () => new Response("<html>bad gateway</html>", { status: 502 }),
    { maxRetries: 0 });
  await assert.rejects(client.kycStatus("x"), (err: unknown) => {
    assert.ok(err instanceof ServerError);
    assert.match((err as ServerError).detail ?? "", /bad gateway/);
    return true;
  });
});

// ---------------------------------------------------------------
// retry semantics
// ---------------------------------------------------------------

test("429 then 200 recovers (2 requests)", async () => {
  const { client, calls } = mockClient((_, i) =>
    i === 0 ? jsonResponse({ detail: "rate limited" }, 429) : jsonResponse({ ok: true }));
  const out = await client.kycStatus("x");
  assert.deepEqual(out, { ok: true });
  assert.equal(calls.length, 2);
});

test("500 sequence recovers within maxRetries", async () => {
  const { client, calls } = mockClient((_, i) =>
    i < 2 ? jsonResponse({ detail: "x" }, 500) : jsonResponse({ ok: 1 }));
  assert.deepEqual(await client.kycStatus("x"), { ok: 1 });
  assert.equal(calls.length, 3);
});

test("5xx exhausted -> ServerError after 1+3 attempts", async () => {
  const { client, calls } = mockClient(() => jsonResponse({ detail: "db down" }, 500));
  await assert.rejects(client.kycStatus("x"), ServerError);
  assert.equal(calls.length, 4);
});

test("429 exhausted -> RateLimitError", async () => {
  const { client, calls } = mockClient(() => jsonResponse({ detail: "slow down" }, 429));
  await assert.rejects(client.kycStatus("x"), RateLimitError);
  assert.equal(calls.length, 4);
});

test("4xx is never retried", async () => {
  const { client, calls } = mockClient(() => jsonResponse({ detail: "nope" }, 403));
  await assert.rejects(client.kycStatus("x"), PermissionError);
  assert.equal(calls.length, 1);
});

test("Retry-After header honoured", async () => {
  const sleeps: number[] = [];
  const { client } = mockClient(
    (_, i) =>
      i === 0
        ? jsonResponse({ detail: "rl" }, 429, { "Retry-After": "7" })
        : jsonResponse({ ok: true }),
    { sleep: async (ms) => { sleeps.push(ms); } });
  await client.kycStatus("x");
  assert.deepEqual(sleeps, [7000]);
});

test("network errors retried then FraudFusionError", async () => {
  const { client, calls } = mockClient(() => {
    throw new Error("ECONNREFUSED");
  });
  await assert.rejects(client.kycStatus("x"), (err: unknown) => {
    assert.ok(err instanceof FraudFusionError);
    assert.match((err as Error).message, /failed after 4 attempts/);
    return true;
  });
  assert.equal(calls.length, 4);
});

test("maxRetries=0 disables retry", async () => {
  const { client, calls } = mockClient(
    () => jsonResponse({ detail: "x" }, 500), { maxRetries: 0 });
  await assert.rejects(client.kycStatus("x"), ServerError);
  assert.equal(calls.length, 1);
});

// ---------------------------------------------------------------
// misc
// ---------------------------------------------------------------

test("constructor validation and baseUrl normalisation", async () => {
  assert.throws(() => new FraudFusionClient({ apiKey: "" }), /apiKey is required/);
  const { client, calls } = mockClient(() => jsonResponse({ ok: 1 }), {
    baseUrl: "http://x.test/",
  });
  await client.kycStatus("y");
  assert.equal(calls[0].url, "http://x.test/api/v1/kyc/status/y");
});

test("204 responses resolve undefined", async () => {
  const { client } = mockClient(() => jsonResponse({}, 204));
  assert.equal(await client.webhookDelete("we_9"), undefined);
});
