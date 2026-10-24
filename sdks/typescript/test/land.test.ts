/** Land due-diligence SDK tests (Round 12) — offline via injected mock fetch. */

import assert from "node:assert/strict";
import { test } from "node:test";

import { ConflictError, FraudFusionClient } from "../src/index.js";

const API_KEY = "ffk_test_" + "ab".repeat(16);
const BASE = "http://land.test";

interface Captured { url: string; method: string; body: unknown }

function mockClient(routes: Record<string, { body: unknown; status?: number }>) {
  const calls: Captured[] = [];
  const fetchImpl: typeof fetch = (async (url: unknown, init: RequestInit = {}) => {
    const call: Captured = {
      url: String(url),
      method: init.method ?? "GET",
      body: init.body ? JSON.parse(String(init.body)) : undefined,
    };
    calls.push(call);
    const key = `${call.method} ${new URL(call.url).pathname}`;
    const route = routes[key];
    assert.ok(route, `no route for ${key}`);
    return new Response(JSON.stringify(route.body), {
      status: route.status ?? 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;
  const client = new FraudFusionClient({
    apiKey: API_KEY, baseUrl: BASE, retryBaseDelayMs: 0, maxRetries: 0,
    fetch: fetchImpl,
  });
  return { client, calls };
}

test("landDueDiligence posts payload", async () => {
  const { client, calls } = mockClient({
    "POST /api/v1/due-diligence": { body: { verdict: "clear" } },
  });
  const out = await client.landDueDiligence({
    state: "Lagos", certificate_number: "CERT-1", claimed_owner: "Chief Seller",
  });
  assert.equal(out.verdict, "clear");
  assert.deepEqual(calls[0].body, {
    state: "Lagos", certificate_number: "CERT-1", claimed_owner: "Chief Seller",
  });
});

test("landRegisterParcel defaults consent_required + auto idempotency", async () => {
  const { client, calls } = mockClient({
    "POST /api/v1/parcels": { body: { parcel_ref: "PLT-1", status: "provisional" }, status: 201 },
  });
  const out = await client.landRegisterParcel({ parcel_ref: "PLT-1", state: "Lagos" });
  assert.equal(out.status, "provisional");
  assert.deepEqual((calls[0].body as Record<string, unknown>).consent_required, []);
});

test("landRegisterParcel conflict throws ConflictError", async () => {
  const { client } = mockClient({
    "POST /api/v1/parcels": {
      body: { detail: { error: "parcel_conflict" } }, status: 409,
    },
  });
  await assert.rejects(
    () => client.landRegisterParcel({ parcel_ref: "PLT-1", state: "Lagos" }),
    ConflictError,
  );
});

test("landRecordConsent defaults confirmed=true", async () => {
  const { client, calls } = mockClient({
    "POST /api/v1/parcels/PLT-1/consents": { body: { status: "clear" } },
  });
  const out = await client.landRecordConsent("PLT-1", { party_name: "Party A" });
  assert.equal(out.status, "clear");
  assert.deepEqual(calls[0].body, { party_name: "Party A", confirmed: true });
});

test("landDeedConformance", async () => {
  const { client, calls } = mockClient({
    "POST /api/v1/deeds/conformance": {
      body: { conformant: false, missing: [{ clause: "habendum", description: "..." }] },
    },
  });
  const out = await client.landDeedConformance("DEED", { consent_parties: ["Heir One"] });
  assert.equal(out.conformant, false);
  assert.deepEqual((calls[0].body as Record<string, unknown>).consent_parties, ["Heir One"]);
});

test("land dispute flow", async () => {
  const { client } = mockClient({
    "POST /api/v1/parcels/PLT-1/disputes": { body: { dispute_id: "d1", sla_days: 90 }, status: 201 },
    "POST /api/v1/disputes/d1/resolve": { body: { status: "resolved" } },
    "GET /api/v1/parcels/PLT-1/disputes": { body: { disputes: [], open: 0, sla_breached: 0 } },
  });
  const d = await client.landOpenDispute("PLT-1", { case_number: "LD/1/2026" });
  assert.equal(d.sla_days, 90);
  const r = await client.landResolveDispute("d1", "settled");
  assert.equal(r.status, "resolved");
  const list = await client.landListDisputes("PLT-1");
  assert.equal(list.open, 0);
});

test("land revocation flow", async () => {
  const { client, calls } = mockClient({
    "POST /api/v1/parcels/PLT-1/revocations": {
      body: { revocation_id: "r1", acquisition_lawful: false }, status: 201,
    },
    "POST /api/v1/revocations/r1/documents": { body: { status: "documents_collected" } },
    "POST /api/v1/revocations/r1/compensate": { body: { acquisition_lawful: true } },
  });
  const r = await client.landOpenRevocation("PLT-1", { notice_ref: "GOV-1" });
  assert.equal(r.acquisition_lawful, false);
  await client.landRevocationDocuments("r1");
  const done = await client.landCompensateRevocation("r1", { amount: 5_000_000, method: "transfer" });
  assert.equal(done.acquisition_lawful, true);
  assert.deepEqual(calls[2].body, { amount: 5_000_000, method: "transfer" });
});

test("landEvidencePack", async () => {
  const { client } = mockClient({
    "GET /api/v1/parcels/PLT-1/evidence": { body: { chain_valid: true, entry_count: 2 } },
  });
  const out = await client.landEvidencePack("PLT-1");
  assert.equal(out.chain_valid, true);
});
