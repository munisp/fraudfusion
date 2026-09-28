# fraudfusion (TypeScript)

Official **zero-runtime-dependency** TypeScript SDK for the FraudFusion API:
KYC/KYB verification, national & cultural fraud intelligence, and webhook
signature verification. Works on **Node 18+** and in **modern browsers /
edge runtimes** (global `fetch`, `FormData`, `crypto.subtle`).

- No runtime dependencies — pure `fetch` + platform crypto.
- Full TypeScript types mirroring the API responses (`.d.ts` shipped).
- Auth via `X-API-Key` (`ffk_live_…` / `ffk_test_…`).
- Typed errors, automatic retry with jitter on 429/5xx (max 3 retries),
  automatic `Idempotency-Key` on POSTs.
- Webhook verification via `node:crypto` `createHmac` + `timingSafeEqual`,
  with automatic Web Crypto (`subtle`) fallback for browser/edge; a
  synchronous Node-only variant is exposed under the `fraudfusion/node`
  subpath.

## Install

```bash
npm install ./sdks/typescript     # from the repo checkout
# (or) npm install fraudfusion    # once published
```

## Getting API keys

Request a key via the onboarding portal (`POST /api/v1/onboarding/api-keys`)
or have an operator issue one through billing-service
(`POST /v1/billing/api-keys`). The raw key is shown **once** at issuance.

| Prefix       | Class | Usage |
|---|---|---|
| `ffk_live_…` | live  | Production. Meters billable usage. |
| `ffk_test_…` | test  | Sandbox/development. Never meters revenue usage. |

## Quickstart (sandbox)

The developer sandbox (`services/python/sandbox`, port **8091**) mirrors the
data-plane shapes with deterministic synthetic data. It accepts **any**
`ffk_test_*` key (60 rpm) and rejects `ffk_live_*`. Every response carries
`"environment": "sandbox"` and `"synthetic": true`.

```ts
import { FraudFusionClient } from "fraudfusion";

const client = new FraudFusionClient({
  apiKey: "ffk_test_dev",               // any ffk_test_ key works in sandbox
  baseUrl: "http://localhost:8091",     // default; pass your live gateway URL in prod
});

// KYC — levels: "basic" (default) | "enhanced" | "premium"
const kyc = await client.kycVerify({
  customer_id: "cus_sandbox_001",
  first_name: "Adaeze", last_name: "Okonkwo",
  bvn: "22300000000", date_of_birth: "1990-01-01",
});
console.log(kyc.decision, kyc.risk_score, kyc.request_id);
const status = await client.kycStatus(kyc.request_id);

// Document verification (multipart; Blob or raw bytes)
const doc = await client.documentVerify(pngBytes, "national_id", {
  filename: "id.png", contentType: "image/png", checkForgery: true,
});

// Biometric verification (base64 string or raw bytes)
const bio = await client.biometricVerify(selfieBytes, {
  reference: portraitBytes, checkLiveness: true,
});

// KYB — document content is verified but never persisted server-side (hash-only)
const app = await client.kybSubmit({
  businessName: "Acme Ltd", cacNumber: "RC1234567",
  contactEmail: "ops@acme.example",
  documents: [{ type: "cac_certificate", reference: "s3://bucket/cac.pdf" }],
});
const verdict = await client.kybGetVerification(app.applicationId);

// Fraud intelligence
const summary = await client.intelNationalSummary();
const hotspots = await client.intelHotspots({ k: 5 });
const cal = await client.intelCulturalCalendar("2026-03-20", "kano");
const ajo = await client.intelCulturalAjoAssess({
  n_members: 12, contribution_cv: 0.1, cadence_cv: 0.2,
  rotation_coverage: 1.0, payout_ratio: 1.0, tenure_days: 400,
});
const score = await client.intelCulturalScore({
  indicators: { event_window_mismatch: 0.8 },
  claimed_event: "ramadan", date: "2026-03-01",
});
const legit = await client.intelLegitimacyAssess({
  requesting_entity_type: "road_safety",
  fields_requested: ["bvn", "otp"], channel: "sms", link_present: true,
});
```

### Sandbox fixtures (deterministic)

| Input | Result |
|---|---|
| BVN ending `000` | `approved` |
| BVN ending `001` | `manual_review` (PEP fixture at enhanced/premium) |
| BVN ending `002` | `rejected` |
| BVN ending `003` | `rejected` (sanctions hit, every level) |
| KYB `cacNumber` `RC000000` / `RC000001` / `RC000002` | verified / manual_review / rejected |
| Document filename containing `reject`/`fail` / `review` | rejected / manual_review |

Full fixture docs: `services/python/sandbox/README.md`
(`GET /sandbox/fixtures` lists all seeded customers).

## Webhooks

### 1. Register an endpoint

```ts
const created = await client.webhookCreate(
  "https://your-app.example/webhooks/fraudfusion",
  ["kyc.verification.completed", "kyb.verification.completed",
   "identity.exposure.detected"],
  { description: "primary receiver" },
);
const SECRET = created.secret!;         // whsec_… — shown ONCE; store it now
await client.webhooksList();
await client.webhookDeliveries(created.id);   // attempt history / dead-letters
```

### 2. Verify deliveries

Events arrive as `POST` with header
`X-FraudFusion-Signature: t=<unix_ts>,v1=<hex hmac-sha256>` and an envelope
body `{"id","type","created_at","tenant_id","data"}`.

Because webhook secrets are stored **hash-only** server-side, the HMAC key at
delivery time is *derived* from the secret — the SDK performs this derivation
for you (and you must NOT skip it if you verify manually):

```
key       = sha256(secret).hexdigest().encode("utf-8")
v1        = HMAC-SHA256(key, "<t>.<raw body>")
tolerance = |now - t| <= 300 s, constant-time compare
            (node:crypto timingSafeEqual; constant-time byte compare on
             Web Crypto runtimes)
```

```ts
import { verifyWebhookSignature, WebhookSignatureError } from "fraudfusion";
// Node-only sync variant: import { verifyWebhookSignatureSync } from "fraudfusion/node";

// Express / Fastify / Hono / edge — verify the RAW body BEFORE JSON parsing:
const raw = await request.text();       // or a Buffer/Uint8Array
try {
  const ok = await verifyWebhookSignature(
    SECRET, raw, request.headers.get("X-FraudFusion-Signature") ?? "");
  if (!ok) return new Response("invalid signature", { status: 401 });
} catch (err) {
  if (err instanceof WebhookSignatureError)
    return new Response("malformed signature header", { status: 400 });
  throw err;
}
const event = JSON.parse(raw);          // { id, type, created_at, tenant_id, data }
```

The sandbox can fire a signed test event at your receiver end-to-end:
`POST /sandbox/trigger-event` with `{"url": "https://…/webhooks/fraudfusion",
"event_type": "kyc.verification.completed"}` — demo secret
`whsec_demo0000000000000000000000000000`.

## Error model

Every non-2xx response throws a typed error (after retries for 429/5xx):

| Status | Error |
|---|---|
| 400 / 422 | `ValidationError` |
| 401 | `AuthenticationError` — key missing/invalid/revoked |
| 403 | `PermissionError` — valid key, missing scope / wrong tenant |
| 404 | `NotFoundError` |
| 409 | `ConflictError` — idempotency-key conflict, state conflicts |
| 429 | `RateLimitError` (`.retryAfter` seconds when the server hints) |
| 5xx | `ServerError` (after retries are exhausted) |
| network | `FraudFusionError` (after retries are exhausted) |

All errors carry `.statusCode`, `.detail` and `.body`; catch
`FraudFusionError` to handle everything.

```ts
import { FraudFusionError, RateLimitError } from "fraudfusion";
try {
  await client.kycVerify({ ... });
} catch (err) {
  if (err instanceof RateLimitError) { /* err.retryAfter */ }
  else if (err instanceof FraudFusionError) { /* err.statusCode, err.detail */ }
}
```

## Retries

429 and 5xx responses — and network errors — are retried up to `maxRetries`
(default **3**) with exponential backoff + full jitter; a `Retry-After`
header on 429 is honoured when longer than the backoff. 4xx responses are
never retried. Tune via
`new FraudFusionClient({ ..., maxRetries: 3, retryBaseDelayMs: 500 })`.

## Idempotency

Mutating KYC endpoints accept an `Idempotency-Key` header: the first response
is replayed for 24h on a repeated key; the same key with a **different**
payload returns `409 ConflictError`. The client attaches a fresh random UUID
(`crypto.randomUUID`) to every POST automatically. To control it:

```ts
import { newIdempotencyKey } from "fraudfusion";

const key = newIdempotencyKey();
await client.kycVerify(req, { idempotencyKey: key });   // safe to retry
await client.kycVerify(req, { idempotencyKey: false }); // opt out
```

## Development

```bash
npm install          # dev-only: typescript + @types/node
npm test             # tsc build + node --test (45 tests, fully offline)
npm run build        # emit dist/ (JS + .d.ts)
```

Tests use the zero-dependency `node:test` runner with an injected mock
`fetch` — no network. The webhook verifier is pinned by a known-answer
vector shared byte-for-byte with the Python SDK and cross-checked against
the webhook-service signer (`services/python/webhook-service/app/signing.py`);
both the `node:crypto` and forced-`webcrypto` paths are tested.
