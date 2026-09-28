# fraudfusion-python

Official Python SDK for the FraudFusion API: KYC/KYB verification, national &
cultural fraud intelligence, and webhook signature verification.

- Single dependency: `httpx` (sync client). Python ≥ 3.9.
- Auth via `X-API-Key` (`ffk_live_…` / `ffk_test_…`).
- Typed errors, automatic retry with jitter on 429/5xx (max 3 retries),
  automatic `Idempotency-Key` on POSTs.
- `verify_webhook_signature()` implementing the exact FraudFusion signing
  scheme (constant-time, ±300s replay tolerance).

## Install

```bash
pip install ./sdks/python        # from the repo checkout
# (or) pip install fraudfusion   # once published
```

## Getting API keys

Request a key via the onboarding portal (`POST /api/v1/onboarding/api-keys`)
or have an operator issue one through billing-service
(`POST /v1/billing/api-keys`). The raw key is shown **once** at issuance —
store it in a secrets manager.

Two key classes exist; never mix them up:

| Prefix       | Class | Usage |
|---|---|---|
| `ffk_live_…` | live  | Production. Meters billable usage. |
| `ffk_test_…` | test  | Sandbox/development. Never meters revenue usage (`environment:"test"`). |

## Quickstart (sandbox)

The developer sandbox (`services/python/sandbox`, port **8091**) mirrors the
data-plane shapes with deterministic synthetic data. It accepts **any**
`ffk_test_*` key (prefix check only, 60 rpm) and rejects `ffk_live_*`.
Every response carries `"environment": "sandbox"` and `"synthetic": true`.

```python
from fraudfusion import FraudFusionClient

client = FraudFusionClient(
    api_key="ffk_test_dev",                 # any ffk_test_ key works in sandbox
    base_url="http://localhost:8091",       # default; pass your live gateway URL in prod
)

# KYC — levels: "basic" (default) | "enhanced" | "premium"
result = client.kyc_verify(
    customer_id="cus_sandbox_001",
    first_name="Adaeze", last_name="Okonkwo",
    bvn="22300000000", nin="70123456000",
    phone="+2348010000001", email="dev@sandbox.example",
    date_of_birth="1990-01-01",
)
print(result["decision"], result["risk_score"], result["request_id"])

# Poll the status later
status = client.kyc_status(result["request_id"])

# Document verification (multipart upload; bytes, file object, or path)
doc = client.document_verify(open("id.png", "rb"), "national_id", check_forgery=True)
print(doc["status"], doc["verification_id"])

# Biometric verification (base64 string or raw bytes — bytes are encoded for you)
bio = client.biometric_verify(selfie_bytes, reference=portrait_bytes, check_liveness=True)
print(bio["status"], bio["face_match"])

# KYB — document content is verified but never persisted server-side (hash-only)
app = client.kyb_submit(
    business_name="Acme Ltd", cac_number="RC1234567",
    contact_email="ops@acme.example",
    documents=[{"type": "cac_certificate", "reference": "s3://bucket/cac.pdf"}],
)
verdict = client.kyb_get_verification(app["applicationId"])

# Fraud intelligence
summary = client.intel_national_summary()
hotspots = client.intel_hotspots(k=5)
cal = client.intel_cultural_calendar("2026-03-20", state="kano")
ajo = client.intel_cultural_ajo_assess(
    n_members=12, contribution_cv=0.1, cadence_cv=0.2,
    rotation_coverage=1.0, payout_ratio=1.0, tenure_days=400)
score = client.intel_cultural_score({"event_window_mismatch": 0.8},
                                    claimed_event="ramadan", date="2026-03-01")
legit = client.intel_legitimacy_assess(
    requesting_entity_type="road_safety",
    fields_requested=["bvn", "otp"], channel="sms", link_present=True)

client.close()  # or use `with FraudFusionClient(...) as client:`
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

`GET /sandbox/fixtures` lists all seeded customers. Full fixture docs:
`services/python/sandbox/README.md`.

## Webhooks

### 1. Register an endpoint

```python
created = client.webhook_create(
    "https://your-app.example/webhooks/fraudfusion",
    ["kyc.verification.completed", "kyb.verification.completed",
     "identity.exposure.detected"],
    description="primary receiver",
)
SECRET = created["secret"]      # whsec_… — shown ONCE; store it now
print(client.webhooks_list())
print(client.webhook_deliveries(created["id"]))   # attempt history / dead-letters
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
tolerance = |now - t| <= 300 s, constant-time compare (hmac.compare_digest)
```

```python
from fraudfusion import verify_webhook_signature, WebhookSignatureError

@app.post("/webhooks/fraudfusion")
async def receive(request):
    body = await request.body()          # RAW bytes — verify BEFORE json parsing
    try:
        ok = verify_webhook_signature(
            SECRET, body, request.headers["X-FraudFusion-Signature"])
    except WebhookSignatureError:
        return Response(status_code=400)  # malformed header
    if not ok:
        return Response(status_code=401)  # bad signature or stale timestamp
    event = json.loads(body)
    ...                                  # handle event["type"]
    return Response(status_code=200)
```

The sandbox can fire a signed test event at your receiver end-to-end:
`POST /sandbox/trigger-event` with `{"url": "https://…/webhooks/fraudfusion",
"event_type": "kyc.verification.completed"}` — demo secret
`whsec_demo0000000000000000000000000000`.

## Error model

Every non-2xx response raises a typed exception (after retries for 429/5xx):

| Status | Exception |
|---|---|
| 400 / 422 | `ValidationError` |
| 401 | `AuthenticationError` — key missing/invalid/revoked |
| 403 | `PermissionError` — valid key, missing scope / wrong tenant |
| 404 | `NotFoundError` |
| 409 | `ConflictError` — idempotency-key conflict, state conflicts |
| 429 | `RateLimitError` (`.retry_after` seconds when the server hints) |
| 5xx | `ServerError` (after retries are exhausted) |
| network | `FraudFusionError` (after retries are exhausted) |

All exceptions carry `.status_code`, `.detail` (the server's `detail`
message) and `.body` (raw parsed body). Catch `FraudFusionError` to handle
everything. Note: `fraudfusion.PermissionError` intentionally shadows the
builtin within the package namespace — import it explicitly.

## Retries

429 and 5xx responses — and connection errors — are retried up to
`max_retries` (default **3**) with exponential backoff + full jitter; a
`Retry-After` header on 429 is honoured when longer than the backoff. 4xx
responses are never retried. Tune via
`FraudFusionClient(..., max_retries=3, retry_base_delay=0.5)`.

## Idempotency

Mutating KYC endpoints accept an `Idempotency-Key` header: the first response
is replayed for 24h on a repeated key; the same key with a **different**
payload returns `409 ConflictError`. The client attaches a fresh random UUID
to every POST automatically. To control it:

```python
from fraudfusion import new_idempotency_key

key = new_idempotency_key()
client.kyc_verify(..., idempotency_key=key)      # safe to retry with the same key
client.kyc_verify(..., idempotency_key=False)    # opt out entirely
```

Pass your own key when the caller already has a natural idempotency identity
(e.g. an internal transaction id) so cross-process retries collapse to one
verification.

## Development

```bash
pip install -e ".[dev]"     # or: pip install httpx pytest
python -m pytest tests/     # 50 tests, fully offline (httpx.MockTransport)
```

The webhook verifier is pinned by a known-answer vector shared byte-for-byte
with the TypeScript SDK and cross-checked against the webhook-service signer
(`services/python/webhook-service/app/signing.py`).
