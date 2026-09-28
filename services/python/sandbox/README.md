# FraudFusion Developer Sandbox (`:8091`)

> **⚠️ THE SANDBOX IS SYNTHETIC — NO REAL VERIFICATION OCCURS.**
> Every response is deterministic, invented test data. No registries, credit
> bureaus, screening lists, or ML models are consulted. Never use sandbox
> results to make real onboarding decisions. Live API keys (`ffk_live_*`)
> are explicitly rejected here.

A self-contained FastAPI service that mirrors the **response shapes** of the
key FraudFusion data-plane endpoints with deterministic synthetic data, so
third parties can integrate end-to-end — clients, error handling, webhook
receivers — without real data or credentials.

## Quickstart

```bash
# Run locally
pip install -r requirements.txt
python -m uvicorn app.main:app --port 8091

# or Docker
docker build -t fraudfusion-sandbox .
docker run -p 8091:8091 fraudfusion-sandbox
```

Auth: pass **any** `X-API-Key` with the `ffk_test_` prefix (prefix check
only). Rate limit: 60 requests/minute per key.

```bash
KEY="X-API-Key: ffk_test_dev"

# KYC verification (mirrors kyc-api KYCResponse; /verify is an alias for
# /verify/basic — /verify/enhanced and /verify/premium also exist)
curl -s localhost:8091/api/v1/kyc/verify -H "$KEY" -H 'Content-Type: application/json' -d '{
  "customer_id": "cus_sandbox_001", "bvn": "22300000000", "nin": "70123456000",
  "phone": "+2348010000001", "email": "dev@sandbox.example",
  "first_name": "Adaeze", "last_name": "Okonkwo", "date_of_birth": "1990-01-01"
}'

# Document verification (multipart, mirrors kyc-api)
curl -s localhost:8091/api/v1/document/verify -H "$KEY" \
  -F document=@/path/to/id.png -F document_type=national_id -F check_forgery=true

# KYB submission (mirrors onboarding-service KybApplicationView; 201)
curl -s localhost:8091/api/v1/onboarding/kyb -H "$KEY" -H 'Content-Type: application/json' -d '{
  "businessName": "Sandbox Verified Ventures Ltd", "cacNumber": "RC000000",
  "businessType": "limited_liability", "contactEmail": "dev@sandbox.example",
  "documents": [{"type": "cac_certificate", "reference": "s3://sandbox/cac.pdf"}]
}'

# Full KYB verification verdict (use the applicationId from the response above)
curl -s localhost:8091/api/v1/onboarding/kyb/kyb_<id>/verification -H "$KEY"

# National fraud-intel summary (mirrors intel-service)
curl -s localhost:8091/v1/intel/national/summary -H "$KEY"

# Request-legitimacy assessment (mirrors intel-service)
curl -s localhost:8091/v1/intel/request-legitimacy/assess -H "$KEY" \
  -H 'Content-Type: application/json' -d '{
    "requesting_entity_type": "road_safety", "fields_requested": ["bvn", "otp"],
    "channel": "sms", "link_present": true}'

# Cultural fraud score (mirrors intel-service)
curl -s localhost:8091/v1/intel/cultural/score -H "$KEY" \
  -H 'Content-Type: application/json' -d '{"indicators": {"urgency": 0.9}}'
```

### SDKs

The official SDKs work against the sandbox by pointing them at
`http://localhost:8091` with any `ffk_test_*` key:

- **Python** — see `sdks/python/README.md` (quickstart, `kyc.verify`,
  `kyb.submit`, `webhooks.verify_signature`, …)
- **TypeScript** — see `sdks/typescript/README.md` (same surface,
  `verifyWebhookSignature`, …)

## Deterministic fixtures

### BVN magic suffixes (`/api/v1/kyc/verify*`)

| BVN ending | `decision` | Notes |
|---|---|---|
| `000` | `approved` | verified |
| `001` | `manual_review` | PEP fixture hit at enhanced/premium |
| `002` | `rejected` | fixture rejection |
| `003` | `rejected` | **sanctions hit** (`sanctions_screening.is_sanctioned=true`, fires at every level) |
| anything else (well-formed) | `approved` | default |

Malformed identifiers mirror the **real** kyc-api behaviour: the request
succeeds (200) with `decision: "rejected"` and the reason in
`verification_results.bvn/nin.reason` (e.g. `"NIN must be exactly 11 digits"`,
`"NIN cannot be a repeated digit"`). Format checks only — the sandbox skips
the real Luhn/registry checks (`registry_status: "sandbox_synthetic"`).

### KYB CAC numbers (`/api/v1/onboarding/kyb`)

| `cacNumber` | verdict | `status` |
|---|---|---|
| `RC000000` | `verified` | `approved` |
| `RC000001` | `manual_review` | `under_review` |
| `RC000002` | `rejected` | `rejected` |
| anything else well-formed | `verified` | `approved` |

Invalid CAC format → `422` with `"CAC number must look like RC1234567 …"`,
mirroring the real schema validator. Application ids are deterministic
(`kyb_` + sha256 of CAC + business name) so re-submitting returns the same id.

### Document verification (`/api/v1/document/verify`)

Format sniffing (jpeg/png/pdf/gif/webp magic bytes) mirrors kyc-api. Verdict
magic keys on the **filename**: contains `reject`/`fail` → `rejected`;
contains `review` → `manual_review`; otherwise `verified` when structurally
valid (recognized format). Empty upload → `422`; unknown format →
`structurally_valid: false` → `rejected`.

### Seeded test customers

`GET /sandbox/fixtures` returns the 10 seeded synthetic customers
(`cus_sandbox_001`…`cus_sandbox_010`) with their expected decisions and the
three KYB test businesses. Every name/number/email in the fixture set is
invented — there is no real PII anywhere in this service.

## Webhook simulation (`POST /sandbox/trigger-event`)

Fire a synthetic **signed** webhook at your own receiver to test it
end-to-end:

```bash
curl -s localhost:8091/sandbox/trigger-event -H "$KEY" \
  -H 'Content-Type: application/json' -d '{
    "url": "http://localhost:9999/my-receiver",
    "event_type": "kyc.verification.completed",
    "payload_overrides": {"decision": "manual_review"}
  }'
```

Event types: `kyc.verification.completed`, `kyb.verification.completed`,
`identity.exposure.detected`. The envelope is the shared contract
`{"id","type","created_at","tenant_id","data"}`; `payload_overrides` merge
into `data`. The response returns the `signature_header` used, delivery
status, and the demo secret.

### Signature scheme (shared contract — identical to webhook-service)

```
X-FraudFusion-Signature: t=<unix_ts>,v1=<hex hmac-sha256>
v1  = HMAC-SHA256(key = sha256(secret).hexdigest().encode("utf-8"),
                  msg = "<t>.<raw request body>")
```

**The HMAC key is derived** (`sha256(secret).hexdigest()` as UTF-8 bytes),
not the raw secret — webhook endpoints store secrets hash-only, so this
derivation is contractual. Receivers should also enforce a ±300 s timestamp
tolerance and compare with a constant-time compare (`hmac.compare_digest` /
`timingSafeEqual`). The sandbox's demo signing secret (also returned by
`GET /sandbox/fixtures`):

```
whsec_demo0000000000000000000000000000
```

Python verify sketch (or use `verify_webhook_signature` in sdks/python):

```python
import hashlib, hmac, time

def verify(secret: str, body: bytes, header: str, tol: int = 300) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    t, v1 = parts["t"], parts["v1"]
    if abs(int(time.time()) - int(t)) > tol:
        return False
    key = hashlib.sha256(secret.encode()).hexdigest().encode()
    expected = hmac.new(key, f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1)
```

## Auth model

| `X-API-Key` | Result |
|---|---|
| `ffk_test_<anything>` | accepted (prefix check only) |
| `ffk_live_*` | **403** — explicit error: live keys cannot be used in the sandbox |
| missing | `401` |
| other/malformed | `401` |

Rate limit: in-memory sliding window, 60 requests/minute per key → `429`
with `Retry-After`.

## Endpoint coverage (shape mirrors)

| Sandbox | Mirrors |
|---|---|
| `POST /api/v1/kyc/verify{,/basic,/enhanced,/premium}` | kyc-api `KYCResponse` |
| `POST /api/v1/document/verify` | kyc-api document verify envelope |
| `POST /api/v1/onboarding/kyb` | onboarding-service `KybApplicationView` |
| `GET /api/v1/onboarding/kyb/{id}/verification` | onboarding-service KYB verdict envelope |
| `GET /v1/intel/national/summary` | intel-service national summary |
| `POST /v1/intel/request-legitimacy/assess` | intel-service legitimacy scoring (same matrix) |
| `POST /v1/intel/cultural/score` | intel-service cultural score (same weights) |
| `POST /sandbox/trigger-event`, `GET /sandbox/fixtures`, `GET /health` | sandbox-only utilities |

## Limitations

- **Synthetic only** — deterministic fixtures, no registries/models. The
  request-legitimacy matrix is identical to intel-service (it is stateless
  there too); the cultural calendar and ajo model are simplified static
  heuristics (documented in `app/intel.py`).
- KYB registry is **in-memory** — verdicts vanish on restart (404 with an
  honest explanation; re-submit to regenerate — ids are deterministic).
- Rate limiter is single-process, per-instance.
- `trigger-event` delivery is synchronous with a 5 s timeout; delivery
  failures are reported in the response, never raised.

## Tests

```bash
pip install -r requirements-dev.txt
python3 -m pytest tests/ -q     # 66 tests
```
