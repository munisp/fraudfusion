# Design-Partner Demo — 15-Minute Runbook

Every command below was executed against the current tree (Round 10) and
produces the output shown. Requires: Python 3.12 (`pip install -r
services/python/sandbox/requirements.txt`), curl, and optionally
`sdks/python` (`pip install -e sdks/python`).

## 0. Start the sandbox (30 seconds)

```bash
cd services/python/sandbox
uvicorn app.main:create_app --factory --port 8091
```

All calls use header `X-API-Key: ffk_test_demo123` (any `ffk_test_*` works;
`ffk_live_*` is rejected with an explicit environment error — show this!).

## 1. Deterministic KYC fixtures (3 min)

```bash
curl -s -X POST localhost:8091/api/v1/kyc/verify/basic \
  -H "X-API-Key: ffk_test_demo123" -H "Content-Type: application/json" \
  -d '{"customer_id":"cust-1","first_name":"Demo","last_name":"User",
       "bvn":"12345678000","nin":"12345678000",
       "date_of_birth":"1990-01-01","phone":"08031234567"}'
```

BVN ending **000 → "approved"**, **001 → "manual_review"**,
**002 → "rejected"**, **003 → rejected with sanctions hit**
(`verification_results.sanctions_screening.is_sanctioned = true`).
Every response carries `"environment":"sandbox"` + `"synthetic":true`.

## 2. SDK happy path (2 min)

```python
from fraudfusion import FraudFusion
sdk = FraudFusion(base_url="http://localhost:8091", api_key="ffk_test_demo123")
sdk.kyc_verify_basic(customer_id="cust-1", first_name="Demo",
                     last_name="User", bvn="12345678000")
# -> decision "approved" (same fixture table, typed errors on 4xx/5xx)
```

## 3. Signed webhooks end-to-end (4 min)

```bash
# terminal 1: tiny receiver that verifies the signature with the SDK helper
python3 - <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
from fraudfusion.webhook import verify_webhook_signature
SECRET = "whsec_demo0000000000000000000000000000"
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        ok = verify_webhook_signature(
            SECRET, body, self.headers["X-FraudFusion-Signature"])
        print("webhook received, signature_valid =", ok)
        self.send_response(200); self.end_headers()
HTTPServer(("127.0.0.1", 9099), H).serve_forever()
EOF

# terminal 2: fire a synthetic signed event at it
curl -s -X POST localhost:8091/sandbox/trigger-event \
  -H "X-API-Key: ffk_test_demo123" -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:9099/hook",
       "event_type":"kyc.verification.completed"}'
# -> terminal 1 prints: webhook received, signature_valid = True
```

## 4. Liveness challenge (2 min)

```bash
curl -s -X POST localhost:8091/api/v1/biometric/liveness/challenge \
  -H "X-API-Key: ffk_test_demo123"
# -> signed challenge {challenge_id, phases, expires_at, signature}
```

(Live verdict path runs in kyc-api with `LIVENESS_CHALLENGE_SECRET` set; the
browser widget `sdks/capture-web` drives the full capture UX.)

## 5. Registry dry-run (3 min) — the "plug-ready" story

The sandbox mirrors the NIBSS/NIMC/CAC response shapes:

```bash
curl -s "localhost:8091/sandbox/registry/bvn/verify?bvn=12345678000"
# -> {"match": true, "verified_fields": ["name","date_of_birth"], ...}
curl -s "localhost:8091/sandbox/registry/company/lookup?rc=RC123456"
# -> {"company": {"status": "ACTIVE", ...}}
```

Point a kyc-api deployment at the doubles —

```bash
export NIBSS_BVN_URL=http://localhost:8091/sandbox/registry
export NIMC_API_URL=http://localhost:8091/sandbox/registry
export CAC_API_URL=http://localhost:8091/sandbox/registry
```

— and `/api/v1/registry/bvn/verify` runs the REAL production adapter code
end-to-end. Swapping those URLs to the live registries (post-procurement)
activates the identical codepath. This is verified in CI by
`tests/test_registry_conformance.py` (23 tests incl. a real uvicorn round
trip).

## 5b. Land due-diligence dry-run (3 min) — the "verify the title" story

The sandbox also doubles the lands registry (Round 11):

```bash
curl -s "localhost:8091/sandbox/registry/lands/owner?state=lagos&certificate_number=CERT-4521"
# -> {"status":"found","owner_name":"SANDBOX LANDOWNER 4521",...}
```

Then against land-verification-service:

```bash
# 1. Pre-purchase composite verdict (registry cross-check + claimants +
#    consents + disputes + revocations)
curl -s localhost:8002/api/v1/due-diligence -H 'Content-Type: application/json' -d '{
  "state":"Lagos","certificate_number":"CERT-4521","claimed_owner":"SANDBOX LANDOWNER 4521"}'
# -> {"verdict":"clear",...}   (CERT-0008 -> owner_mismatch high_risk; CERT-0009 -> registry_not_found)

# 2. First-wins parcel registration — a second registration of the same
#    certificate is the multiple-sale alarm (409 / disputed + conflict record)
curl -s -X POST localhost:8002/api/v1/parcels -H 'Content-Type: application/json' -d '{
  "parcel_ref":"PLT-452","state":"Lagos","certificate_number":"CERT-4521",
  "consent_required":["Family Head","Heir One"]}'

# 3. Deed template conformance + consents, then the court-grade evidence pack
curl -s -X POST localhost:8002/api/v1/deeds/conformance -H 'Content-Type: application/json' \
  -d '{"deed_text":"...","consent_parties":["Family Head"]}'
curl -s localhost:8002/api/v1/parcels/PLT-452/evidence   # hash-chained, verifies offline
```

## 6. Honesty moments (sprinkle throughout)

- `GET /api/v1/registry/status` with no URLs configured → every registry
  `available: false` with the reason — **nothing is ever fabricated**.
- KYB fixture: `RC000000 → verified`, `RC000001 → manual_review`,
  `RC000002 → rejected`.
- Close with the audit trail: every verdict above wrote a hash-only
  provenance row — show `document_verifications` in the kyc-api DB.
