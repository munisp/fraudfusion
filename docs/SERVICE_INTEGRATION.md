# Service Integration Map — who calls whom, and how

**Status: implemented (Round 18).** Every cross-service call goes through the
shared mesh client (`services/python/integration/mesh.py`) with one contract:
env-configured peer URLs, internal-token/API-key auth, fail-closed
`{"status": "unavailable", "reason": ...}` on any error, provenance
(adapter/service/source/latency) on every result.

## The mesh registry

| Service | Env var | Default port |
|---|---|---|
| kyc-api | `KYC_API_URL` | 8000 |
| land-verification | `LAND_SERVICE_URL` | 8200 |
| intel-service | `INTEL_SERVICE_URL` | 8500 |
| onboarding-service | `ONBOARDING_SERVICE_URL` | 8300 |
| backoffice-api | `BACKOFFICE_API_URL` | 8400 |
| billing-service | `BILLING_SERVICE_URL` | 8600 |
| webhook-service | `WEBHOOK_SERVICE_URL` | 8700 |
| doc-intelligence | `DOC_INTEL_URL` | 8800 |

Auth: `FRAUDFUSION_INTERNAL_TOKEN` (X-Internal-Token) for internal endpoints;
per-service `<NAME>_API_KEY` (X-API-Key) for scope-gated peers such as
kyc-api screening. Unset URL = honestly unavailable, never fabricated.

## Integration edges (implemented)

| Caller | → | Callee | Flow | Nature |
|---|---|---|---|---|
| kyc-api `/risk/assess`, `/risk/fraud-check` | → | intel-service | `intel_national_summary` | **Advisory** enrichment (`national_intelligence` block); never moves the score |
| land `/due-diligence` | → | kyc-api | `kyc_pep_screening` + `kyc_sanctions_screening` on the seller's claimed name | Hits become scored factors (`seller_sanctions_hit` high / `seller_pep_hit` medium); outage → honest block |
| kyc-api, land | → | all peers | `GET /api/v1/integrations/status` | Operator-visible mesh health (configured/reachable/latency per service) |
| kyc-api, onboarding, land | → | webhook-service | `emit_event` (pre-existing) | Fire-and-forget signed events |
| kyc-api, onboarding, land | → | doc-verification engine | in-process embed (default) or `DOC_INTEL_URL` sidecar | Document forensics on every document path |
| Any service | → | doc-intel / ollama sidecars | `deploy/docker-compose.doc-intel.yml` | PaddleOCR + Qwen2.5-VL |
| temporal-orchestrator | → | land (journey endpoints), kyc | pre-existing contracts, pinned by contract tests | Journey orchestration |

## Deployment

`deploy/docker-compose.platform.yml` boots Postgres + the seven python
services with the full registry wired. Combine with
`docker-compose.doc-intel.yml` for the AI sidecars:

```bash
docker compose -f deploy/docker-compose.platform.yml \
               -f deploy/docker-compose.doc-intel.yml up
```

## Invariants (pinned by tests)

1. A peer being down NEVER breaks the caller's own endpoint (200 with an
   honest `unavailable` block).
2. Advisory enrichment NEVER silently moves a score or verdict.
3. Every cross-service result carries provenance.
4. `services/python/integration/tests/test_mesh.py` pins the contract with
   MockTransport; per-service tests pin the fold-ins.
