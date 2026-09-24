# FraudFusion Onboarding Guide

Per-stakeholder onboarding flows, mapped to the real code and endpoints in this
repository. Each step is marked **[implemented]**, **[partial]**, or
**[missing]** honestly, so integrators know what works today and what is still
on the backlog.

Endpoint base URLs in local development come from `local-e2e/docker-compose.yml`
(postgres, redis, keycloak, permify, mlflow, aml-ml-service, model-router,
land-verification-service, onboarding-service, temporal + temporal-orchestrator,
go-mobile-mock).

---

## 1. Retail customer (KYC tiers)

| Step | Mechanism | Endpoint / file | Status |
| --- | --- | --- | --- |
| Register account | Mobile app registration screen | `mobile/react-native/src/screens/RegisterScreen.tsx` | [implemented] |
| Login (OIDC) | Keycloak-issued token via `react-native-app-auth` | `mobile/react-native/src/services/AuthService.ts` | [implemented] |
| Basic KYC (BVN/NIN) | Tier 1 verification | `POST /api/v1/kyc/verify/basic` (consumed by `frontend/kyc-frontend/src/services/api.ts`, `kycAPI.verifyBasic`) | [partial] — frontend ready; backend route not in this repo |
| Enhanced KYC (PEP/sanctions) | Tier 2 | `POST /api/v1/kyc/verify/enhanced`, `POST /api/v1/screening/pep`, `POST /api/v1/screening/sanctions` | [partial] — frontend ready |
| Premium KYC (credit bureau) | Tier 3 | `POST /api/v1/kyc/verify/premium`, `POST /api/v1/credit-bureau/check` | [partial] — frontend ready |
| Document upload | Presigned upload + complete | `POST /kyc/sessions/:id/documents`, `POST .../documents/:docId/complete` via `MobileApi.beginDocumentUpload` / `completeDocumentUpload` (`DocumentUploadScreen`) | [partial] — mobile client + contract mock only; production backend route missing |
| Biometric enrollment | Device biometrics + server challenge | `POST /kyc/sessions/:id/biometric-challenge`, `POST .../biometric-challenge/:challengeId/complete` via `KYCBiometricScreen` + `BiometricService` | [partial] — mobile client + contract mock only; production backend route missing |
| Video KYC | Recorded session submission | `POST /kyc/sessions/:id/video` via `VideoKYCScreen` | [partial] — mobile client + contract mock only; production backend route missing |
| Session status | Poll KYC session | `GET /kyc/sessions/:id` (`KYCStatusScreen`) | [partial] — mobile client + contract mock only; production backend route missing |

## 2. Business customer (KYB)

| Step | Mechanism | Endpoint / file | Status |
| --- | --- | --- | --- |
| Business verification type | Back-office queue distinguishes individual vs business | `implementations/backoffice-ui/src/pages/KYCVerifications.tsx` | [implemented] (UI) |
| CAC certificate check | CAC public-search verification | `cac_verification` in `services/land-verification-service/api/verification_workflow.py` | [partial] — stub pending CAC integration |
| Corporate documents review | Document review queue | `GET /backoffice/documents/reviews`, `POST /backoffice/documents/reviews/decision` (`backoffice-ui/src/services/api.ts`) | [partial] — UI wired, backend route missing |

## 3. Landlord / property verification

| Step | Mechanism | Endpoint / file | Status |
| --- | --- | --- | --- |
| Submit land document | C of O, survey plan, deed, allocation upload | `POST /api/v1/verify` (`services/land-verification-service`) | [implemented] — requires Keycloak bearer token |
| Registry lookup | State land registry cross-check | workflow `REGISTRY_LOOKUP` state | [partial] — deterministic stub, external registry integration pending |
| Site inspection | Physical inspection gate for unregistered parcels | workflow `SITE_INSPECTION` state (state machine in `api/verification_workflow.py`) | [implemented] as state; inspector app missing |
| Fraud scoring | Rules-based fraud probability | `_detect_fraud` in workflow | [implemented] (rules-v1) |
| Verification report | PDF report | `GET /api/v1/report/{id}` + `reports/generator.py` (reportlab, minimal-PDF fallback) | [implemented] |
| Status tracking | Persisted state machine (SQLite/Postgres) | `GET /api/v1/status/{id}` | [implemented] |

## 4. Professional (surveyor / agent)

| Step | Mechanism | Endpoint / file | Status |
| --- | --- | --- | --- |
| Survey plan lodgement check | Surveyor-General verification | `surveyor_verification` in workflow | [partial] — stub pending integration |
| Coordinate overlap analysis | GIS beacon check | `coordinate_verification` in workflow | [partial] — stub pending GIS integration |

## 5. Back-office staff

| Step | Mechanism | Endpoint / file | Status |
| --- | --- | --- | --- |
| Dashboard metrics | Operations stats | `GET /backoffice/dashboard/stats` (`Dashboard.tsx`) | [partial] — UI wired, backend route missing |
| KYC approve/reject | Decision override with reason | `POST /backoffice/kyc/verifications/{id}/override` (`KYCVerifications.tsx`, optimistic UI + rollback) | [partial] — UI wired, backend route missing |
| Fraud alert triage | Investigate / resolve / false-positive | `POST /backoffice/fraud/alerts/{id}/status` (`FraudAlerts.tsx`) | [partial] — UI wired, backend route missing |
| Journey monitoring | 30-journey operations dashboard | `GET /api/v1/journeys`, `GET /api/v1/journeys/executions`, `GET /api/v1/journeys/analytics` (`frontend/src/pages/JourneyDashboard.tsx`) | [partial] — UI wired, backend route missing |
| Audit logs | Export/inspect audit trail | `GET /backoffice/audit/logs` (`backoffice-ui/src/services/api.ts`) | [partial] — client method only |

## 6. Tenant fintech

| Step | Mechanism | Endpoint / file | Status |
| --- | --- | --- | --- |
| Request API key | Onboarding portal form | `POST /api/v1/onboarding/api-keys` (`ml-onboarding-portal/src/api.ts` → `services/python/onboarding-service`) | [implemented] — key issued after staff dual-control approval |
| Select KYC tier | basic / enhanced / premium per tenant | `POST /api/v1/onboarding/kyc-tier` (`onboarding-service`) | [implemented] |
| Integration checklist | Go-live checklist tracking | `GET/POST /api/v1/onboarding/checklist[/:id]` (`onboarding-service`) | [implemented] |
| Onboarding status | Tenant state overview | `GET /api/v1/onboarding/status` (`onboarding-service`) | [implemented] |

## 7. Developer

| Step | Mechanism | Endpoint / file | Status |
| --- | --- | --- | --- |
| Local stack | docker compose with healthchecks | `local-e2e/docker-compose.yml` (postgres, redis, keycloak, permify, mlflow, aml-ml-service, model-router, land-verification-service, onboarding-service, temporal-orchestrator, go-mobile-mock) | [implemented] |
| Contract test | Mobile↔Go contract scenario runner | `local-e2e/run-contract-e2e.sh` | [implemented] |
| Realm import | Keycloak realm auto-import | `deploy/keycloak/fraudfusion-realm.json` mounted into compose keycloak (`local-e2e/docker-compose.yml`) | [implemented] |
| AML scoring | ML inference service | `POST /v1/aml/score` on aml-ml-service (port 8100) | [implemented] — rule-fallback mode without ONNX artifact |
| Model registry | MLflow tracking | http://localhost:5000 | [implemented] |

---

## Honest gap summary

- The KYC/screening/credit-bureau backend (`/api/v1/kyc/*`, `/api/v1/screening/*`,
  `/api/v1/credit-bureau/*`, `/api/v1/biometric/*`, `/api/v1/document/*`) consumed
  by `frontend/kyc-frontend` is **not implemented in this repository**.
- The backoffice backend (`/backoffice/*`) consumed by `implementations/backoffice-ui`
  is **not implemented in this repository**; pages show a documented sample-data
  fallback when the API is unreachable.
- The onboarding backend (`/api/v1/onboarding/*`) consumed by
  `ml-onboarding-portal` is implemented by `services/python/onboarding-service`
  (FastAPI): developer API-key requests, tenant provisioning (`tenants` +
  `tenant_api_keys` tables in `database/20260826_tenants_onboarding.sql`),
  KYC tier selection, integration checklist, and a staff approval workflow
  with dual control (`/api/v1/onboarding/admin/*`, Keycloak role
  `onboarding_admin`/`admin`).
- The journeys backend (`/api/v1/journeys*`) consumed by `frontend/` is **missing**.
- Land-verification external integrations (state registries, CAC, Surveyor-General,
  GIS) are deterministic stubs pending vendor integrations.
