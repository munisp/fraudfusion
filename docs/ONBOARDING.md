# FraudFusion Onboarding Guide

Per-stakeholder onboarding flows, mapped to the real code and endpoints in this
repository. Each step is marked **[implemented]**, **[partial]**, or
**[missing]** honestly, so integrators know what works today and what is still
on the backlog.

Endpoint base URLs in local development come from `local-e2e/docker-compose.yml`
(postgres, redis, keycloak, permify, mlflow, aml-ml-service, go-mobile-mock).

---

## 1. Retail customer (KYC tiers)

| Step | Mechanism | Endpoint / file | Status |
| --- | --- | --- | --- |
| Register account | Mobile app registration screen | `mobile/react-native/src/screens/RegisterScreen.tsx` | [implemented] |
| Login (OIDC) | Keycloak-issued token via `react-native-app-auth` | `mobile/react-native/src/services/AuthService.ts` | [implemented] |
| Basic KYC (BVN/NIN) | Tier 1 verification | `POST /api/v1/kyc/verify/basic` (consumed by `frontend/kyc-frontend/src/services/api.ts`, `kycAPI.verifyBasic`) | [partial] — frontend ready; backend route not in this repo |
| Enhanced KYC (PEP/sanctions) | Tier 2 | `POST /api/v1/kyc/verify/enhanced`, `POST /api/v1/screening/pep`, `POST /api/v1/screening/sanctions` | [partial] — frontend ready |
| Premium KYC (credit bureau) | Tier 3 | `POST /api/v1/kyc/verify/premium`, `POST /api/v1/credit-bureau/check` | [partial] — frontend ready |
| Document upload | Presigned upload + complete | `POST /kyc/sessions/:id/documents`, `POST .../documents/:docId/complete` via `MobileApi.beginDocumentUpload` / `completeDocumentUpload` (`DocumentUploadScreen`) | [implemented] in mobile client + contract mock |
| Biometric enrollment | Device biometrics + server challenge | `POST /kyc/sessions/:id/biometric-challenge`, `POST .../biometric-challenge/:challengeId/complete` via `KYCBiometricScreen` + `BiometricService` | [implemented] in mobile client |
| Video KYC | Recorded session submission | `POST /kyc/sessions/:id/video` via `VideoKYCScreen` | [implemented] in mobile client |
| Session status | Poll KYC session | `GET /kyc/sessions/:id` (`KYCStatusScreen`) | [implemented] in mobile client |

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
| Request API key | Onboarding portal form | `POST /api/v1/onboarding/api-keys` (`ml-onboarding-portal/src/api.ts`) | [partial] — portal implemented; backend route missing (orchestrator lane) |
| Select KYC tier | basic / enhanced / premium per tenant | `POST /api/v1/onboarding/kyc-tier` | [partial] — portal implemented; backend route missing |
| Integration checklist | Go-live checklist tracking | `GET/POST /api/v1/onboarding/checklist[/:id]` | [partial] — portal implemented; backend route missing |
| Onboarding status | Tenant state overview | `GET /api/v1/onboarding/status` | [partial] — portal implemented; backend route missing |

## 7. Developer

| Step | Mechanism | Endpoint / file | Status |
| --- | --- | --- | --- |
| Local stack | docker compose with healthchecks | `local-e2e/docker-compose.yml` (postgres, redis, keycloak, permify, mlflow, aml-ml-service, go-mobile-mock) | [implemented] |
| Contract test | Mobile↔Go contract scenario runner | `local-e2e/run-contract-e2e.sh` | [implemented] |
| Realm import | Keycloak realm auto-import | commented volume in compose; **blocked**: `deploy/keycloak/fraudfusion-realm.json` does not exist yet | [missing] — realm export required |
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
  `ml-onboarding-portal` belongs to the orchestrator lane and is **missing**.
- The journeys backend (`/api/v1/journeys*`) consumed by `frontend/` is **missing**.
- Land-verification external integrations (state registries, CAC, Surveyor-General,
  GIS) are deterministic stubs pending vendor integrations.
