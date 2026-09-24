# Local Mobile-to-Go Contract Environment

This directory provides a **local contract-test simulator**, not a production stack.

## Services

| Service | Port(s) | Purpose |
| --- | --- | --- |
| postgres | 54329 | Contract-test database |
| go-mobile-mock | 8088 | Go mock of the mobile/KYC API under contract test |
| redis | 6380 | Cache/queue seam used by services |
| keycloak | 8180 | OIDC issuer (start-dev); realm import wired for `deploy/keycloak/fraudfusion-realm.json` — **that file does not exist yet**, so the container starts with the default `master` realm until it is added (see commented volume in `docker-compose.yml`) |
| permify | 3476/3478 | Authorization service (in-memory schema) |
| mlflow (+ mlflow-db) | 5000 | Model registry, mirrors `mlops/mlflow/docker-compose.yml` |
| aml-ml-service | 8100 | AML scorer from `mlops/serving`; starts in documented rule-fallback mode without the ONNX artifact |

All services carry healthchecks except `go-mobile-mock` (distroless image with no
shell or curl); the contract script polls its `/healthz` with retries instead.
Permify's image is distroless too, so its healthcheck is process-level
(`permify version`).

## Start

```bash
cd local-e2e
docker compose up --build --wait
```

The mock API is then available on `http://localhost:8088/api/v1`. The Compose PostgreSQL service is published on `localhost:54329` for inspection only.

## Contract Smoke Checks

```bash
curl http://localhost:8088/healthz
curl -i http://localhost:8088/api/v1/mobile/dashboard
curl -H 'Authorization: Bearer local-contract-token' \
  http://localhost:8088/api/v1/mobile/dashboard
curl -X POST -H 'Authorization: Bearer local-contract-token' \
  http://localhost:8088/api/v1/kyc/sessions
```

The unauthenticated dashboard request must return `401`. The authenticated dashboard request must return the mobile dashboard JSON contract, and the KYC request must return a `201` persisted-session contract response.

## Mobile Configuration for Contract Testing

A test harness can provide the API base URL without embedding a secret:

```ts
globalThis.__FRAUDFUSION_API_CONFIG__ = { baseUrl: 'http://10.0.2.2:8088/api/v1' };
```

For a physical device, use the host LAN address rather than `10.0.2.2`. The local mock accepts any non-empty bearer token **only for local contract testing**; it does not replace Keycloak token validation, Permify authorization, PostgreSQL tenant isolation, FCM/APNs, uploads, or KYC/liveness in staging.

## Stop and Reset

```bash
docker compose down -v
```
