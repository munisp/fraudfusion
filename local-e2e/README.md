# Local Mobile-to-Go Contract Environment

This directory provides a **local contract-test simulator**, not a production stack. It runs PostgreSQL and a small Go HTTP service that implements the subset of mobile endpoints used by the screen-level tests.

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
