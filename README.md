# FraudFusion

FraudFusion is a multi-service fraud prevention platform containing Go, Python, TypeScript, and React Native components.

## Security and Quality Controls

The repository includes a signed HMAC release-gate metric producer, Prometheus and Alertmanager templates, EKS staging monitoring resources, and GitHub Actions quality gates.

## Repository Layout

- `services/` — Fraud detection and workflow services.
- `orchestrator/` — Service orchestration and authorization integration.
- `mobile/react-native/` — React Native mobile client.
- `frontend/` and `implementations/backoffice-ui/` — Web applications.
- `observability/` — Release-gate metrics, Prometheus, Alertmanager, and EKS monitoring templates.
- `database/` — Database schema and migration assets.

## Local Validation

```bash
cd observability/release-gate-metrics
go test -race ./...
./run-hmac-load-test.sh
```

Deployment requires approved secret injection and an authorized staging environment; do not commit credentials into the repository.
