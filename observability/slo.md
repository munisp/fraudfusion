# FraudFusion service-level objectives

Applies to production `fraudfusion-services`. Dashboards:
`observability/grafana/fraudfusion-overview.json`. Alert rules:
`observability/prometheus/*.rules.yml`. Error budgets are computed over a
**28-day rolling window**.

## SLOs

| # | Service / path | Indicator | Objective |
|---|----------------|-----------|-----------|
| 1 | Platform edge (APISIX → services) | Availability: fraction of requests not returning 5xx | **99.9%** per 28d rolling window |
| 2 | Fraud scoring (model-router → aml-ml-service, both arms) | Latency: `http_request_duration_seconds` for score requests | **p95 ≤ 150 ms**, measured over 5m windows |
| 3 | Ledger posting (ledger-command `POST` double-entry journals) | Latency per posted journal | **p95 ≤ 100 ms** |
| 4 | KYC verification (kyc-api `/api/v1/kyc/verify/*`) | Latency per verification call | **p95 ≤ 800 ms** (includes registry/bureau round-trips) |

Supporting targets (alert-level, not contractual SLOs):

- Feature PSI drift: page-level investigation when `max(fraudfusion_drift_psi) > 0.25` for 30m.
- Model rolling F1 ≥ 0.5 (1h window); degradation flag `fraudfusion_model_degraded == 1` for 15m is critical.
- Ledger correctness is a hard invariant, not a latency/availability target: the
  double-entry integrity checks (`database/tests/20260822_ledger_integrity_verification.sql`)
  must pass on every release; a failed invariant is a Sev-1 regardless of budget.

## Error budgets

- Availability 99.9% over 28 days ⇒ **~40.3 minutes** of full outage, or the
  equivalent partial-error budget, per window.
- Latency SLOs: budget = 5% of requests above the latency threshold (the
  complement of the p95 objective). A p95 breach sustained over a 1h window
  counts as burning budget at the observed violation rate.

## Error-budget policy

1. **Budget healthy (> 25% remaining):** normal release cadence; feature work
   proceeds.
2. **Budget low (≤ 25% remaining):** release-gate scrutiny increases — no
   discretionary risky changes (schema migrations with locks, model
   promotions, dependency majors) without staff-engineer sign-off.
3. **Budget exhausted (≤ 0):** **feature freeze** on the affected service.
   Only reliability fixes, rollbacks, and incident remediation ship until the
   28-day window recovers. The ML champion/challenger promotion pipeline is
   paused except for rollback of a degraded champion.
4. **Post-incident:** every SLO breach gets a postmortem with the runbook
   (`docs/runbooks/<AlertName>.md`) updated or created if the triage path
   differed from the documented one.

## Measurement notes

- Availability and latency are measured at the service boundary
  (`http_requests_total` / `http_request_duration_seconds_bucket`), so client
  retries do not mask service-side failures.
- The fraud-score SLO covers both experiment arms; the challenger
  (`aml-ml-service-v2`) is held to the same p95 as the champion so experiments
  never degrade scored traffic beyond budget.
