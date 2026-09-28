# Runbook: FraudFusionModelDriftAlert

## Symptom
A production model's prediction-score distribution has drifted from its reference window (PSI/KS over the alerting threshold).

## Triage
1. Identify the model and version from the alert labels. 2. Open the fraudfusion-overview Grafana dashboard drift panels and compare live vs reference distributions. 3. Check upstream feature pipelines (mlops/lakehouse exports) for schema or null-rate changes. 4. Confirm whether drift coincides with a deploy, data-source change, or seasonal event.

## Fix
If the input features drifted: fix the upstream feature export and re-validate. If genuine population drift: retrain and promote via the champion/challenger experiment (mlops/experiments/), never by hot-swapping the champion. Silence only with a dated ticket.
