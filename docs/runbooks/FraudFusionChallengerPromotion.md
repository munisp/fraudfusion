# Runbook: FraudFusionChallengerPromotion

## Symptom
The challenger arm has outperformed the champion past the promotion criteria; a human promotion decision is required.

## Triage
1. Review the experiment report for fraud_net (mlops/experiments/, model-router arm metrics): sample sizes, uplift, guardrail metrics. 2. Confirm challenger pods (aml-ml-service-v2) are healthy and resource headroom exists.

## Fix
Promote by updating the experiment config so the challenger version becomes champion (ConfigMap model-router-config + mlops/experiments file), roll the router, and keep the old champion deployment as rollback for one full evaluation window.
