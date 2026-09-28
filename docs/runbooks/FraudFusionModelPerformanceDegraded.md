# Runbook: FraudFusionModelPerformanceDegraded

## Symptom
Online performance proxy (precision/recall proxy or outcome-based metric) for a served model dropped below threshold.

## Triage
1. Confirm with labels which model/version degraded. 2. Check whether the champion or challenger arm is affected (model-router arm metrics). 3. Review recent feedback/label ingestion for outages — degraded labels masquerade as degraded models.

## Fix
If labels are stale, restore the feedback pipeline first. If the champion truly degraded, shift traffic to the challenger/rollback version via mlops/experiments config and schedule retraining.
