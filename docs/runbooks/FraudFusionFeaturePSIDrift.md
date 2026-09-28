# Runbook: FraudFusionFeaturePSIDrift

## Symptom
Population Stability Index for one or more input features exceeds the alerting threshold.

## Triage
1. Alert labels name the feature; inspect its live histogram against the training reference in the drift dashboard. 2. Check for recent changes to feature computation (deploys touching ml/ or mlops/lakehouse). 3. Verify no upstream null/default fallback started emitting constants.

## Fix
Roll back the offending feature-pipeline change, or retrain with the new feature distribution and promote through the experiment router. Add the feature to the data-contract checks if it changed silently.
