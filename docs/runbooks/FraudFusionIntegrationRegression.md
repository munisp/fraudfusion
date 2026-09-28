# Runbook: FraudFusionIntegrationRegression

## Symptom
Post-deploy integration tests regressed against the staged release.

## Triage
1. Identify the failing suite/test from the alert annotation and CI artifacts. 2. Diff the release against the last green one (services, migrations, config). 3. Check whether the failure is deterministic or environment flake (re-run once).

## Fix
Roll back the release via the deployment pipeline if the regression is real; otherwise fix-forward with a targeted patch. Do not promote a release with a red integration gate.
