# Runbook: FraudFusionTokenLeakSignal

## Symptom
Log-scan detected patterns consistent with bearer tokens or API keys appearing in logs.

## Triage
1. Identify the service and log pipeline from the alert labels. 2. Confirm whether a real credential was logged (search for the exact token shape) and which principals are affected. 3. Find the code path logging the credential.

## Fix
Rotate every potentially exposed credential immediately (Keycloak clients, API keys via onboarding-service revoke). Patch the logging code path to redact, deploy, and purge/scrub retained log segments per policy.
