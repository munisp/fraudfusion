# Runbook: FraudFusionUnauthorizedSpike

## Symptom
Rate of 401/403 auth-denied responses spiked above baseline across edge or service auth.

## Triage
1. Break down by service/route and by principal/client in the alert labels and logs. 2. Check for expired/rotated Keycloak client secrets or realm config changes. 3. Look for scanning/bruteforce source IPs in APISIX/access logs.

## Fix
For misconfiguration: restore the correct client secret/realm settings. For attack traffic: block at the gateway (APISIX), tighten rate limits, and rotate any potentially compromised credentials.
