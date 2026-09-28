# Runbook: FraudFusionModelF1Low

## Symptom
Rolling F1 score for a fraud model fell below the release-qualified floor.

## Triage
1. Pull the confusion-matrix breakdown per threshold from the evaluation job. 2. Check class-balance shifts in recent scored traffic. 3. Verify the scoring threshold wasn't changed by a recent config deploy.

## Fix
Re-tune the decision threshold or retrain; validate offline against the holdout, then promote via champion/challenger. If labels are delayed, extend the evaluation window before acting.
