"""Generate fixtures/detector_cases.json — the cross-language parity contract.

Every language port (Python, TypeScript, Go, Rust) must reproduce these exact
scores/verdicts from these exact payloads+histories. Regenerate with:
    python3 tests/generate_fixtures.py
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import detectors  # noqa: E402

NOW = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)


def ev(days_ago, **payload):
    return {"payload": payload,
            "created_at": (NOW - timedelta(days=days_ago)).isoformat()}


CASES = [
    ("app_scam", {"payee_is_new": True, "payee_age_hours": 0.2,
                  "amount_ngn": 500_000, "customer_avg_amount": 10_000,
                  "session_seconds": 20, "device_is_new": True,
                  "payee_mule_score": 0.8}, []),
    ("app_scam", {"amount_ngn": 5_000, "customer_avg_amount": 8_000,
                  "session_seconds": 300}, [ev(1)]),
    ("mule", {}, [ev(1, direction="in", amount_ngn=100_000, counterparty=f"s{i}")
                  for i in range(6)]
                 + [ev(0.5, direction="out", amount_ngn=95_000, counterparty=f"x{i}")
                    for i in range(6)]),
    ("mule", {"dormant_days_before": 120, "shared_device_accounts": 4},
     [ev(1, direction="in", amount_ngn=10_000, counterparty="a")]),
    ("agent", {"baseline_tx_per_day": 1, "float_mismatch_ngn": 250_000,
               "distance_from_registered_km": 12},
     [ev(0.05, type="cash_out", amount_ngn=48_000) for _ in range(4)]),
    ("agent", {"baseline_tx_per_day": 10, "distance_from_registered_km": 1},
     [ev(0.05, type="cash_out", amount_ngn=20_000),
      ev(0.02, type="cash_in", amount_ngn=15_000)]),
    ("loan_stacking", {"thin_file": True},
     [ev(2, lender_id=f"lender{i}") for i in range(3)]),
    ("loan_stacking", {"document_authenticity_score": 72,
                       "first_payment_default": True}, []),
    ("issuance", {"peer_officer_mean_per_day": 5, "peer_officer_std_per_day": 2,
                  "issued_hour_local": 2, "registry_survey_mismatch": True},
     [ev(0.02, certificate=f"C{i}") for i in range(20)]),
    ("issuance", {"peer_officer_mean_per_day": 5, "peer_officer_std_per_day": 2,
                  "issued_hour_local": 11},
     [ev(0.02, certificate="C1") for _ in range(4)]),
    ("channel", {"channel": "ussd", "sim_change_hours": 3,
                 "alert_integrity_fail": True}, []),
    ("channel", {"channel": "ussd", "sim_change_hours": 200,
                 "phone_tenure_days": 400}, []),
    ("ghost_payroll", {"employee_id": "e1", "bank_account_hash": "A",
                       "identity_hash": "X"},
     [ev(1, employee_id="e2", bank_account_hash="A", identity_hash="X"),
      ev(1, employee_id="e3", bank_account_hash="A", identity_hash="Y")]),
    ("ghost_payroll", {"employee_id": "e1", "deceased_registry_hit": True}, []),
    ("subsidy", {"farm_hectares": 2, "claim_ngn": 2_000_000,
                 "farm_geocode_outside_lga": True,
                 "no_field_activity_evidence": True,
                 "claim_id": "c1", "identity_hash": "X"},
     [ev(1, claim_id="c2", identity_hash="X")]),
    ("subsidy", {"farm_hectares": 5, "claim_ngn": 200_000,
                 "claim_id": "c1", "identity_hash": "X"}, []),
]


def main():
    out = {"generated_at": NOW.isoformat(), "note":
           "Scores computed by the Python reference implementation; every "
           "language port must match score (3dp) and verdict.", "cases": []}
    for name, payload, history in CASES:
        score, verdict, factors = detectors.DETECTORS[name](payload, history)
        out["cases"].append({
            "detector": name, "payload": payload, "history": history,
            "expected": {"score": score, "verdict": verdict,
                         "factor_codes": [f["code"] for f in factors]}})
    dest = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "fixtures", "detector_cases.json")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"wrote {len(out['cases'])} cases -> {dest}")


if __name__ == "__main__":
    main()
