"""Generate fixtures/backtest_cases.jsonl — a small labeled dataset for the
backtest harness. These are SYNTHETIC reference cases with hand-assigned
labels: they demonstrate the harness and give a baseline reading, they are
NOT a substitute for backtesting on real production fraud data.

Regenerate: python3 tests/generate_backtest_cases.py
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

NOW = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)


def ev(days_ago, **payload):
    return {"payload": payload,
            "created_at": (NOW - timedelta(days=days_ago)).isoformat()}


CASES = [
    # --- app_scam ---
    {"detector": "app_scam", "label": "fraud",
     "payload": {"payee_is_new": True, "payee_age_hours": 0.3,
                 "amount_ngn": 800_000, "customer_avg_amount": 12_000,
                 "session_seconds": 25, "device_is_new": True,
                 "payee_mule_score": 0.7}, "history": []},
    {"detector": "app_scam", "label": "fraud",
     "payload": {"payee_is_new": True, "payee_age_hours": 0.8,
                 "amount_ngn": 300_000, "customer_avg_amount": 20_000,
                 "session_seconds": 30}, "history": [ev(1)]},
    {"detector": "app_scam", "label": "legit",
     "payload": {"payee_is_new": False, "amount_ngn": 15_000,
                 "customer_avg_amount": 12_000, "session_seconds": 180},
     "history": [ev(1)]},
    {"detector": "app_scam", "label": "legit",
     "payload": {"payee_is_new": True, "payee_age_hours": 48,
                 "amount_ngn": 9_000, "customer_avg_amount": 10_000,
                 "session_seconds": 240}, "history": [ev(1)]},
    # --- mule ---
    {"detector": "mule", "label": "fraud", "payload": {},
     "history": [ev(1, direction="in", amount_ngn=100_000, counterparty=f"s{i}")
                 for i in range(6)]
                + [ev(0.5, direction="out", amount_ngn=95_000, counterparty=f"x{i}")
                   for i in range(6)]},
    {"detector": "mule", "label": "fraud",
     "payload": {"dormant_days_before": 180, "shared_device_accounts": 5},
     "history": [ev(0.2, direction="in", amount_ngn=50_000, counterparty="a"),
                 ev(0.1, direction="out", amount_ngn=48_000, counterparty="b")]},
    {"detector": "mule", "label": "legit", "payload": {},
     "history": [ev(2, direction="in", amount_ngn=250_000, counterparty="employer"),
                 ev(1, direction="out", amount_ngn=8_000, counterparty="shop"),
                 ev(0.5, direction="out", amount_ngn=12_000, counterparty="pharmacy")]},
    {"detector": "mule", "label": "legit", "payload": {},
     "history": [ev(1, direction="in", amount_ngn=40_000, counterparty="friend"),
                 ev(0.8, direction="out", amount_ngn=5_000, counterparty="cafe")]},
    # --- agent ---
    {"detector": "agent", "label": "fraud",
     "payload": {"baseline_tx_per_day": 2, "float_mismatch_ngn": 300_000,
                 "distance_from_registered_km": 15},
     "history": [ev(0.05, type="cash_out", amount_ngn=47_500) for _ in range(4)]
                + [ev(0.02, type="cash_in", amount_ngn=10_000) for _ in range(4)]},
    {"detector": "agent", "label": "fraud",
     "payload": {"baseline_tx_per_day": 1},
     "history": [ev(0.05, type="cash_out", amount_ngn=49_000) for _ in range(3)]},
    {"detector": "agent", "label": "legit",
     "payload": {"baseline_tx_per_day": 20, "distance_from_registered_km": 0.5},
     "history": [ev(0.05, type="cash_out", amount_ngn=20_000),
                 ev(0.04, type="cash_in", amount_ngn=30_000),
                 ev(0.03, type="cash_out", amount_ngn=15_000)]},
    {"detector": "agent", "label": "legit",
     "payload": {"baseline_tx_per_day": 8},
     "history": [ev(0.05, type="cash_out", amount_ngn=60_000),
                 ev(0.04, type="cash_in", amount_ngn=25_000)]},
    # --- loan_stacking ---
    {"detector": "loan_stacking", "label": "fraud",
     "payload": {"thin_file": True, "first_payment_default": True},
     "history": [ev(2, lender_id=f"lender{i}") for i in range(4)]},
    {"detector": "loan_stacking", "label": "fraud",
     "payload": {"document_authenticity_score": 78},
     "history": [ev(3, lender_id="l1"), ev(2, lender_id="l2"),
                 ev(1, lender_id="l3")]},
    {"detector": "loan_stacking", "label": "legit", "payload": {},
     "history": [ev(3, lender_id="l1"), ev(2, lender_id="l1")]},
    {"detector": "loan_stacking", "label": "legit", "payload": {"thin_file": False},
     "history": [ev(10, lender_id="l1"), ev(9, lender_id="l2")]},
    # --- issuance ---
    {"detector": "issuance", "label": "fraud",
     "payload": {"peer_officer_mean_per_day": 5, "peer_officer_std_per_day": 2,
                 "issued_hour_local": 23, "registry_survey_mismatch": True},
     "history": [ev(0.02, certificate=f"C{i}") for i in range(20)]},
    {"detector": "issuance", "label": "fraud",
     "payload": {"sequence_gap": True, "registry_survey_mismatch": True,
                 "issued_hour_local": 3},
     "history": []},
    {"detector": "issuance", "label": "legit",
     "payload": {"peer_officer_mean_per_day": 5, "peer_officer_std_per_day": 2,
                 "issued_hour_local": 10},
     "history": [ev(0.02, certificate="C1") for _ in range(4)]},
    {"detector": "issuance", "label": "legit",
     "payload": {"peer_officer_mean_per_day": 6, "peer_officer_std_per_day": 3,
                 "issued_hour_local": 14},
     "history": [ev(0.02, certificate="C1") for _ in range(6)]},
    # --- channel ---
    {"detector": "channel", "label": "fraud",
     "payload": {"channel": "ussd", "sim_change_hours": 2,
                 "alert_integrity_fail": True}, "history": []},
    {"detector": "channel", "label": "fraud",
     "payload": {"channel": "ussd", "sim_change_hours": 10,
                 "imei_is_new": True, "amount_ngn": 400_000,
                 "phone_tenure_days": 12}, "history": []},
    {"detector": "channel", "label": "legit",
     "payload": {"channel": "ussd", "sim_change_hours": 400,
                 "phone_tenure_days": 900}, "history": []},
    {"detector": "channel", "label": "legit",
     "payload": {"channel": "app", "imei_is_new": False,
                 "amount_ngn": 30_000, "phone_tenure_days": 200}, "history": []},
    # --- ghost_payroll ---
    {"detector": "ghost_payroll", "label": "fraud",
     "payload": {"employee_id": "e1", "bank_account_hash": "A",
                 "identity_hash": "X", "account_dormant_except_salary": True},
     "history": [ev(1, employee_id="e2", bank_account_hash="A", identity_hash="X"),
                 ev(1, employee_id="e3", bank_account_hash="A", identity_hash="Y")]},
    {"detector": "ghost_payroll", "label": "fraud",
     "payload": {"employee_id": "e9", "deceased_registry_hit": True},
     "history": []},
    {"detector": "ghost_payroll", "label": "legit",
     "payload": {"employee_id": "e1", "bank_account_hash": "A",
                 "identity_hash": "X"},
     "history": [ev(1, employee_id="e2", bank_account_hash="B", identity_hash="Y"),
                 ev(1, employee_id="e3", bank_account_hash="C", identity_hash="Z")]},
    {"detector": "ghost_payroll", "label": "legit",
     "payload": {"employee_id": "e1", "bank_account_hash": "A",
                 "identity_hash": "X"},
     "history": []},
    # --- subsidy ---
    {"detector": "subsidy", "label": "fraud",
     "payload": {"farm_hectares": 1, "claim_ngn": 900_000,
                 "farm_geocode_outside_lga": True,
                 "no_field_activity_evidence": True,
                 "claim_id": "c1", "identity_hash": "X"},
     "history": [ev(1, claim_id="c2", identity_hash="X")]},
    {"detector": "subsidy", "label": "fraud",
     "payload": {"farm_hectares": 0.5, "claim_ngn": 400_000,
                 "claim_id": "c9", "identity_hash": "Z"},
     "history": [ev(1, claim_id="c8", identity_hash="Z")]},
    {"detector": "subsidy", "label": "legit",
     "payload": {"farm_hectares": 4, "claim_ngn": 300_000,
                 "claim_id": "c1", "identity_hash": "X"}, "history": []},
    {"detector": "subsidy", "label": "legit",
     "payload": {"farm_hectares": 10, "claim_ngn": 1_000_000,
                 "claim_id": "c2", "identity_hash": "Y"},
     "history": [ev(1, claim_id="c3", identity_hash="Q")]},
]


def main():
    dest = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "fixtures", "backtest_cases.jsonl")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w") as fh:
        for c in CASES:
            fh.write(json.dumps(c) + "\n")
    print(f"wrote {len(CASES)} labeled cases -> {dest}")


if __name__ == "__main__":
    main()
