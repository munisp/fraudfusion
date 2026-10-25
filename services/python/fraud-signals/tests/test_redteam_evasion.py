"""Red-team evasion suite.

Every test is an attack: a fraudster who has READ the detector source and
shaped their behaviour to stay under its thresholds. Two documented outcomes:

  * EVASION RESISTED — the attack still lands in review/block because other
    signals catch it (the additive multi-signal design doing its job)
  * KNOWN GAP — the evasion succeeds today. These tests are the honest
    register of the platform's evasion surface; each names the compensating
    control that would close it. If a future change accidentally CLOSES a
    known gap, tighten the test to the resisted set.

A test that starts failing because an evasion STOPPED working is good news —
move it to the resisted class, don't weaken it.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import detectors  # noqa: E402

NOW = datetime.now(timezone.utc)


def ev(days_ago, **payload):
    return {"payload": payload,
            "created_at": (NOW - timedelta(days=days_ago)).isoformat()}


# ---------------------------------------------------------------------------
# Evasions that are RESISTED — the multi-signal design still catches them
# ---------------------------------------------------------------------------

class TestEvasionResisted:
    def test_structuring_below_the_structuring_window(self):
        """Attacker splits at ₦30k — below the 45–50k structuring window.
        The structuring factor goes blind, but 7 same-day cash-outs against a
        baseline of 1 still trips velocity_spike, and operating 8km from the
        registered location adds off_location."""
        history = [ev(0.02, type="cash_out", amount_ngn=30_000) for _ in range(7)]
        score, verdict, factors = detectors.agent(
            {"baseline_tx_per_day": 1, "distance_from_registered_km": 8},
            history)
        codes = {f["code"] for f in factors}
        assert "structuring" not in codes          # evasion worked on that factor
        assert {"velocity_spike", "off_location"} <= codes  # ...these still fire
        assert verdict in ("review", "block")

    def test_mule_slow_drip_below_pass_through(self):
        """Attacker forwards only 80% (under the 0.85 pass-through line) —
        but keeps the 6-sender fan-in and the dormancy burst."""
        history = [ev(1, direction="in", amount_ngn=100_000, counterparty=f"s{i}")
                   for i in range(6)]
        history += [ev(0.5, direction="out", amount_ngn=80_000, counterparty=f"x{i}")
                    for i in range(6)]
        score, verdict, factors = detectors.mule(
            {"dormant_days_before": 120}, history)
        codes = {f["code"] for f in factors}
        assert "pass_through" not in codes
        assert {"fan_in", "dormancy_burst"} <= codes
        assert verdict in ("review", "block")

    def test_calm_session_scam_still_flagged(self):
        """Attacker coaches the victim to take 5 minutes (no rushed_session)
        — the new-payee + amount-outlier + mule-payee combination still
        reaches the block band."""
        score, verdict, _ = detectors.app_scam(
            {"payee_is_new": True, "payee_age_hours": 0.5,
             "amount_ngn": 500_000, "customer_avg_amount": 10_000,
             "session_seconds": 300, "payee_mule_score": 0.8}, [])
        assert verdict == "block"

    def test_two_lender_stack_with_forged_docs(self):
        """Attacker stays at 2 lenders (under the 3-lender line) — forged
        income docs + first-payment default history still blocks."""
        score, verdict, factors = detectors.loan_stacking(
            {"first_payment_default": True, "document_authenticity_score": 70},
            [ev(2, lender_id="l1"), ev(1, lender_id="l2")])
        assert verdict in ("review", "block")
        assert "multi_lender_stack" not in {f["code"] for f in factors}

    def test_business_hours_insider_still_flagged_by_velocity(self):
        """Insider issues during business hours (no after_hours signal) but
        can't hide 20 issuances against a peer mean of 5, plus the survey
        mismatch."""
        score, verdict, factors = detectors.issuance(
            {"peer_officer_mean_per_day": 5, "peer_officer_std_per_day": 2,
             "issued_hour_local": 11, "registry_survey_mismatch": True},
            [ev(0.02, certificate=f"C{i}") for i in range(20)])
        assert verdict in ("review", "block")
        assert "after_hours_issuance" not in {f["code"] for f in factors}


# ---------------------------------------------------------------------------
# KNOWN GAPS — evasions that succeed today, with the compensating control
# that would close each. These assertions document the current surface.
# ---------------------------------------------------------------------------

class TestKnownGaps:
    def test_sim_swap_plus_25h_wait_evades(self):
        """GAP: patient SIM-swapper waits 25h before the USSD session.
        ussd_after_sim_change goes blind; with an established device and
        number the score stays clear.
        Compensating control: step-up auth window scaled to SIM age, not a
        fixed 24h cliff."""
        _, verdict, factors = detectors.channel(
            {"channel": "ussd", "sim_change_hours": 25,
             "phone_tenure_days": 400}, [])
        assert verdict == "clear"
        assert not [f for f in factors if f["weight"] > 0]

    def test_mule_below_fan_in_and_pass_through_evades(self):
        """GAP: 4 senders (under fan-in 5) forwarding 80% (under 0.85).
        Both behavioural factors miss; a fresh account with this pattern is
        clear.
        Compensating control: graph analytics — the SENDERS' risk scores
        feeding the receiver (partially available via mesh composition)."""
        history = [ev(1, direction="in", amount_ngn=100_000, counterparty=f"s{i}")
                   for i in range(4)]
        history += [ev(0.5, direction="out", amount_ngn=80_000, counterparty="x")]
        _, verdict, factors = detectors.mule({}, history)
        weighted = [f["code"] for f in factors if f["weight"] > 0]
        assert verdict == "clear" and weighted == []

    def test_distributed_ghost_accounts_evade(self):
        """GAP: each ghost gets its own bank account (no shared account),
        distinct synthetic identities (no duplicate hash), and the death
        registry is not consulted (no deceased hit).
        Compensating control: liveness re-verification at payday; biometric
        dedup against the full identity registry (NIN/BVN dedup service)."""
        _, verdict, _ = detectors.ghost_payroll(
            {"employee_id": "e1", "bank_account_hash": "A",
             "identity_hash": "X"},
            [ev(1, employee_id="e2", bank_account_hash="B", identity_hash="Y")])
        assert verdict == "clear"

    def test_single_lender_first_time_borrower_evades(self):
        """GAP: a first-time borrower applying at one lender with genuine
        documents is indistinguishable from a bust-out's first move.
        Compensating control: credit-bureau cross-reporting hooks (the
        detector consumes them when present — thin_file only adds 0.10)."""
        _, verdict, _ = detectors.loan_stacking(
            {}, [ev(1, lender_id="l1")])
        assert verdict == "clear"

    def test_plausible_subsidy_ratio_evades(self):
        """GAP: a phantom farmer claiming ₦140k/ha (just under the 150k
        ceiling) on a correctly geolocated plot with fabricated field
        evidence.
        Compensating control: satellite/NDVI vegetation cross-check on the
        geocode — a roadmap integration, not a threshold tweak."""
        _, verdict, _ = detectors.subsidy(
            {"farm_hectares": 3, "claim_ngn": 420_000, "claim_id": "c1",
             "identity_hash": "X"}, [])
        assert verdict == "clear"

    def test_slow_insider_issuance_evades(self):
        """GAP: an insider issuing 2 fraudulent certificates per day (inside
        the peer band), during hours, with consistent survey records.
        Compensating control: beneficiary-side anomaly detection (the
        RECEIVER's profile, not the officer's velocity) + mandatory
        four-eyes review for high-value issuances."""
        _, verdict, _ = detectors.issuance(
            {"peer_officer_mean_per_day": 5, "peer_officer_std_per_day": 3,
             "issued_hour_local": 10},
            [ev(0.3, certificate="C1"), ev(0.1, certificate="C2")])
        assert verdict == "clear"

    def test_scam_to_aged_payee_from_known_device_evades(self):
        """GAP: a scammer who ages the payee account for a week and has the
        victim transact from their usual device at a normal pace with a
        plausible amount — every app_scam factor is dark.
        Compensating control: payee-side mule scoring is the last line
        (payee_mule_score feeds the detector); this is why the mesh
        composition matters more than any single factor."""
        _, verdict, _ = detectors.app_scam(
            {"payee_is_new": False, "amount_ngn": 10_000,
             "customer_avg_amount": 9_000, "session_seconds": 300}, [])
        assert verdict == "clear"
