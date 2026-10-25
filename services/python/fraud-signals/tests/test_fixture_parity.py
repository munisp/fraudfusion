"""Guard: the Python reference must reproduce its own published fixture —
catches fixture drift before the TS/Go/Rust ports do."""
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import detectors  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "fixtures", "detector_cases.json")


def test_fixture_cases_reproduce():
    with open(FIXTURE) as fh:
        fx = json.load(fh)
    for i, c in enumerate(fx["cases"]):
        score, verdict, factors = detectors.DETECTORS[c["detector"]](
            c["payload"], c["history"])
        assert score == c["expected"]["score"], f"case {i} score"
        assert verdict == c["expected"]["verdict"], f"case {i} verdict"
        assert [f["code"] for f in factors] == \
            c["expected"]["factor_codes"], f"case {i} factor codes"
