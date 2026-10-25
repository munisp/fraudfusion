"""Tests for intelligence/geo_analytics — reference implementations and the
Sedona jobs' honest unavailability contract.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from intelligence.geo_analytics import reference, sedona_jobs


LAGOS = (6.5244, 3.3792)
NEAR_LAGOS = (6.5300, 3.3850)   # ~0.9 km
IKOYI = (6.4525, 3.4350)        # ~9.5 km
ABUJA = (9.0765, 7.3986)


class TestReferenceClustering:
    def _events(self, subjects_at, point):
        return [{"subject_id": s, "lat": point[0], "lon": point[1]}
                for s in subjects_at]

    def test_dense_distinct_subjects_flagged(self):
        events = (self._events([f"mule-{i}" for i in range(6)], LAGOS)
                  + self._events(["legit-1", "legit-2"], ABUJA))
        out = reference.mule_ring_geo_clusters(events, eps_km=2.0, min_samples=5)
        assert len(out["clusters"]) == 1
        assert out["clusters"][0]["subject_count"] == 6
        assert out["events_placed"] == 8 and out["events_unresolved"] == 0

    def test_shared_device_fewer_subjects_than_min_not_flagged(self):
        # Same 2 subjects, many events: dense but NOT a ring.
        events = self._events(["a", "b"], LAGOS) * 4
        out = reference.mule_ring_geo_clusters(events, eps_km=2.0, min_samples=5)
        assert out["clusters"] == []

    def test_unresolved_events_counted_never_placed(self):
        events = [{"subject_id": "x", "lat": None, "lon": None}]
        out = reference.mule_ring_geo_clusters(events)
        assert out["events_unresolved"] == 1 and out["events_placed"] == 0

    def test_noise_points_unclustered(self):
        events = (self._events(["a"], LAGOS) + self._events(["b"], ABUJA)
                  + self._events(["c"], NEAR_LAGOS))
        out = reference.mule_ring_geo_clusters(events, eps_km=2.0, min_samples=3)
        assert out["clusters"] == []


class TestOfflocationRollup:
    def test_share_computed_per_agent(self):
        events = [
            {"agent_id": "ag-1", "lat": LAGOS[0], "lon": LAGOS[1]},
            {"agent_id": "ag-1", "lat": NEAR_LAGOS[0], "lon": NEAR_LAGOS[1]},
            {"agent_id": "ag-1", "lat": ABUJA[0], "lon": ABUJA[1]},
        ]
        out = reference.agent_offlocation_rollup(events, {"ag-1": LAGOS}, radius_km=5.0)
        assert out[0]["assessable"] is True
        assert out[0]["off_location"] == 1 and out[0]["off_location_share"] == pytest.approx(1 / 3, abs=1e-3)

    def test_unregistered_agent_is_honestly_unassessable(self):
        events = [{"agent_id": "ghost", "lat": LAGOS[0], "lon": LAGOS[1]}]
        out = reference.agent_offlocation_rollup(events, {}, radius_km=5.0)
        assert out[0]["assessable"] is False
        assert out[0]["reason"] == "no registered location"


class TestSedonaHonesty:
    def test_missing_pyspark_is_an_honest_error_not_a_silent_pass(self):
        if sedona_jobs is None:
            pytest.skip("module unavailable")
        try:
            import pyspark  # noqa: F401
            pytest.skip("pyspark installed in this environment")
        except ImportError:
            pass
        with pytest.raises(RuntimeError, match="pyspark not installed"):
            sedona_jobs._session(None)

    def test_km_to_degree_conversion_constant(self):
        assert sedona_jobs.KM_TO_DEG_AT_EQUATOR == pytest.approx(1 / 111.32)

    def test_cli_reports_honest_unavailability(self):
        """The __main__ runner exits 2 with a clear message when the Sedona
        runtime is missing — it never pretends a job ran."""
        try:
            import pyspark  # noqa: F401
            pytest.skip("pyspark installed in this environment")
        except ImportError:
            pass
        from intelligence.geo_analytics import __main__ as cli
        rc = cli.main(["mule-clusters", "--events", "/tmp/none.parquet",
                       "--out", "/tmp/out"])
        assert rc == 2
