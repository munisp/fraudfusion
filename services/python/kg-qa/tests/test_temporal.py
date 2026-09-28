"""Tests for temporal-phrase parsing + time-windowed path reasoning."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import path_reasoning, temporal  # noqa: E402

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)


def test_last_week():
    w = temporal.parse_temporal("which accounts shared devices last week?", NOW)
    assert w is not None and w.phrase == "last week"
    assert (w.end - w.start).days == 7
    assert w.end <= NOW  # last week ended before this week


def test_last_n_days():
    w = temporal.parse_temporal("show me fraud in the past 14 days", NOW)
    assert w is not None and (w.end - w.start).days == 15  # inclusive of today


def test_month_with_year():
    w = temporal.parse_temporal("SARs filed in March 2026", NOW)
    assert w is not None
    assert w.start == datetime(2026, 3, 1, tzinfo=timezone.utc)
    assert w.end == datetime(2026, 4, 1, tzinfo=timezone.utc)


def test_month_without_year_defaults_current():
    w = temporal.parse_temporal("transactions in August", NOW)
    assert w is not None and w.start.year == 2026 and w.start.month == 8


def test_since_month():
    w = temporal.parse_temporal("mule activity since January 2026", NOW)
    assert w is not None
    assert w.start == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert w.end > NOW


def test_between_months():
    w = temporal.parse_temporal("links between January 2026 and March 2026", NOW)
    assert w is not None
    assert w.start == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert w.end == datetime(2026, 4, 1, tzinfo=timezone.utc)


def test_quarter():
    w = temporal.parse_temporal("chargebacks Q2 2026", NOW)
    assert w is not None
    assert w.start == datetime(2026, 4, 1, tzinfo=timezone.utc)
    assert w.end == datetime(2026, 7, 1, tzinfo=timezone.utc)


def test_year_only():
    w = temporal.parse_temporal("fraud rings in 2025", NOW)
    assert w is not None
    assert w.start == datetime(2025, 1, 1, tzinfo=timezone.utc)
    assert w.end == datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_no_temporal_phrase_returns_none():
    assert temporal.parse_temporal("who is connected to customer_pii_abc?") is None


def test_undated_edges_excluded_from_window():
    w = temporal.TimeWindow(datetime(2026, 9, 1, tzinfo=timezone.utc),
                            datetime(2026, 9, 8, tzinfo=timezone.utc), "test")
    assert w.contains(None) is False
    assert w.contains("not-a-date") is False
    assert w.contains("2026-09-03T10:00:00Z") is True
    assert w.contains("2026-08-31T23:59:59Z") is False


class _FakeStore:
    mode = "test"

    def __init__(self):
        self.edges = {
            "a": [
                {"src": "a", "dst": "b", "type": "SHARES_DEVICE",
                 "ts": "2026-09-03T10:00:00Z", "count": 1},
                {"src": "a", "dst": "c", "type": "SHARES_DEVICE",
                 "ts": "2025-01-15T10:00:00Z", "count": 1},
                {"src": "a", "dst": "d", "type": "SHARES_DEVICE",
                 "ts": None, "count": 1},
            ],
            "b": [], "c": [], "d": [],
        }

    def neighbors(self, eid):
        return self.edges.get(eid, [])


def test_window_filters_paths():
    store = _FakeStore()
    w = temporal.TimeWindow(datetime(2026, 9, 1, tzinfo=timezone.utc),
                            datetime(2026, 9, 8, tzinfo=timezone.utc), "test")
    windowed = path_reasoning.enumerate_paths(store, ["a"], window=w)
    dests = {h["dst"] for p in windowed for h in p["hops"]}
    assert dests == {"b"}          # only the in-window dated edge survives
    unwindowed = path_reasoning.enumerate_paths(store, ["a"])
    dests_all = {h["dst"] for p in unwindowed for h in p["hops"]}
    assert dests_all == {"b", "c", "d"}


def test_window_with_no_matches_returns_empty():
    store = _FakeStore()
    w = temporal.TimeWindow(datetime(2024, 1, 1, tzinfo=timezone.utc),
                            datetime(2024, 2, 1, tzinfo=timezone.utc), "test")
    assert path_reasoning.enumerate_paths(store, ["a"], window=w) == []
