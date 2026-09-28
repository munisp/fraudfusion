"""Tests for events-consumer: FileTailSource tailing, archive + weekly
aggregate writes, honest source selection and health reporting.

Run: python3 -m pytest tests/ -q   (from services/python/events-consumer)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from consumer import (  # noqa: E402
    ArchiveSink,
    EventsConsumer,
    FileTailSource,
    select_source,
)


@pytest.fixture()
def sink(tmp_path):
    return ArchiveSink(database_url="", sqlite_path=str(tmp_path / "events.db"))


def write_jsonl(path: Path, events: list[dict]) -> None:
    with path.open("a") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")


class TestFileTailSource:
    def test_reads_and_resumes_from_checkpoint(self, tmp_path):
        events_dir = tmp_path / "lake"
        events_dir.mkdir()
        f = events_dir / "events.jsonl"
        write_jsonl(f, [
            {"key": "k1", "event_type": "transaction.scored",
             "timestamp": "2026-08-31T10:00:00Z", "payload": {"amount": 100}},
            {"key": "k2", "event_type": "alert.raised",
             "timestamp": "2026-08-31T10:01:00Z", "payload": {"severity": "high"}},
        ])
        source = FileTailSource(str(events_dir))
        batch = list(source.read_batch(10))
        assert len(batch) == 2
        assert batch[0].event_type == "transaction.scored"
        # checkpoint persisted; a fresh source instance resumes, no replay
        source2 = FileTailSource(str(events_dir))
        assert list(source2.read_batch(10)) == []
        write_jsonl(f, [{"key": "k3", "event_type": "alert.raised",
                         "timestamp": "2026-09-01T00:00:00Z", "payload": {}}])
        batch = list(source2.read_batch(10))
        assert len(batch) == 1 and batch[0].key == "k3"

    def test_malformed_lines_skipped_loudly(self, tmp_path, caplog):
        import logging

        events_dir = tmp_path / "lake"
        events_dir.mkdir()
        f = events_dir / "events.jsonl"
        f.write_text('{"event_type": "ok", "payload": {}}\nnot-json\n')
        source = FileTailSource(str(events_dir))
        with caplog.at_level(logging.ERROR):
            batch = list(source.read_batch(10))
        assert len(batch) == 1
        assert any("malformed" in r.message for r in caplog.records)


class TestArchiveAndAggregates:
    def test_archive_and_weekly_aggregates(self, tmp_path, sink):
        events_dir = tmp_path / "lake"
        events_dir.mkdir()
        write_jsonl(events_dir / "events.jsonl", [
            {"key": "k1", "event_type": "transaction.scored",
             "timestamp": "2026-08-31T10:00:00Z", "payload": {"amount": 100}},
            {"key": "k2", "event_type": "transaction.scored",
             "timestamp": "2026-09-01T10:00:00Z", "payload": {"amount": 200}},
            {"key": "k3", "event_type": "alert.raised",
             "timestamp": "2026-09-05T10:00:00Z", "payload": {"severity": "high"}},
        ])
        consumer = EventsConsumer(FileTailSource(str(events_dir)), sink)
        assert consumer.run_once() == 3

        archived = sink.query("SELECT * FROM events_archive ORDER BY id")
        assert len(archived) == 3
        assert all(r["source"] == "filetail" for r in archived)
        assert json.loads(archived[0]["payload"])["amount"] == 100

        # 2026-08-31 is the Monday of its week; 2026-09-05 belongs to the
        # week starting 2026-08-31 too... both scored events are same week.
        aggs = sink.query(
            "SELECT week_start, event_type, event_count FROM events_aggregates_weekly"
            " ORDER BY event_type")
        by_type = {(a["week_start"], a["event_type"]): a["event_count"] for a in aggs}
        assert by_type[("2026-08-31", "transaction.scored")] == 2
        assert by_type[("2026-08-31", "alert.raised")] == 1

        # second run: no duplicates (source checkpointed)
        assert consumer.run_once() == 0
        assert sink.query("SELECT COUNT(*) c FROM events_archive")[0]["c"] == 3

    def test_health_reports_source_honestly(self, tmp_path, sink):
        events_dir = tmp_path / "lake"
        events_dir.mkdir()
        consumer = EventsConsumer(FileTailSource(str(events_dir)), sink)
        health = consumer.health()
        assert health["source"] == "filetail"
        assert health["status"] == "healthy"


class TestSourceSelection:
    def test_auto_fails_closed_when_nothing_configured(self, monkeypatch):
        monkeypatch.setattr("consumer.EVENTS_SOURCE", "auto")
        monkeypatch.setattr("consumer.BOOTSTRAP", "")
        monkeypatch.setattr("consumer.EVENTS_FILE_DIR", "")
        with pytest.raises(RuntimeError, match="no event source"):
            select_source()

    def test_explicit_kafka_requires_bootstrap(self, monkeypatch):
        monkeypatch.setattr("consumer.EVENTS_SOURCE", "kafka")
        monkeypatch.setattr("consumer.BOOTSTRAP", "")
        try:
            from kafka.errors import NoBrokersAvailable
        except ImportError:
            NoBrokersAvailable = RuntimeError

        with pytest.raises((RuntimeError, NoBrokersAvailable)):
            select_source()

    def test_filetail_selected_when_dir_configured(self, monkeypatch, tmp_path):
        monkeypatch.setattr("consumer.EVENTS_SOURCE", "auto")
        monkeypatch.setattr("consumer.BOOTSTRAP", "")
        monkeypatch.setattr("consumer.EVENTS_FILE_DIR", str(tmp_path))
        source = select_source()
        assert source.name == "filetail"
