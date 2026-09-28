"""FraudFusion events consumer.

Consumes the `fraudfusion-events` topic and writes into Postgres
`events_archive` (append-only) + weekly per-type aggregates
(`events_aggregates_weekly`, the intel_state_weekly-style hook; the intel
service is owned by another lane and reads these tables).

Sources (dependency-injected, honestly reported in /health as
`source: kafka|filetail`):
  * KafkaSource     — kafka-python consumer (KAFKA_BOOTSTRAP_SERVERS).
                      Selected when EVENTS_SOURCE=kafka, or
                      EVENTS_SOURCE=auto with kafka-python installed and
                      KAFKA_BOOTSTRAP_SERVERS set.
  * FileTailSource  — tails the lakehouse jsonl export (EVENTS_FILE_DIR,
                      *.jsonl, one event JSON per line). Used as the fallback
                      when Kafka is not configured; state is checkpointed in
                      a local file so restarts resume rather than replay.

There is deliberately NO fake/in-memory source: when neither backend is
usable the consumer refuses to start (fail closed).

Run: python3 consumer.py  (health on :8090)
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("events-consumer")

TOPIC = os.getenv("KAFKA_TOPIC", "fraudfusion-events")
BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "").strip()
EVENTS_FILE_DIR = os.getenv("EVENTS_FILE_DIR", "").strip()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
SQLITE_PATH = os.getenv("EVENTS_DB", str(Path(__file__).resolve().parent / "data" / "events.db"))
EVENTS_SOURCE = os.getenv("EVENTS_SOURCE", "auto").strip().lower()
BATCH_SIZE = int(os.getenv("EVENTS_BATCH_SIZE", "200"))


@dataclass
class Event:
    key: Optional[str]
    event_type: str
    payload: dict[str, Any]
    event_ts: Optional[str] = None
    partition: Optional[int] = None
    offset: Optional[int] = None


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

class KafkaSource:
    name = "kafka"

    def __init__(self, bootstrap: str = BOOTSTRAP, topic: str = TOPIC,
                 group_id: str = "events-consumer"):
        try:
            from kafka import KafkaConsumer
        except ImportError as exc:
            raise RuntimeError(
                "EVENTS_SOURCE=kafka requires kafka-python (pip install kafka-python)"
            ) from exc
        if not bootstrap.strip():
            raise RuntimeError(
                "EVENTS_SOURCE=kafka requires KAFKA_BOOTSTRAP_SERVERS to be set"
            )
        self.topic = topic
        self._consumer = KafkaConsumer(
            topic,
            bootstrap_servers=bootstrap.split(","),
            group_id=group_id,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
            value_deserializer=lambda b: json.loads(b.decode("utf-8")),
            consumer_timeout_ms=1000,
        )

    def read_batch(self, limit: int) -> Iterator[Event]:
        count = 0
        for msg in self._consumer:
            body = msg.value if isinstance(msg.value, dict) else {"payload": msg.value}
            yield Event(
                key=body.get("key") or (msg.key.decode() if msg.key else None),
                event_type=body.get("event_type", "unknown"),
                payload=body.get("payload", body),
                event_ts=body.get("timestamp"),
                partition=msg.partition,
                offset=msg.offset,
            )
            count += 1
            if count >= limit:
                break

    def commit(self) -> None:
        self._consumer.commit()


class FileTailSource:
    """Tails EVENTS_FILE_DIR/*.jsonl (the lakehouse event export). One JSON
    event per line. Per-file byte offsets are checkpointed to a local state
    file so restarts resume where they stopped."""

    name = "filetail"

    def __init__(self, directory: str, state_file: Optional[str] = None):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.state_file = Path(state_file) if state_file else self.directory / ".filetail_state.json"
        self._offsets: dict[str, int] = self._load_state()
        self.commit = lambda: None  # offsets are checkpointed per batch already

    def _load_state(self) -> dict[str, int]:
        try:
            return json.loads(self.state_file.read_text())
        except Exception:
            return {}

    def _save_state(self) -> None:
        self.state_file.write_text(json.dumps(self._offsets))

    def read_batch(self, limit: int) -> Iterator[Event]:
        count = 0
        for path in sorted(self.directory.glob("*.jsonl")):
            if count >= limit:
                break
            offset = self._offsets.get(str(path), 0)
            size = path.stat().st_size
            if offset >= size:
                continue
            with path.open("r", encoding="utf-8") as fh:
                fh.seek(offset)
                for line in fh:
                    if count >= limit:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        body = json.loads(line)
                    except json.JSONDecodeError:
                        logger.error("skipping malformed jsonl line in %s", path.name)
                        continue
                    yield Event(
                        key=body.get("key"),
                        event_type=body.get("event_type", "unknown"),
                        payload=body.get("payload", body),
                        event_ts=body.get("timestamp"),
                    )
                    count += 1
                self._offsets[str(path)] = fh.tell()
        self._save_state()


def select_source() -> KafkaSource | FileTailSource:
    """EVENTS_SOURCE=kafka|filetail|auto. Auto: kafka only when kafka-python
    is importable AND KAFKA_BOOTSTRAP_SERVERS is set; otherwise filetail when
    EVENTS_FILE_DIR is set; otherwise refuse to start (fail closed)."""
    if EVENTS_SOURCE == "kafka":
        return KafkaSource()
    if EVENTS_SOURCE == "filetail":
        if not EVENTS_FILE_DIR:
            raise RuntimeError("EVENTS_SOURCE=filetail requires EVENTS_FILE_DIR")
        return FileTailSource(EVENTS_FILE_DIR)
    # auto
    if BOOTSTRAP:
        try:
            return KafkaSource()
        except RuntimeError as exc:
            logger.error("Kafka unavailable (%s); trying filetail fallback", exc)
    if EVENTS_FILE_DIR:
        logger.warning("Kafka not configured; consuming lakehouse jsonl from %s "
                       "(source: filetail)", EVENTS_FILE_DIR)
        return FileTailSource(EVENTS_FILE_DIR)
    raise RuntimeError(
        "no event source available: set KAFKA_BOOTSTRAP_SERVERS (kafka) or "
        "EVENTS_FILE_DIR (filetail)"
    )


# ---------------------------------------------------------------------------
# Sink
# ---------------------------------------------------------------------------

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS events_archive (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    topic        TEXT NOT NULL DEFAULT 'fraudfusion-events',
    partition    INTEGER,
    kafka_offset INTEGER,
    event_key    TEXT,
    event_type   TEXT,
    payload      TEXT NOT NULL,
    source       TEXT NOT NULL CHECK (source IN ('kafka', 'filetail')),
    event_ts     TEXT,
    archived_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS events_aggregates_weekly (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    week_start  TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (tenant_id, week_start, event_type)
);
"""


class ArchiveSink:
    """Writes events_archive + events_aggregates_weekly. Dual driver:
    psycopg/Postgres when DATABASE_URL is postgres, else a SQLite mirror."""

    def __init__(self, database_url: str = DATABASE_URL, sqlite_path: str = SQLITE_PATH):
        self._lock = threading.Lock()
        self._is_pg = database_url.startswith(("postgres://", "postgresql://"))
        if self._is_pg:
            import psycopg

            self._psycopg = psycopg
            self._dsn = database_url
            self._conn = None
        else:
            Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(sqlite_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            with self._lock, self._conn:
                self._conn.executescript(SQLITE_SCHEMA)

    @staticmethod
    def week_start(ts: Optional[str]) -> str:
        try:
            dt = datetime.fromisoformat((ts or "").replace("Z", "+00:00"))
        except ValueError:
            dt = datetime.now(timezone.utc)
        monday = dt.date().toordinal() - dt.weekday()
        return datetime.fromordinal(monday).date().isoformat()

    def write(self, source_name: str, events: list[Event]) -> int:
        if not events:
            return 0
        counts: dict[str, int] = {}
        with self._lock:
            if self._is_pg:
                with self._psycopg.connect(self._dsn) as conn:
                    for ev in events:
                        conn.execute(
                            "INSERT INTO events_archive (topic, partition, kafka_offset,"
                            " event_key, event_type, payload, source, event_ts)"
                            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                            " ON CONFLICT (topic, partition, kafka_offset) DO NOTHING",
                            (TOPIC, ev.partition, ev.offset, ev.key, ev.event_type,
                             json.dumps(ev.payload), source_name, ev.event_ts),
                        )
                        week = self.week_start(ev.event_ts)
                        counts[week + "|" + ev.event_type] = counts.get(week + "|" + ev.event_type, 0) + 1
                    for combo, n in counts.items():
                        week, event_type = combo.split("|", 1)
                        conn.execute(
                            "INSERT INTO events_aggregates_weekly (week_start, event_type,"
                            " event_count) VALUES (%s, %s, %s)"
                            " ON CONFLICT (tenant_id, week_start, event_type) DO UPDATE SET"
                            " event_count = events_aggregates_weekly.event_count + %s,"
                            " updated_at = now()",
                            (week, event_type, n, n),
                        )
                    conn.commit()
            else:
                with self._conn:
                    for ev in events:
                        self._conn.execute(
                            "INSERT INTO events_archive (topic, partition, kafka_offset,"
                            " event_key, event_type, payload, source, event_ts)"
                            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (TOPIC, ev.partition, ev.offset, ev.key, ev.event_type,
                             json.dumps(ev.payload), source_name, ev.event_ts),
                        )
                        week = self.week_start(ev.event_ts)
                        counts[week + "|" + ev.event_type] = counts.get(week + "|" + ev.event_type, 0) + 1
                    for combo, n in counts.items():
                        week, event_type = combo.split("|", 1)
                        self._conn.execute(
                            "INSERT INTO events_aggregates_weekly (week_start, event_type,"
                            " event_count) VALUES (?, ?, ?)"
                            " ON CONFLICT (tenant_id, week_start, event_type) DO UPDATE SET"
                            " event_count = event_count + ?,"
                            " updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
                            (week, event_type, n, n),
                        )
        return len(events)

    def query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        if self._is_pg:
            from psycopg.rows import dict_row

            with self._psycopg.connect(self._dsn, row_factory=dict_row) as conn:
                return [dict(r) for r in conn.execute(sql, params).fetchall()]
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]


# ---------------------------------------------------------------------------
# Consumer loop + health
# ---------------------------------------------------------------------------

class EventsConsumer:
    def __init__(self, source, sink: ArchiveSink, batch_size: int = BATCH_SIZE):
        self.source = source
        self.sink = sink
        self.batch_size = batch_size
        self.consumed_total = 0
        self.last_batch_at: Optional[str] = None
        self._stop = threading.Event()

    def run_once(self) -> int:
        batch = list(self.source.read_batch(self.batch_size))
        written = self.sink.write(self.source.name, batch)
        self.consumed_total += written
        if written:
            self.last_batch_at = datetime.now(timezone.utc).isoformat()
        if batch:
            self.source.commit()
        return written

    def run_forever(self, idle_sleep: float = 2.0) -> None:
        logger.info("events consumer started: source=%s topic=%s", self.source.name, TOPIC)
        while not self._stop.is_set():
            try:
                written = self.run_once()
            except Exception:
                logger.exception("consumer iteration failed; backing off")
                time.sleep(5)
                continue
            if not written:
                time.sleep(idle_sleep)

    def stop(self) -> None:
        self._stop.set()

    def health(self) -> dict[str, Any]:
        return {
            "status": "healthy",
            "service": "events-consumer",
            "source": self.source.name,  # honest: kafka | filetail
            "topic": TOPIC,
            "consumed_total": self.consumed_total,
            "last_batch_at": self.last_batch_at,
        }


_consumer: Optional[EventsConsumer] = None


def main() -> None:
    global _consumer

    from fastapi import FastAPI
    import uvicorn

    source = select_source()
    sink = ArchiveSink()
    _consumer = EventsConsumer(source, sink)

    app = FastAPI(title="FraudFusion Events Consumer")

    @app.get("/health")
    def health():
        return _consumer.health()

    thread = threading.Thread(target=_consumer.run_forever, daemon=True)
    thread.start()
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("HEALTH_PORT", "8090")))


if __name__ == "__main__":
    main()
