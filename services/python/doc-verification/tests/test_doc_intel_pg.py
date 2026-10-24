"""Round 15: PostgreSQL source-of-record conformance for the document
intelligence store. Runs the real engine against an embedded PostgreSQL
(pgserver) with the canonical migration applied — skipped cleanly when
pgserver/psycopg are unavailable.

Also pins the production guard: FRAUDFUSION_REQUIRE_POSTGRES=1 makes the
SQLite fallback a boot-time error.

Run: python3 -m pytest tests/test_doc_intel_pg.py -q
"""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import cv2
import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import doc_intelligence  # noqa: E402

pgserver = pytest.importorskip("pgserver", reason="embedded postgres unavailable")
psycopg = pytest.importorskip("psycopg", reason="psycopg unavailable")

MIGRATION = (Path(__file__).resolve().parents[4]
             / "database" / "20261028_document_intelligence.sql")


@pytest.fixture(scope="module")
def pg_url(tmp_path_factory):
    xdg = Path("/tmp/xdg"); xdg.mkdir(parents=True, exist_ok=True)
    os.environ["XDG_RUNTIME_DIR"] = str(xdg)
    pg = pgserver.get_server(tmp_path_factory.mktemp("docintel-pg"))
    url = pg.get_uri()
    with psycopg.connect(url) as conn:
        conn.execute(MIGRATION.read_text())
        conn.commit()
    return url


def _img_b64(seed: int = 11) -> str:
    rng = np.random.default_rng(seed)
    img = rng.normal(225, 6, (384, 512, 3)).clip(0, 255).astype(np.uint8)
    y = 40
    while y < 320:
        cv2.rectangle(img, (40, y), (40 + int(rng.integers(200, 420)), y + 14),
                      (40, 40, 40), -1)
        y += int(rng.integers(28, 55))
    ok, enc = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 95])
    return base64.b64encode(enc.tobytes()).decode()


class TestPostgresSourceOfRecord:
    def test_engine_full_cycle_on_postgres(self, pg_url):
        store = doc_intelligence.DocIntelStore(database_url=pg_url)
        assert store._is_pg is True
        payload = doc_intelligence.IntelligenceInput(
            image_base64=_img_b64(), doc_type="certificate_of_occupancy",
            register=True, reference="pg-conformance")
        result = doc_intelligence.run_intelligence(store, payload)
        doc_hash = result["document_sha256"]
        # Registry row persisted in PG:
        row = store.query_one("SELECT * FROM doc_registry WHERE doc_hash = :d",
                              {"d": doc_hash})
        assert row["status"] == "active"
        # Resubmission detected from PG state:
        again = doc_intelligence.run_intelligence(store, payload)
        assert "same_document_resubmitted" in {f["code"] for f in again["factors"]}
        # Hash-chained verification log persisted and verifies from PG rows:
        chain = store.get_chain(doc_hash)
        assert len(chain) >= 2
        assert doc_intelligence.DocIntelStore.verify_chain(chain, doc_hash) is True
        # Revocation forces forgery verdict, all served from PG:
        store.execute(
            "UPDATE doc_registry SET status = 'revoked', revoke_reason = 'pg-test'"
            " WHERE doc_hash = :d", {"d": doc_hash})
        third = doc_intelligence.run_intelligence(store, payload)
        assert third["authenticity_score"] == 100
        assert third["verdict"] == "rejected"

    def test_require_postgres_guard(self, monkeypatch, tmp_path):
        monkeypatch.setenv("FRAUDFUSION_REQUIRE_POSTGRES", "1")
        with pytest.raises(RuntimeError, match="source of record"):
            doc_intelligence.DocIntelStore(database_url="",
                                           sqlite_path=str(tmp_path / "x.db"))
        monkeypatch.delenv("FRAUDFUSION_REQUIRE_POSTGRES")
        # Opt-in dev path still works when the guard is off:
        store = doc_intelligence.DocIntelStore(database_url="",
                                               sqlite_path=str(tmp_path / "ok.db"))
        assert store._is_pg is False
