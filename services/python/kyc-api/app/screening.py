"""PEP and sanctions screening against local list data.

- PEP screening: fuzzy name match (token-sort ratio, stdlib difflib) against
  the `pep_list` table, with date-of-birth / nationality agreement raising
  the match score.
- Sanctions screening: matches against the local watchlist. Source precedence:
  `watchlist` DB table when populated, else the JSON seed file
  (WATCHLIST_PATH, default data/watchlist.json). The file is an honest stub:
  live UN/OFAC/NFIU list feeds are NOT integrated; every response carries
  list provenance so callers can see what was actually screened.
"""

from __future__ import annotations

import json
import os
import unicodedata
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Optional

WATCHLIST_PATH = os.getenv(
    "WATCHLIST_PATH",
    str(Path(__file__).resolve().parent.parent / "data" / "watchlist.json"),
)

# Fuzzy match thresholds (token-sort ratio 0..1).
PEP_MATCH_THRESHOLD = 0.85
SANCTIONS_MATCH_THRESHOLD = 0.90


def _normalize(name: str) -> str:
    text = unicodedata.normalize("NFKD", name or "")
    text = "".join(c for c in text if not unicodedata.combining(c))
    return " ".join(text.lower().replace("-", " ").split())


def name_similarity(a: str, b: str) -> float:
    """Token-sort ratio: order-insensitive fuzzy name comparison."""
    na, nb = _normalize(a), _normalize(b)
    if not na or not nb:
        return 0.0
    ta, tb = " ".join(sorted(na.split())), " ".join(sorted(nb.split()))
    return SequenceMatcher(None, ta, tb).ratio()


def _score_entry(query_name: str, query_dob: Optional[str], query_nat: Optional[str],
                 entry: dict) -> float:
    score = name_similarity(query_name, entry.get("full_name", ""))
    # Corroborating attributes nudge a borderline name match upward; a
    # contradictory DOB (both present, different) penalizes.
    if query_dob and entry.get("date_of_birth"):
        score += 0.10 if query_dob == entry["date_of_birth"] else -0.15
    if query_nat and entry.get("nationality"):
        if query_nat.upper() == str(entry["nationality"]).upper():
            score += 0.05
    return max(0.0, min(1.0, score))


def screen_pep(db, full_name: str, date_of_birth: Optional[str] = None,
               nationality: Optional[str] = None) -> dict:
    entries = db.query(
        "SELECT id, full_name, date_of_birth, nationality, position, source FROM pep_list"
    )
    matches = []
    for e in entries:
        score = _score_entry(full_name, date_of_birth, nationality, e)
        if score >= PEP_MATCH_THRESHOLD:
            matches.append({
                "entry_id": e["id"],
                "full_name": e["full_name"],
                "position": e.get("position", ""),
                "nationality": e.get("nationality"),
                "score": round(score, 3),
                "list_source": e.get("source", "local"),
            })
    matches.sort(key=lambda m: m["score"], reverse=True)
    return {
        "full_name": full_name,
        "is_pep": bool(matches),
        "matches": matches,
        "list": "pep_list (local)",
        "entries_screened": len(entries),
    }


def _load_watchlist_file(path: str = WATCHLIST_PATH) -> list[dict[str, Any]]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    if isinstance(data, dict):
        data = data.get("entries", [])
    return [e for e in data if isinstance(e, dict) and e.get("full_name")]


def load_watchlist(db=None) -> tuple[list[dict[str, Any]], str]:
    """Return (entries, provenance). DB table wins when populated."""
    if db is not None:
        rows = db.query(
            "SELECT id, full_name, date_of_birth, nationality, program, source FROM watchlist"
        )
        if rows:
            return rows, "watchlist (database table)"
    return _load_watchlist_file(), "watchlist (local seed file)"


def screen_sanctions(db, full_name: str, date_of_birth: Optional[str] = None,
                     nationality: Optional[str] = None,
                     passport_number: Optional[str] = None) -> dict:
    entries, provenance = load_watchlist(db)
    matches = []
    for e in entries:
        score = _score_entry(full_name, date_of_birth, nationality, e)
        if passport_number and e.get("passport_number"):
            score = min(1.0, score + (0.15 if passport_number == e["passport_number"] else 0.0))
        if score >= SANCTIONS_MATCH_THRESHOLD:
            matches.append({
                "full_name": e["full_name"],
                "program": e.get("program", ""),
                "nationality": e.get("nationality"),
                "score": round(score, 3),
                "list_source": e.get("source", "local"),
            })
    matches.sort(key=lambda m: m["score"], reverse=True)
    return {
        "full_name": full_name,
        "is_sanctioned": bool(matches),
        "matches": matches,
        "list": provenance,
        "entries_screened": len(entries),
        # Honest provenance: no live UN/OFAC/NFIU feed is integrated.
        "live_feeds": "not_configured",
    }


def comprehensive_screening(db, full_name: str, date_of_birth: Optional[str] = None,
                            nationality: Optional[str] = None,
                            passport_number: Optional[str] = None) -> dict:
    pep = screen_pep(db, full_name, date_of_birth, nationality)
    sanctions = screen_sanctions(db, full_name, date_of_birth, nationality, passport_number)
    if sanctions["is_sanctioned"]:
        recommendation = "reject"
    elif pep["is_pep"]:
        recommendation = "enhanced_due_diligence"
    else:
        recommendation = "proceed"
    return {
        "full_name": full_name,
        "pep": pep,
        "sanctions": sanctions,
        "recommendation": recommendation,
    }
