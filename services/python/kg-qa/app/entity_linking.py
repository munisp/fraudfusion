"""Entity linking: map natural-language question mentions to KG entities.

Strategy (EPR-KGQA-style, no ML dependency):
  1. exact — question contains the entity id or a prop alias verbatim
     (case-insensitive token/substring match)
  2. fuzzy — difflib ratio >= FUZZY_THRESHOLD between a question n-gram and
     an alias (bounded to aliases with length >= 4 to avoid noise)

Returns ranked candidates with a score in (0, 1]. Pseudonymized ids are
matched when analysts paste them; human-readable aliases come from entity
props (bank, state, city, alert_type, status, name).
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any

from .graph_store import GraphStore

FUZZY_THRESHOLD = 0.85
MAX_LINKED = 8

_TOKEN_RE = re.compile(r"[a-zA-Z0-9_:\-\.]+")


def _question_ngrams(question: str, max_n: int = 4) -> list[str]:
    tokens = _TOKEN_RE.findall(question.lower())
    grams: list[str] = []
    for n in range(1, max_n + 1):
        for i in range(0, len(tokens) - n + 1):
            grams.append(" ".join(tokens[i:i + n]))
    return grams


def link_entities(question: str, store: GraphStore,
                  max_linked: int = MAX_LINKED) -> list[dict[str, Any]]:
    """Return up to max_linked {entity_id, label, score, matched} candidates."""
    q = question.lower()
    grams = _question_ngrams(question)
    scored: dict[str, dict[str, Any]] = {}

    aliases = store.search_aliases()
    ent_meta = store.get_entities([eid for _a, eid in aliases])

    for alias, eid in aliases:
        a = alias.lower()
        if len(a) < 3:
            continue
        # exact substring (word-boundary-ish)
        if a in q:
            score = 1.0 if a == q.strip() else 0.95
            _bump(scored, eid, ent_meta, score, alias)
            continue
        # fuzzy against question n-grams
        if len(a) >= 4:
            best = 0.0
            for g in grams:
                if abs(len(g) - len(a)) > max(3, len(a) // 2):
                    continue
                ratio = SequenceMatcher(None, a, g).ratio()
                if ratio > best:
                    best = ratio
            if best >= FUZZY_THRESHOLD:
                _bump(scored, eid, ent_meta, best * 0.9, alias)

    ranked = sorted(scored.values(), key=lambda x: -x["score"])
    return ranked[:max_linked]


def _bump(scored: dict, eid: str, ent_meta: dict, score: float, matched: str) -> None:
    cur = scored.get(eid)
    if cur is None or score > cur["score"]:
        meta = ent_meta.get(eid, {})
        scored[eid] = {"entity_id": eid, "label": meta.get("label"),
                       "score": score, "matched": matched}
