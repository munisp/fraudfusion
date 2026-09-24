"""Answer composition: grounded templates + optional local-LLM rephrasing.

Rules (honesty contract):
  * the template answer contains ONLY facts from scored KG paths
  * the ollama rephrase step receives the template facts and is instructed
    to rephrase without adding facts; any ollama failure (unreachable,
    timeout, error) degrades to the template answer with llm_used=False
  * when nothing links, the answer says so — nothing is fabricated

Env:
  OLLAMA_URL      e.g. http://ollama:11434 (unset/unreachable -> template only)
  OLLAMA_MODEL    default llama3.2:3b
  OLLAMA_TIMEOUT_S  request timeout, default 10
"""
from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger("kg-qa.compose")

OLLAMA_URL = os.environ.get("OLLAMA_URL")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_TIMEOUT_S = float(os.environ.get("OLLAMA_TIMEOUT_S", "10"))

_VERB = {
    "TRANSACTED_WITH": "transacted with",
    "SHARES_DEVICE": "shares a device with",
    "FLAGGED_BY": "was flagged by",
    "FILED_AGAINST": "filed against",
    "OWNS": "owns",
    "LOCATED_IN": "is located in",
    "WORKS_WITH": "works with",
}


def _short(eid: str, entities: dict[str, dict[str, Any]]) -> str:
    e = entities.get(eid)
    if not e:
        return eid
    label = e.get("label") or "Entity"
    name = e.get("props", {}).get("name") or e.get("props", {}).get("alert_type")
    suffix = eid.split("_")[-1][:8]
    return f"{label} {name or '…' + suffix}"


def render_path_text(hops: list[dict[str, Any]],
                     entities: dict[str, dict[str, Any]]) -> str:
    parts = []
    for h in hops:
        verb = _VERB.get(h["type"], h["type"].lower().replace("_", " "))
        seg = f"{_short(h['src'], entities)} {verb} {_short(h['dst'], entities)}"
        if h.get("ts"):
            seg += f" (as of {str(h['ts'])[:10]})"
        if h.get("count", 1) > 1:
            seg += f" [{h['count']}x]"
        parts.append(seg)
    return " → ".join(parts)


def template_answer(question: str, paths: list[dict[str, Any]],
                    entities: dict[str, dict[str, Any]],
                    linked: list[dict[str, Any]]) -> str:
    if not linked:
        return ("I could not link any part of your question to entities in the "
                "fraud knowledge graph. Try mentioning a bank, state/city, alert "
                "type, SAR status, or a pseudonymized entity id (e.g. "
                "customer_pii_…). No answer was generated.")
    if not paths:
        names = ", ".join(f"{l['label'] or 'Entity'} ({l['matched']})" for l in linked)
        return (f"I linked your question to {names}, but found no relationship "
                f"paths within the hop bound. The graph may not (yet) contain "
                f"connections for these entities.")
    lines = []
    for i, p in enumerate(paths, 1):
        text = render_path_text(p["hops"], entities)
        lines.append(f"{i}. {text} (score {p['score']:.3f})")
    header = (f"Based on the fraud knowledge graph, {len(paths)} relevant "
              f"relationship path(s) were found:")
    return header + "\n" + "\n".join(lines)


def ollama_rephrase(question: str, facts: str) -> str | None:
    """Ask the local LLM to rephrase grounded facts. Returns None on any
    failure — the caller then ships the template answer unchanged."""
    if not OLLAMA_URL:
        return None
    try:
        import httpx
    except ImportError:
        log.warning("httpx not installed; ollama rephrase unavailable")
        return None
    prompt = (
        "You are a fraud-analysis assistant. Rephrase the following "
        "knowledge-graph findings into one concise analyst-facing answer to "
        "the question. Do NOT add, infer or remove any facts; keep every "
        "entity reference and date exactly as given. If the findings say no "
        "answer exists, say so plainly.\n\n"
        f"Question: {question}\n\nFindings:\n{facts}\n\nAnswer:")
    try:
        r = httpx.post(f"{OLLAMA_URL.rstrip('/')}/api/generate",
                       json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
                             "options": {"temperature": 0.1}},
                       timeout=OLLAMA_TIMEOUT_S)
        r.raise_for_status()
        text = (r.json().get("response") or "").strip()
        return text or None
    except Exception as e:  # noqa: BLE001
        log.info("ollama rephrase unavailable (%s); using template answer", e)
        return None


def ollama_reachable() -> bool:
    if not OLLAMA_URL:
        return False
    try:
        import httpx
        r = httpx.get(f"{OLLAMA_URL.rstrip('/')}/api/tags", timeout=3.0)
        return r.status_code == 200
    except Exception:  # noqa: BLE001
        return False
