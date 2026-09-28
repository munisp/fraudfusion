"""Temporal phrase parsing for analyst questions.

Closes the Round-4 caveat "KGQA is retrieval-bound ... no temporal-phrase
parsing". Analysts ask time-scoped questions ("which accounts shared a device
last week?", "SARs filed since January"). This module extracts an explicit
[window_start, window_end] constraint from natural-language time phrases;
`path_reasoning.enumerate_paths` then filters edges whose `ts` falls outside
the window. When nothing survives the filter the answer says so honestly —
the window is reported in every response so the scope is never ambiguous.

Supported phrases (case-insensitive):
  today, yesterday, this week|month|quarter|year, recent
  last week|month|quarter|year
  last|past N days|weeks|months
  in <Month> [YYYY]        e.g. "in August", "in March 2026"
  in <YYYY>                e.g. "in 2025"
  since <Month> [YYYY]     e.g. "since January 2026"
  between <Month YYYY> and <Month YYYY>
  Q1..Q4 [YYYY]            e.g. "Q2 2026"

Everything is computed against an injectable `now` so tests are deterministic.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

_MONTHS = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
    "july": 7, "august": 8, "september": 9, "october": 10, "november": 11,
    "december": 12,
}
_MONTH_RE = "|".join(_MONTHS)


@dataclass(frozen=True)
class TimeWindow:
    start: datetime          # inclusive, tz-aware UTC
    end: datetime            # exclusive, tz-aware UTC
    phrase: str              # the matched source text, for honest reporting

    def contains(self, ts: str | None) -> bool:
        """Edges with no timestamp are EXCLUDED from time-scoped questions:
        we cannot claim an undated edge happened inside the window."""
        if not ts:
            return False
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return False
        return self.start <= dt < self.end

    def describe(self) -> str:
        return (f"{self.start.date().isoformat()} to "
                f"{(self.end - timedelta(days=1)).date().isoformat()}")


def _day(y: int, m: int, d: int) -> datetime:
    return datetime(y, m, d, tzinfo=timezone.utc)


def _month_window(y: int, m: int) -> tuple[datetime, datetime]:
    start = _day(y, m, 1)
    end = _day(y + 1, 1, 1) if m == 12 else _day(y, m + 1, 1)
    return start, end


def parse_temporal(question: str, now: datetime | None = None) -> TimeWindow | None:
    """Extract the FIRST temporal constraint from a question, if any."""
    now = now or datetime.now(timezone.utc)
    q = question.lower()
    today = _day(now.year, now.month, now.day)

    m = re.search(r"\b(?:last|past)\s+(\d+)\s+(day|week|month)s?\b", q)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        days = n * {"day": 1, "week": 7, "month": 30}[unit]
        return TimeWindow(today - timedelta(days=days), today + timedelta(days=1), m.group(0))

    m = re.search(rf"\bbetween\s+({_MONTH_RE})\s+(\d{{4}})\s+and\s+({_MONTH_RE})\s+(\d{{4}})\b", q)
    if m:
        s, _ = _month_window(int(m.group(2)), _MONTHS[m.group(1)])
        _, e = _month_window(int(m.group(4)), _MONTHS[m.group(3)])
        return TimeWindow(s, e, m.group(0))

    m = re.search(rf"\bsince\s+({_MONTH_RE})(?:\s+(\d{{4}}))?\b", q)
    if m:
        y = int(m.group(2)) if m.group(2) else now.year
        s, _ = _month_window(y, _MONTHS[m.group(1)])
        return TimeWindow(s, today + timedelta(days=1), m.group(0))

    m = re.search(rf"\bin\s+({_MONTH_RE})(?:\s+(\d{{4}}))?\b", q)
    if m:
        y = int(m.group(2)) if m.group(2) else now.year
        s, e = _month_window(y, _MONTHS[m.group(1)])
        return TimeWindow(s, e, m.group(0))

    m = re.search(r"\bq([1-4])(?:\s+(\d{4}))?\b", q)
    if m:
        qtr = int(m.group(1))
        y = int(m.group(2)) if m.group(2) else now.year
        s, _ = _month_window(y, 3 * (qtr - 1) + 1)
        _, e = _month_window(y, 3 * (qtr - 1) + 3)
        return TimeWindow(s, e, m.group(0))

    m = re.search(r"\bin\s+(\d{4})\b", q)
    if m:
        y = int(m.group(1))
        return TimeWindow(_day(y, 1, 1), _day(y + 1, 1, 1), m.group(0))

    simple = {
        "today": (today, today + timedelta(days=1)),
        "yesterday": (today - timedelta(days=1), today),
        "this week": (today - timedelta(days=today.weekday()), today + timedelta(days=1)),
        "this month": _month_window(now.year, now.month),
        "this year": (_day(now.year, 1, 1), _day(now.year + 1, 1, 1)),
        "last week": (today - timedelta(days=today.weekday() + 7),
                      today - timedelta(days=today.weekday())),
        "last month": _month_window(now.year if now.month > 1 else now.year - 1,
                                    now.month - 1 if now.month > 1 else 12),
        "last year": (_day(now.year - 1, 1, 1), _day(now.year, 1, 1)),
        "recent": (today - timedelta(days=30), today + timedelta(days=1)),
    }
    for phrase, (s, e) in simple.items():
        if re.search(rf"\b{re.escape(phrase)}\b", q):
            return TimeWindow(s, e, phrase)
    return None
