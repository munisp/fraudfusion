"""Deed-of-assignment template conformance checker.

Implements the video recommendation that every land sale should follow one
standard state deed template ("It happens in America... that is the standard
for this state" — once the template is standard, interpretation is uniform
and remedies/penalties are known). Until Lagos State publishes that template,
this checker enforces the clauses any conformant deed of assignment must
contain under Nigerian conveyancing practice and the Land Use Act 1978:

  parties            — named assignor AND assignee
  recitals           — root of title / ownership history ("WHEREAS")
  consideration      — purchase price stated
  parcel_description — plot number and/or survey plan and/or beacon coordinates
  habendum           — "TO HAVE AND TO HOLD"
  covenants          — assignor covenants (quiet enjoyment / good title)
  governors_consent  — Land Use Act s.22 consent clause
  execution          — signature blocks for ALL parties incl. consent parties
  attestation        — witness clause

Pure function, no I/O — unit-testable in isolation.
"""

from __future__ import annotations

import re
from typing import Any

# Each clause: (name, description, [regex alternatives])
_CLAUSES: list[tuple[str, str, list[str]]] = [
    ("parties", "Named assignor and assignee",
     [r"\bassignor\b.*\bassignee\b", r"\bassignee\b.*\bassignor\b"]),
    ("recitals", "Recitals / root of title (WHEREAS ...)",
     [r"\bwhereas\b", r"\broot of title\b"]),
    ("consideration", "Purchase consideration stated",
     [r"\bconsideration\b", r"\bpurchase (price|sum)\b", r"\b(naira|ngn|₦)\s*[\d,]+",
      r"\bsum of\b"]),
    ("parcel_description", "Parcel description (plot / survey plan / beacons)",
     [r"\bplot\s*(no\.?|number|#)?\s*\w*\d", r"\bsurvey plan\b", r"\bplan\s*(no\.?|number)\b",
      r"\bbeacons?\b", r"\b\d+\.\d+\s*[ns]\b.*\b\d+\.\d+\s*[ew]\b"]),
    ("habendum", "Habendum (TO HAVE AND TO HOLD)",
     [r"to have and to hold"]),
    ("covenants", "Assignor covenants (title / quiet enjoyment)",
     [r"\bcovenants?\b", r"\bquiet enjoyment\b"]),
    ("governors_consent", "Governor's consent clause (Land Use Act s.22)",
     [r"governor'?s consent", r"\bsection 22\b", r"\bs\.?\s*22\b.*\bland use act\b",
      r"\bland use act\b"]),
    ("execution", "Execution / signature blocks",
     [r"\bsigned\b", r"\bsignature\b", r"\bin witness whereof\b",
      r"\bexecuted\b"]),
    ("attestation", "Attestation / witness clause",
     [r"\bwitness\b", r"\battest"]),
]


def check_deed_conformance(deed_text: str,
                           consent_parties: list[str] | None = None) -> dict[str, Any]:
    """Check a deed of assignment against the standard clause list.

    Returns {conformant, score, present, missing, consent_parties_missing}.
    A deed is conformant only when every clause is present AND every named
    consent party's signature block appears (family-consent fraud from the
    video: heirs later denying they signed).
    """
    text = (deed_text or "").strip()
    low = text.lower()
    present: list[str] = []
    missing: list[dict[str, str]] = []
    for name, description, patterns in _CLAUSES:
        if any(re.search(p, low, flags=re.DOTALL) for p in patterns):
            present.append(name)
        else:
            missing.append({"clause": name, "description": description})

    consent_missing: list[str] = []
    lines = low.splitlines()
    for party in consent_parties or []:
        pname = party.strip().lower()
        if not pname:
            continue
        # A consent party must sign: their name must share a LINE with an
        # execution/consent marker. A name in the recitals (the video's exact
        # fraud — an heir who never signed later denies consent) is not
        # consent, and a neighbour's signature block is not theirs.
        if any(pname in line
               and re.search(r"\b(signed|signature|sign|consent|executed|thumbprint)\b", line)
               for line in lines):
            continue
        consent_missing.append(party.strip())

    total = len(_CLAUSES)
    conformant = not missing and not consent_missing and bool(text)
    return {
        "conformant": conformant,
        "score": round((total - len(missing)) / total, 3),
        "present": present,
        "missing": missing,
        "consent_parties_missing": consent_missing,
    }
