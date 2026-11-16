"""Shared building blocks: numbered lines, findings, and citation verification.

Every warning the checker shows must cite real lines of the message, and the
quoted words must appear there. Findings with no valid citation are dropped.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict

RISK_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Finding:
    title: str
    explanation: str
    risk: str = "medium"          # high | medium | low
    line_ids: list[int] = field(default_factory=list)
    quote: str = ""               # text the finding relied on
    verified: bool = False
    rule_id: str = ""
    advice: str = ""
    kind: str = "text"            # text | signal | model

    def to_dict(self) -> dict:
        return asdict(self)


def split_lines(text: str) -> list[tuple[int, str]]:
    """Split a document into numbered, non-empty lines.

    Long paragraphs are split on sentence boundaries so a citation points at
    a sentence, not a wall of text. Numbering is 1-based and stable.
    """
    pieces: list[str] = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        if len(raw) > 240:
            parts = re.split(r"(?<=[.;!?])\s+(?=[A-Z0-9\"(])", raw)
            pieces.extend(p.strip() for p in parts if p.strip())
        else:
            pieces.append(raw)
    return [(i + 1, p) for i, p in enumerate(pieces)]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def verify(findings: list[Finding], lines: list[tuple[int, str]]) -> tuple[list[Finding], dict]:
    """Check every citation against the source. Drop unsupported findings.

    A finding is kept only if at least one cited line exists. It is marked
    verified when all cited ids exist AND its quote (if given) appears
    verbatim (ignoring whitespace and case) in the cited lines.
    """
    by_id = dict(lines)
    kept: list[Finding] = []
    dropped = 0
    for f in findings:
        valid_ids = [i for i in f.line_ids if i in by_id]
        if not valid_ids:
            dropped += 1
            continue
        cited_text = _norm(" ".join(by_id[i] for i in valid_ids))
        quote_ok = (not f.quote) or _norm(f.quote) in cited_text
        all_ids_valid = len(valid_ids) == len(f.line_ids)
        f.line_ids = valid_ids
        f.verified = quote_ok and all_ids_valid
        if f.risk not in RISK_ORDER:
            f.risk = "medium"
        kept.append(f)
    kept.sort(key=lambda f: (RISK_ORDER[f.risk], f.line_ids[0]))
    stats = {
        "proposed": len(findings),
        "kept": len(kept),
        "dropped_no_valid_citation": dropped,
        "verified": sum(1 for f in kept if f.verified),
    }
    return kept, stats
