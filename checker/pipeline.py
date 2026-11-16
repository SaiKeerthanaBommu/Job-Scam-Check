from __future__ import annotations

from dataclasses import dataclass, field

from . import rules, signals
from .core import Finding, split_lines, verify
from .scoring import score


@dataclass
class Report:
    lines: list[tuple[int, str]]
    findings: list[Finding]
    stats: dict
    result: dict
    advice: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"result": self.result, "stats": self.stats, "advice": self.advice,
                "findings": [f.to_dict() for f in self.findings],
                "lines": [{"id": i, "text": t} for i, t in self.lines]}


def analyze(text: str, sender: str = "", lookup: bool = False, model=None, fetcher=None, now=None) -> Report:
    """Run text rules and verification signals, verify every citation, and score the result."""
    full = f"From: {sender.strip()}\n{text}" if sender.strip() else text
    lines = split_lines(full)
    raw = rules.find(lines)
    sig, info = signals.find(lines, lookup=lookup, fetcher=fetcher, now=now)
    raw += sig
    findings, stats = verify(raw, lines)
    stats.update(info)
    prob = None
    if model is not None:
        from .classifier import predict_proba
        prob = predict_proba(model, full)
        stats["model_probability_scam"] = round(prob, 3)
    result = score(findings, prob)
    seen, advice = set(), []
    for f in findings:
        if f.advice and f.advice not in seen:
            seen.add(f.advice)
            advice.append(f.advice)
    return Report(lines=lines, findings=findings, stats=stats, result=result, advice=advice)
