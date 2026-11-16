"""Turn findings into a risk level with an honest confidence note.

Points: high=5, medium=2, low=1, counted once per rule. Level:
  high   if any high-severity finding, or total points >= 8
  medium if total points >= 3
  low    otherwise
This is a risk ESTIMATE, never a verdict. Thresholds are simple on purpose so they can be explained.
"""
from __future__ import annotations

from .core import Finding

POINTS = {"high": 5, "medium": 2, "low": 1}


def score(findings: list[Finding], model_prob: float | None = None) -> dict:
    per_rule: dict[str, int] = {}
    for f in findings:
        key = f.rule_id or f.title
        per_rule[key] = max(per_rule.get(key, 0), POINTS.get(f.risk, 2))
    points = sum(per_rule.values())
    if model_prob is not None:
        points += 2 if model_prob >= 0.8 else 1 if model_prob >= 0.5 else 0
    has_high = any(f.risk == "high" for f in findings)
    level = "high" if has_high or points >= 8 else "medium" if points >= 3 else "low"
    n_signals = len({f.rule_id or f.title for f in findings})
    if level == "low":
        confidence = ("Few or no warning signs were found. That does not prove it is safe: "
                      "check the company independently.")
    elif n_signals >= 3:
        confidence = "Several independent warning signs agree. Treat this with strong caution."
    else:
        confidence = "Some warning signs were found, but not many. Verify before sharing anything."
    return {"level": level, "points": points, "confidence": confidence,
            "disclaimer": "This is a risk estimate, not a verdict. Real employers can trip some checks."}
