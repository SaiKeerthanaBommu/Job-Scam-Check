"""Held-out evaluation on YOUR labeled data. Run: python -m eval.run_eval

Reports scam recall, false-alarm rate on legit, and citation validity on the TEST split only.
Sample data is not a benchmark: numbers mean something only with your own real, verified labels.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from checker import analyze  # noqa: E402


def load(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def evaluate(rows: list[dict], flag_levels=("medium", "high")) -> dict:
    tp = fn = fp = tn = 0
    kept = verified = 0
    for r in rows:
        if r["label"] not in ("scam", "legit"):
            continue
        rep = analyze(r["text"])
        flagged = rep.result["level"] in flag_levels
        kept += rep.stats["kept"]
        verified += rep.stats["verified"]
        if r["label"] == "scam":
            tp += flagged
            fn += not flagged
        else:
            fp += flagged
            tn += not flagged
    ns, nl = tp + fn, fp + tn
    out = {"n_scam": ns, "n_legit": nl,
           "scam_recall": round(tp / ns, 3) if ns else None,
           "false_alarm_rate": round(fp / nl, 3) if nl else None,
           "citation_validity": round(verified / kept, 3) if kept else None,
           "warnings": []}
    if ns < 20 or nl < 20:
        out["warnings"].append("Fewer than 20 examples in a class: these numbers are not reliable.")
    return out


def main() -> int:
    labeled, split = ROOT / "data" / "labeled.csv", ROOT / "data" / "split.csv"
    if not split.exists():
        print("No data/split.csv yet. Label your data, then run: python scripts/make_split.py")
        return 1
    test_ids = {r["id"] for r in load(split) if r["split"] == "test"}
    rows = [r for r in load(labeled) if r["id"] in test_ids]
    res = evaluate(rows)
    (ROOT / "eval" / "results").mkdir(exist_ok=True)
    (ROOT / "eval" / "results" / "latest.json").write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
