"""Assign each labeled row to train or test, once, with a fixed seed (70/30).

Writes data/split.csv. Run this AFTER labeling and do not rerun after looking at results.
Rows are stratified by label so both splits contain scam, legit and unclear examples.
"""
import csv
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEED = 42


def make_split(rows, seed=SEED, test_fraction=0.3):
    rng = random.Random(seed)
    by_label: dict[str, list[str]] = {}
    for r in rows:
        by_label.setdefault(r["label"], []).append(r["id"])
    out = {}
    for ids in by_label.values():
        ids = sorted(ids)
        rng.shuffle(ids)
        n_test = max(1, round(len(ids) * test_fraction)) if len(ids) > 1 else 0
        for i, rid in enumerate(ids):
            out[rid] = "test" if i < n_test else "train"
    return out


if __name__ == "__main__":
    rows = [r for r in csv.DictReader(open(ROOT / "data" / "labeled.csv", encoding="utf-8")) if r["label"]]
    if not rows:
        sys.exit("No labeled rows yet. Fill in the label column first.")
    split = make_split(rows)
    with open(ROOT / "data" / "split.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "split"])
        w.writerows(sorted(split.items()))
    print({k: sum(1 for v in split.values() if v == k) for k in ("train", "test")})
