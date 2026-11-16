"""Validate data/labeled.csv: schema, labels, and leftover personal details.

Exit code 1 if anything is wrong, so CI can block an unsafe commit.
"""
import csv
import re
import sys
from pathlib import Path

PATH = Path(__file__).resolve().parent.parent / "data" / "labeled.csv"
COLUMNS = ["id", "text", "label", "red_flags", "how_verified", "source"]
LABELS = {"scam", "legit", "unclear", ""}  # blank allowed while still labeling

PII = {
    "email address": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone number": re.compile(r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?!\d)"),
    "web link": re.compile(r"https?://|www\.", re.I),
}


def check(path: Path = PATH) -> list[str]:
    problems: list[str] = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != COLUMNS:
            return [f"columns must be exactly {COLUMNS}, found {reader.fieldnames}"]
        seen: set[str] = set()
        for n, row in enumerate(reader, start=2):
            rid = row["id"].strip()
            if not rid or rid in seen:
                problems.append(f"row {n}: missing or duplicate id '{rid}'")
            seen.add(rid)
            if row["label"].strip() not in LABELS:
                problems.append(f"row {n} ({rid}): label must be scam, legit or unclear")
            if len(row["text"].strip()) < 20:
                problems.append(f"row {n} ({rid}): text is empty or too short")
            if row["label"].strip() in {"scam", "legit"} and not row["how_verified"].strip():
                problems.append(f"row {n} ({rid}): scam/legit needs a how_verified note")
            for field in ("text", "red_flags", "how_verified"):
                for name, rx in PII.items():
                    if rx.search(row[field]):
                        problems.append(f"row {n} ({rid}): possible {name} in {field}; redact it")
    return problems


if __name__ == "__main__":
    issues = check()
    for p in issues:
        print("PROBLEM:", p)
    print("OK" if not issues else f"{len(issues)} problem(s) found")
    sys.exit(1 if issues else 0)
