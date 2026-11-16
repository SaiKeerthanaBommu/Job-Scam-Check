from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .pipeline import analyze


def render(rep) -> str:
    r = rep.result
    out = [f"Risk estimate: {r['level'].upper()} ({r['points']} points)", r["confidence"], r["disclaimer"], ""]
    for f in rep.findings:
        mark = "verified" if f.verified else "UNVERIFIED"
        out.append(f"[{f.risk.upper()}] {f.title} (line {', '.join(map(str, f.line_ids))}, {mark})")
        out.append(f"    quote: {f.quote}")
        out.append(f"    why:   {f.explanation}")
    if rep.advice:
        out += ["", "What to do:"] + [f"  - {a}" for a in rep.advice]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="checker", description="Check a job or interview message for scam signs.")
    ap.add_argument("file", nargs="?", help="text file with the message (default: read stdin)")
    ap.add_argument("--sender", default="", help="sender email address, e.g. jane@gmail.com")
    ap.add_argument("--lookup", action="store_true", help="look up domain age (sends only the domain name)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--serve", action="store_true", help="start the local web page")
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args(argv)
    if a.serve:
        from .web import serve
        serve(a.port)
        return 0
    text = Path(a.file).read_text(encoding="utf-8", errors="replace") if a.file else sys.stdin.read()
    rep = analyze(text, sender=a.sender, lookup=a.lookup)
    print(json.dumps(rep.to_dict(), indent=2) if a.json else render(rep))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
