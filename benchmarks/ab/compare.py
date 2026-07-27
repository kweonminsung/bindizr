#!/usr/bin/env python3
"""Compare two benchmark raw result files (A vs B) metric by metric.

Usage: compare.py <A.json> <B.json> [--label-a NAME] [--label-b NAME]

Groups rows by their dimension fields (system/backend/size/changes), averages
each numeric metric across repeats, and prints a table with the B-vs-A delta.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib.report import DIMENSION_FIELDS  # noqa: E402

# Metrics where a smaller value is better (delta sign is flipped for "better?").
LOWER_IS_BETTER = ("p50", "p95", "p99", "_ms", "secs", "latency", "error_rate",
                   "bytes", "mem", "cpu")


def _group(path: Path) -> dict[tuple, list[dict]]:
    payload = json.loads(path.read_text())
    groups: dict[tuple, list[dict]] = {}
    for r in payload["results"]:
        key = tuple(str(r.get(f)) for f in DIMENSION_FIELDS)
        groups.setdefault(key, []).append(r)
    return groups


def _mean(rows: list[dict], k: str):
    vals = [r[k] for r in rows
            if isinstance(r.get(k), (int, float)) and not isinstance(r.get(k), bool)]
    return statistics.fmean(vals) if vals else None


def _lower_better(metric: str) -> bool:
    return any(tok in metric for tok in LOWER_IS_BETTER)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--label-a", default="A")
    ap.add_argument("--label-b", default="B")
    args = ap.parse_args()

    ga, gb = _group(Path(args.a)), _group(Path(args.b))

    for key in ga:
        if key not in gb:
            continue
        rows_a, rows_b = ga[key], gb[key]
        dims = [f"{f}={v}" for f, v in zip(DIMENSION_FIELDS, key) if v != "None"]
        print(f"\n### {' | '.join(dims)}   "
              f"(runs: {args.label_a}={len(rows_a)}, {args.label_b}={len(rows_b)})")
        print(f"{'metric':<20} {args.label_a:>14} {args.label_b:>14} {'delta':>12}  better?")
        print("-" * 74)
        for k in rows_a[0]:
            if k in DIMENSION_FIELDS:
                continue
            ma, mb = _mean(rows_a, k), _mean(rows_b, k)
            if ma is None or mb is None:
                continue
            if ma == 0:
                delta = "n/a" if mb == 0 else "+inf"
                better = ""
            else:
                pct = (mb - ma) / ma * 100.0
                delta = f"{pct:+.1f}%"
                improved = (pct < 0) if _lower_better(k) else (pct > 0)
                better = "yes" if abs(pct) >= 1 and improved else ("no" if abs(pct) >= 1 else "~")
            print(f"{k:<20} {ma:>14.3f} {mb:>14.3f} {delta:>12}  {better}")


if __name__ == "__main__":
    main()
