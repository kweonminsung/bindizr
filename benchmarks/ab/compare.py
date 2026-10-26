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
    """Group a raw result file by benchmark measurement dimensions."""
    payload = json.loads(path.read_text())
    groups: dict[tuple, list[dict]] = {}
    for row in payload["results"]:
        key = tuple(str(row.get(field)) for field in DIMENSION_FIELDS)
        groups.setdefault(key, []).append(row)
    return groups


def _mean(rows: list[dict], metric: str):
    """Average the available numeric values of one metric."""
    values = [row[metric] for row in rows
            if isinstance(row.get(metric), (int, float)) and not isinstance(row.get(metric), bool)]
    return statistics.fmean(values) if values else None


def _is_lower_better(metric: str) -> bool:
    """Check whether a smaller metric value indicates improvement."""
    return any(token in metric for token in LOWER_IS_BETTER)


def main() -> None:
    """Print a metric-by-metric comparison of two benchmark result files."""
    parser = argparse.ArgumentParser()
    parser.add_argument("a")
    parser.add_argument("b")
    parser.add_argument("--label-a", default="A")
    parser.add_argument("--label-b", default="B")
    args = parser.parse_args()

    groups_a, groups_b = _group(Path(args.a)), _group(Path(args.b))

    for key in groups_a:
        if key not in groups_b:
            continue

        rows_a, rows_b = groups_a[key], groups_b[key]
        dimensions = [f"{field}={value}" for field, value in zip(DIMENSION_FIELDS, key) if value != "None"]
        print(f"\n### {' | '.join(dimensions)}   "
              f"(runs: {args.label_a}={len(rows_a)}, {args.label_b}={len(rows_b)})")
        print(f"{'metric':<20} {args.label_a:>14} {args.label_b:>14} {'delta':>12}  better?")
        print("-" * 74)

        for metric in rows_a[0]:
            if metric in DIMENSION_FIELDS:
                continue

            mean_a, mean_b = _mean(rows_a, metric), _mean(rows_b, metric)

            if mean_a is None or mean_b is None:
                continue

            if mean_a == 0:
                delta = "n/a" if mean_b == 0 else "+inf"
                better = ""
            else:
                pct = (mean_b - mean_a) / mean_a * 100.0
                delta = f"{pct:+.1f}%"
                improved = (pct < 0) if _is_lower_better(metric) else (pct > 0)
                better = "yes" if abs(pct) >= 1 and improved else ("no" if abs(pct) >= 1 else "~")

            print(f"{metric:<20} {mean_a:>14.3f} {mean_b:>14.3f} {delta:>12}  {better}")


if __name__ == "__main__":
    main()
