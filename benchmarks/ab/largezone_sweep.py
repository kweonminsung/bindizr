#!/usr/bin/env python3
"""Measure single-record create TPS as the target zone grows.

The per-write conflict lookup scans the owner's existing records; without an
index on records(zone_id, name) that is O(zone size) per write, so create TPS
should fall as the prepopulated zone grows. With the index it should stay flat.

Runs the Bindizr adapter directly (notify off, so we isolate the DB write path),
prepopulating each size via the bulk API and then timing single creates.
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from adapters import registry  # noqa: E402
from datasets.gen_dataset import generate  # noqa: E402
from lib import loadgen  # noqa: E402

ZONE = "bench.example."
SIZES = [1_000, 20_000, 50_000, 100_000]
CONCURRENCY = 16
DURATION = 6.0
WARMUP = 1.5


async def measure(adapter, prepop: int) -> dict:
    await adapter.delete_zone(ZONE)
    await adapter.create_zone(ZONE)
    pool = generate(prepop, 1337)
    for i, rec in enumerate(pool):
        rec["name"] = f"pool{i:07d}"
    await adapter.bulk_import(ZONE, pool)

    create_recs = generate(300_000, 4242)

    async def step(seq: int) -> bool:
        rec = dict(create_recs[seq % len(create_recs)])
        rec["name"] = f"crt{seq:08d}"
        await adapter.create_record(ZONE, rec)
        return True

    rec = await loadgen.run_closed_loop(step, CONCURRENCY, DURATION, WARMUP)
    s = rec.summary()
    return {"prepop": prepop, "create_tps": s["tps"],
            "p95_ms": s["p95_ms"], "p99_ms": s["p99_ms"], "errors": rec.errors}


async def main() -> None:
    label = sys.argv[1] if len(sys.argv) > 1 else "build"
    adapter = registry.build("bindizr", {"resources": {"sample_interval_secs": 1}},
                             f"bench-lz-{label}", notify_after_update=False)
    rows = []
    try:
        await adapter.setup()
        for size in SIZES:
            row = await measure(adapter, size)
            rows.append(row)
            print(f"[{label}] prepop={size:>7}  create_tps={row['create_tps']:>8.1f}  "
                  f"p95={row['p95_ms']:>7.1f}ms  p99={row['p99_ms']:>7.1f}ms  "
                  f"errors={row['errors']}", flush=True)
    finally:
        await adapter.teardown()

    base = rows[0]["create_tps"] or 1
    print(f"\n=== {label}: create TPS vs zone size ===")
    print(f"{'prepop':>8} {'create_tps':>12} {'vs 1k':>8} {'p95_ms':>10}")
    for r in rows:
        print(f"{r['prepop']:>8} {r['create_tps']:>12.1f} "
              f"{r['create_tps'] / base * 100:>7.0f}% {r['p95_ms']:>10.1f}")


if __name__ == "__main__":
    asyncio.run(main())
