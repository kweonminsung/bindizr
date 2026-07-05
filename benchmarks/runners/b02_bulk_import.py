"""Benchmark 2 — Bulk Import.

Imports N records (per configured size) into a fresh zone and measures wall-clock
import time, records/sec, and peak memory. Uses each adapter's `bulk_import`
(batch APIs where available, else sequential concurrent creates).

Emits one row per (system, size).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datasets.gen_dataset import generate  # noqa: E402
from lib.resources import ResourceSampler  # noqa: E402


async def run(adapter, cfg, ctx) -> list:
    zone = ctx["zone"]
    rows = []
    for size in cfg["sizes"]:
        await adapter.delete_zone(zone)
        await adapter.create_zone(zone)
        records = generate(size, cfg["seed"], zone)

        ids = [adapter.compose.container_id(s) for s in adapter.resource_services]
        sampler = ResourceSampler([i for i in ids if i],
                                  cfg["resources"]["sample_interval_secs"])
        sampler.start()
        t0 = time.monotonic()
        await adapter.bulk_import(zone, records)
        elapsed = time.monotonic() - t0
        res = sampler.stop()

        row = {
            "system": ctx["label"],
            "size": size,
            "import_secs": round(elapsed, 3),
            "records_per_sec": round(size / elapsed, 1) if elapsed else 0,
            "import_errors": getattr(adapter, "bulk_errors", 0),
            "peak_mem_mb": res.get("peak_mem_mb", 0),
            "avg_cpu_pct": res.get("avg_cpu_pct", 0),
        }
        rows.append(row)
    return rows
