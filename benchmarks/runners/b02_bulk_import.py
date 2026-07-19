"""Benchmark 2 — Bulk Import.

Imports N records (per configured size) into a fresh zone and measures wall-clock
import time, records/sec, and peak memory. Uses each adapter's `bulk_import`
(batch APIs where available, else sequential concurrent creates).

Adapters that expose a second bulk-load path (Bindizr's BIND zone-file import)
also report it as an extra `<label> (zone import)` row, so the two Bindizr
bulk-load APIs can be compared side by side.

Emits one row per (system, size[, path]).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datasets.gen_dataset import generate  # noqa: E402
from lib.resources import ResourceSampler  # noqa: E402


async def _measure(adapter, zone, size, label, load, errors) -> dict:
    """Load records into a fresh zone via `load()` and time it, sampling the
    server's resource usage. `errors()` reads the adapter's post-load error count."""
    await adapter.delete_zone(zone)
    await adapter.create_zone(zone)

    ids = [adapter.compose.container_id(s) for s in adapter.resource_services]
    sampler = ResourceSampler([i for i in ids if i],
                              adapter.cfg["resources"]["sample_interval_secs"])
    sampler.start()
    t0 = time.monotonic()
    await load()
    elapsed = time.monotonic() - t0
    res = sampler.stop()

    return {
        "system": label,
        "size": size,
        "import_secs": round(elapsed, 3),
        "records_per_sec": round(size / elapsed, 1) if elapsed else 0,
        "import_errors": errors(),
        "peak_mem_mb": res.get("peak_mem_mb", 0),
        "avg_cpu_pct": res.get("avg_cpu_pct", 0),
    }


async def run(adapter, cfg, ctx) -> list:
    zone = ctx["zone"]
    rows = []
    for size in cfg["sizes"]:
        records = generate(size, cfg["seed"], zone)

        rows.append(await _measure(
            adapter, zone, size, ctx["label"],
            lambda: adapter.bulk_import(zone, records),
            lambda: getattr(adapter, "bulk_errors", 0)))

        # Bindizr also supports importing a BIND zone file; report it alongside.
        if getattr(adapter, "supports_zone_import", False):
            rows.append(await _measure(
                adapter, zone, size, f'{ctx["label"]} (zone import)',
                lambda: adapter.import_zone_file(zone, records),
                lambda: getattr(adapter, "import_errors", 0)))
    return rows
