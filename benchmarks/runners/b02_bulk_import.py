"""Measure bulk-import time, records/sec and peak memory per system, size and path.

Use each adapter's batch API or fixed worker pool; report Bindizr zone-file import separately.
"""
from __future__ import annotations

import time

from datasets.gen_dataset import generate
from lib.resources import load_sampler

# Sampled around the measured phase below, not by the orchestrator.
SELF_SAMPLES = True


async def _measure(adapter, zone_name, size, label, load, errors) -> dict:
    """Load records into a fresh zone via `load()` and time it, sampling the
    server's resource usage. `errors()` reads the adapter's post-load error count."""
    await adapter.delete_zone(zone_name)
    await adapter.create_zone(zone_name)

    sampler = load_sampler(adapter, adapter.config)
    with sampler:
        started = time.monotonic()

        await load()

        elapsed = time.monotonic() - started
    resource_usage = sampler.summary()

    # Adapters count failures instead of raising, so rate off what landed —
    # a fast total failure would otherwise top the chart.
    failed = errors()
    imported = max(size - failed, 0)

    return {
        "system": label,
        "size": size,
        "import_secs": round(elapsed, 3),
        "records_per_sec": round(imported / elapsed, 1) if elapsed else 0,
        "import_errors": failed,
        "peak_mem_mb": resource_usage.get("peak_mem_mb"),
        "avg_cpu_pct": resource_usage.get("avg_cpu_pct"),
    }


async def run(adapter, config, context) -> list:
    """Measure bulk import performance at the configured record counts."""
    zone_name = context["zone"]
    rows = []

    for size in config["sizes"]:
        records = generate(size, config["seed"], zone_name)

        rows.append(await _measure(
            adapter, zone_name, size, context["label"],
            lambda: adapter.import_records(zone_name, records),
            lambda: getattr(adapter, "bulk_errors", 0)))

        # Bindizr also supports importing a BIND zone file; report it alongside.
        if getattr(adapter, "supports_zone_import", False):
            rows.append(await _measure(
                adapter, zone_name, size, f'{context["label"]} (zone import)',
                lambda: adapter.import_zone_file(zone_name, records),
                lambda: getattr(adapter, "import_errors", 0)))

    return rows
