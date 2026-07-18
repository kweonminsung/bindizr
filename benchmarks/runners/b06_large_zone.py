"""Benchmark 6 — Large Zone Performance (Bindizr).

Across zone sizes, measures the lifecycle operations on a single large zone:
create, populate (bulk), export (AXFR), and delete, plus peak memory/CPU.
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datasets.gen_dataset import generate  # noqa: E402
from lib import dnsutil  # noqa: E402
from lib.resources import ResourceSampler  # noqa: E402


async def run(adapter, cfg, ctx) -> list:
    zone = ctx["zone"]
    xe = adapter.xfr_endpoint()
    loop = asyncio.get_event_loop()
    rows = []
    for size in cfg["sizes"]:
        ids = [i for i in (adapter.compose.container_id(s)
                           for s in adapter.resource_services) if i]
        sampler = ResourceSampler(ids, cfg["resources"]["sample_interval_secs"])
        sampler.start()

        await adapter.delete_zone(zone)
        t = time.monotonic()
        await adapter.create_zone(zone)
        create_secs = time.monotonic() - t

        recs = generate(size, cfg["seed"], zone)
        t = time.monotonic()
        await adapter.bulk_import(zone, recs)
        populate_secs = time.monotonic() - t

        # The BIND9 secondary pulls asynchronously — bulk_import returns after
        # commit+NOTIFY, not after the transfer lands — so poll until the
        # transferable count covers the set and stops growing before timing the
        # export (AXFR).
        deadline = time.monotonic() + 120
        prev = -1
        while time.monotonic() < deadline:
            _, count, _ = await loop.run_in_executor(
                None, dnsutil.axfr, zone, xe.host, xe.port, 300)
            if count >= size and count == prev:
                break
            prev = count
            await asyncio.sleep(1.0)

        export_secs, _, export_bytes = await loop.run_in_executor(
            None, dnsutil.axfr, zone, xe.host, xe.port, 300)

        t = time.monotonic()
        await adapter.delete_zone(zone)
        delete_secs = time.monotonic() - t

        res = sampler.stop()
        rows.append({
            "system": ctx["label"],
            "size": size,
            "create_secs": round(create_secs, 3),
            "populate_secs": round(populate_secs, 3),
            "export_secs": round(export_secs, 3),
            "export_mb": round(export_bytes / 1024**2, 2),
            "delete_secs": round(delete_secs, 3),
            "peak_mem_mb": res.get("peak_mem_mb", 0),
            "peak_cpu_pct": res.get("peak_cpu_pct", 0),
        })
    return rows
