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
        # Wait for the delete to reach the XFR endpoint before recreating: the
        # secondary drops the zone via the catalog seconds later, and the new
        # low serial would otherwise collide with the stale copy it still holds.
        drop_deadline = time.monotonic() + 30
        dropped = False
        while time.monotonic() < drop_deadline:
            _, count, _ = await loop.run_in_executor(
                None, dnsutil.axfr, zone, xe.host, xe.port, 300)
            if count == 0:
                dropped = True
                break
            await asyncio.sleep(1.0)

        # Recreating over a zone the secondary still serves measures the stale
        # copy, which a descending BENCH_SIZES would report as the new size.
        if not dropped:
            print(f'  [FAIL] b06: secondary still serves the old zone '
                  f'for size {size}')
            sampler.stop()
            rows.append({
                "system": ctx["label"],
                "size": size,
                "status": "FAILED",
                "error": "delete timeout: secondary still serves the old zone",
            })
            continue

        t = time.monotonic()
        await adapter.create_zone(zone)
        create_secs = time.monotonic() - t

        recs = generate(size, cfg["seed"], zone)
        t = time.monotonic()
        await adapter.bulk_import(zone, recs)
        populate_secs = time.monotonic() - t

        # The BIND9 secondary pulls asynchronously (bulk_import returns after
        # commit+NOTIFY, not after the transfer lands), so poll until the count
        # covers the set before timing the export; scale the bound with size.
        deadline = time.monotonic() + max(120, size / 500)
        prev = -1
        propagated = False
        while time.monotonic() < deadline:
            _, count, _ = await loop.run_in_executor(
                None, dnsutil.axfr, zone, xe.host, xe.port, 300)
            if count >= size and count == prev:
                propagated = True
                break
            prev = count
            await asyncio.sleep(1.0)

        # A timed-out poll means the secondary never received the full zone;
        # exporting anyway would time a stale transfer and label it this size.
        if not propagated:
            print(f'  [FAIL] b06: zone not fully transferable within deadline '
                  f'for size {size}')
            sampler.stop()
            rows.append({
                "system": ctx["label"],
                "size": size,
                "status": "FAILED",
                "error": "propagation timeout: zone not fully transferable",
            })
            continue

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
