"""Benchmark 4 — AXFR Performance.

Loads an N-record zone, then performs a full zone transfer (AXFR) from the
system's XFR endpoint, measuring transfer time, wire size, and records/sec.

For Bindizr the transfer is pulled from the BIND9 secondary (which received the
zone from Bindizr's XFR server), so we first wait for propagation to complete.
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datasets.gen_dataset import generate  # noqa: E402
from lib import dnsutil  # noqa: E402


async def _axfr_count(zone, host, port, timeout=300):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, dnsutil.axfr, zone, host, port, timeout)


async def run(adapter, cfg, ctx) -> list:
    zone = ctx["zone"]
    xe = adapter.xfr_endpoint()
    rows = []
    for size in cfg["sizes"]:
        await adapter.delete_zone(zone)
        # Wait for the delete to reach the XFR endpoint before recreating: for
        # Bindizr the BIND9 secondary drops the zone via the catalog ~5s after
        # the API delete, and recreating sooner lets the new low serial collide
        # with the stale copy. A no-op for systems that delete synchronously.
        drop_deadline = time.monotonic() + 30
        dropped = False
        while time.monotonic() < drop_deadline:
            _, count, _ = await _axfr_count(zone, xe.host, xe.port)
            if count == 0:
                dropped = True
                break
            await asyncio.sleep(1.0)

        # Recreating over a zone the secondary still serves measures the stale
        # copy, which a descending BENCH_SIZES would report as the new size.
        if not dropped:
            print(f'  [FAIL] b04: secondary still serves the old zone '
                  f'for {ctx["label"]}')
            rows.append({
                "system": ctx["label"],
                "size": size,
                "status": "FAILED",
                "error": "delete timeout: secondary still serves the old zone",
            })
            continue

        await adapter.create_zone(zone)
        await adapter.bulk_import(zone, generate(size, cfg["seed"], zone))

        # Wait until the zone is fully transferable — Bindizr's secondary pulls
        # asynchronously. Poll until the AXFR count stops growing and covers the
        # set; scale the bound with size so a large transfer isn't cut off early.
        deadline = time.monotonic() + max(120, size / 500)
        prev = -1
        propagated = False
        while time.monotonic() < deadline:
            _, count, _ = await _axfr_count(zone, xe.host, xe.port)
            if count >= size and count == prev:
                propagated = True
                break
            prev = count
            await asyncio.sleep(1.0)

        # A timed-out poll means the secondary never fully received the zone (or
        # AXFR is refused); record a failure instead of a misleading partial row.
        if not propagated:
            print(f'  [FAIL] b04: zone not fully transferable within deadline '
                  f'for {ctx["label"]}')
            rows.append({
                "system": ctx["label"],
                "size": size,
                "status": "FAILED",
                "error": "propagation timeout: zone not fully transferable",
            })
            continue

        # Clean measured transfer.
        secs, count, nbytes = await _axfr_count(zone, xe.host, xe.port)
        rows.append({
            "system": ctx["label"],
            "size": size,
            "transfer_secs": round(secs, 3),
            "records": count,
            "transfer_bytes": nbytes,
            "records_per_sec": round(count / secs, 1) if secs else 0,
        })
    return rows
