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
        await adapter.create_zone(zone)
        await adapter.bulk_import(zone, generate(size, cfg["seed"], zone))

        # Wait for the zone to be fully transferable (matters for Bindizr's
        # secondary, which pulls asynchronously). Poll until the AXFR record
        # count stops growing and covers the imported set. Scale the bound with
        # size so a 100k/1M transfer isn't cut off at a fixed 120s.
        deadline = time.monotonic() + max(120, size / 500)
        prev = -1
        while time.monotonic() < deadline:
            _, count, _ = await _axfr_count(zone, xe.host, xe.port)
            if count >= size and count == prev:
                break
            prev = count
            await asyncio.sleep(1.0)

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
