"""Measure AXFR duration, wire size and records/sec after loading N records.

For Bindizr, wait for propagation and transfer from the secondary.
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datasets.gen_dataset import generate  # noqa: E402
from lib import dig  # noqa: E402


# A statically-configured zone (Knot, CoreDNS) still answers AXFR with its apex
# — SOA, NS, glue, closing SOA — once its records are gone, so a dropped zone
# floors at the apex rather than at zero.
APEX_LINES = 10


async def _axfr_count(zone, host, port, timeout=300):
    """Read the current record count through an AXFR."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, dig.axfr, zone, host, port, timeout)


async def run(adapter, config, context) -> list:
    """Measure full zone-transfer performance at the configured zone sizes."""
    zone = context["zone"]
    xe = adapter.xfr_endpoint()
    rows = []

    for size in config["sizes"]:
        await adapter.delete_zone(zone)

        # Wait for the delete to reach the XFR endpoint before recreating: the
        # secondary drops the zone via the catalog seconds later, and the new
        # low serial would otherwise collide with the stale copy it still holds.
        drop_deadline = time.monotonic() + 30
        dropped = False

        while time.monotonic() < drop_deadline:
            _, count, _ = await _axfr_count(zone, xe.host, xe.port)
            if count <= APEX_LINES:
                dropped = True
                break
            await asyncio.sleep(1.0)

        # Recreating over a zone the secondary still serves measures the stale
        # copy, which a descending BENCH_SIZES would report as the new size.
        if not dropped:
            print(f'  [FAIL] b04: secondary still serves the old zone '
                  f'for {context["label"]}')
            rows.append({
                "system": context["label"],
                "size": size,
                "status": "FAILED",
                "error": "delete timeout: secondary still serves the old zone",
            })

            continue

        await adapter.create_zone(zone)
        await adapter.import_records(zone, generate(size, config["seed"], zone))

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
                  f'for {context["label"]}')
            rows.append({
                "system": context["label"],
                "size": size,
                "status": "FAILED",
                "error": "propagation timeout: zone not fully transferable",
            })

            continue

        secs, count, nbytes = await _axfr_count(zone, xe.host, xe.port)

        rows.append({
            "system": context["label"],
            "size": size,
            "transfer_secs": round(secs, 3),
            "records": count,
            "transfer_bytes": nbytes,
            "records_per_sec": round(count / secs, 1) if secs else 0,
        })

    return rows
