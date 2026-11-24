"""Measure AXFR duration, wire size and records/sec after loading N records.

For Bindizr, wait for propagation and transfer from the secondary.
"""
from __future__ import annotations

import asyncio
import time

from datasets.gen_dataset import generate
from lib import dig


# A statically-configured zone (Knot, CoreDNS) still answers AXFR with its apex
# — SOA, NS, glue, closing SOA — once its records are gone, so a dropped zone
# floors at the apex rather than at zero.
APEX_LINES = 10


async def run(adapter, config, context) -> list:
    """Measure full zone-transfer performance at the configured zone sizes."""
    zone_name = context["zone"]
    endpoint = adapter.xfr_endpoint()
    rows = []

    for size in config["sizes"]:
        await adapter.delete_zone(zone_name)

        # Wait for the delete to reach the XFR endpoint before recreating: the
        # secondary drops the zone via the catalog seconds later, and the new
        # low serial would otherwise collide with the stale copy it still holds.
        drop_deadline = time.monotonic() + 30
        dropped = False

        while time.monotonic() < drop_deadline:
            if await dig.zone_is_cleared(zone_name, endpoint.host, endpoint.port, APEX_LINES):
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

        await adapter.create_zone(zone_name)
        await adapter.import_records(zone_name, generate(size, config["seed"], zone_name))
        if adapter.bulk_errors:
            raise RuntimeError(f"preparing the AXFR zone failed for {adapter.bulk_errors} records")

        # Wait until the zone is fully transferable — Bindizr's secondary pulls
        # asynchronously. Poll until the AXFR count stops growing and covers the
        # set; scale the bound with size so a large transfer isn't cut off early.
        deadline = time.monotonic() + max(120, size / 500)
        prev = -1
        propagated = False

        while time.monotonic() < deadline:
            count = await dig.count_axfr_records(zone_name, endpoint.host, endpoint.port)
            if count is not None and count >= size and count == prev:
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

        try:
            transfer = await dig.axfr(zone_name, endpoint.host, endpoint.port)
        except dig.TransferError as error:
            rows.append({
                "system": context["label"],
                "size": size,
                "status": "FAILED",
                "error": str(error),
            })
            continue
        seconds = transfer.seconds

        rows.append({
            "system": context["label"],
            "size": size,
            "transfer_secs": round(seconds, 3),
            "records": transfer.records,
            "transfer_bytes": transfer.output_bytes,
            "records_per_sec": round(transfer.records / seconds, 1) if seconds else 0,
        })

    return rows
