"""Measure IXFR from a baseline serial after each change batch has propagated.

Report transfer size so an AXFR fallback remains visible.
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datasets.gen_dataset import generate  # noqa: E402
from lib import dig  # noqa: E402

# Fallbacks used only when the config lacks the ixfr_* keys; a normal run
# overrides both from settings.yaml (ixfr_change_sizes / ixfr_baseline).
CHANGE_SIZES = [1, 10, 100, 1000, 10000]
BASELINE = 1000


def _query_serial(zone, host, port):
    """Query a zone's SOA serial from the transfer endpoint."""
    ok, _, out = dig.query(zone, "SOA", host, port)

    if ok and len(out.split()) >= 3:
        try:
            return int(out.split()[2])
        except ValueError:
            return None

    return None


async def run(adapter, config, context) -> list:
    """Measure incremental transfers after each configured change batch propagates."""
    zone = context["zone"]
    xe = adapter.xfr_endpoint()
    loop = asyncio.get_event_loop()
    change_sizes = config.get("ixfr_change_sizes", CHANGE_SIZES)
    baseline = config.get("ixfr_baseline", BASELINE)

    await adapter.delete_zone(zone)
    await adapter.create_zone(zone)
    await adapter.import_records(zone, generate(baseline, config["seed"], zone))

    # Wait for the baseline to reach the secondary before reading serials:
    # reading a pre-baseline serial would request IXFR from a serial with no
    # delta history, a spurious full-AXFR outlier.
    deadline = time.monotonic() + max(60, baseline / 500)
    prev = -1
    propagated = False

    while time.monotonic() < deadline:
        _, count, _ = await loop.run_in_executor(
            None, dig.axfr, zone, xe.host, xe.port, 300)
        if count >= baseline and count == prev:
            propagated = True
            break
        prev = count
        await asyncio.sleep(1.0)

    if not propagated:
        print(f'  [FAIL] b05: baseline not fully transferable within deadline '
              f'for {context["label"]}')
        return [{
            "system": context["label"],
            "changes": n,
            "status": "FAILED",
            "error": "baseline propagation timeout: zone not fully transferable",
        } for n in change_sizes]

    rows = []
    change_pool = generate(sum(change_sizes) + baseline, config["seed"] + 50, zone)
    ci = 0

    for n in change_sizes:
        # Retry a transient SOA miss rather than defaulting: a made-up base
        # serial has no delta history behind it and forces a full AXFR.
        base_serial = None

        for _ in range(10):
            base_serial = await loop.run_in_executor(None, _query_serial, zone, xe.host, xe.port)
            if base_serial is not None:
                break
            await asyncio.sleep(0.5)

        if base_serial is None:
            print(f"  [SKIP] b05: could not read base serial for {n}-change IXFR")
            continue

        batch = []

        for _ in range(n):
            record = dict(change_pool[ci % len(change_pool)])
            record["name"] = f"ixfr{ci:07d}"
            batch.append(record)
            ci += 1

        await adapter.import_records(zone, batch)

        # Hold until the serial and the record count both stop moving: an
        # unchanged serial answers IXFR with a tiny "up-to-date" SOA, and the
        # first bump may cover only one of a chunked batch's transactions.
        deadline = time.monotonic() + 120
        propagated = False
        prev = None

        while time.monotonic() < deadline:
            current_serial = await loop.run_in_executor(None, _query_serial, zone, xe.host, xe.port)
            _, count, _ = await loop.run_in_executor(
                None, dig.axfr, zone, xe.host, xe.port, 300)

            if current_serial is not None and current_serial > base_serial and (current_serial, count) == prev:
                propagated = True
                break

            prev = (current_serial, count)

            await asyncio.sleep(1.0)

        if not propagated:
            print(f"  [FAIL] b05: serial did not advance within 120s for {n}-change IXFR")
            rows.append({
                "system": context["label"],
                "changes": n,
                "status": "FAILED",
                "error": "propagation timeout: serial did not advance within 120s",
            })

            continue

        secs, lines, nbytes = await loop.run_in_executor(
            None, dig.ixfr, zone, xe.host, xe.port, base_serial)

        rows.append({
            "system": context["label"],
            "changes": n,
            "transfer_secs": round(secs, 4),
            "transfer_bytes": nbytes,
            "lines": lines,
            "records_per_sec": round(lines / secs, 1) if secs else 0,
            "true_ixfr": bool(adapter.supports_ixfr),
        })

    return rows
