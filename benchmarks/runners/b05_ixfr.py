"""Benchmark 5 — IXFR Performance.

Establishes a baseline zone, records its SOA serial, applies a batch of changes
(1 / 10 / 100 / 1000 records), waits for the serial to advance, then requests an
incremental transfer (IXFR=baseline) and measures how much data moves.

A well-behaved incremental server sends only the delta; a server without real
IXFR falls back to a full AXFR — which this benchmark surfaces as a large
transfer size, itself a meaningful result.
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datasets.gen_dataset import generate  # noqa: E402
from lib import dnsutil  # noqa: E402

# Fallbacks used only when the config lacks the ixfr_* keys; a normal run
# overrides both from settings.yaml (ixfr_change_sizes / ixfr_baseline).
CHANGE_SIZES = [1, 10, 100, 1000, 10000]
BASELINE = 1000


def _serial(zone, host, port):
    ok, _, out = dnsutil.dig(zone, "SOA", host, port)
    if ok and len(out.split()) >= 3:
        try:
            return int(out.split()[2])
        except ValueError:
            return None
    return None


async def run(adapter, cfg, ctx) -> list:
    zone = ctx["zone"]
    xe = adapter.xfr_endpoint()
    loop = asyncio.get_event_loop()
    change_sizes = cfg.get("ixfr_change_sizes", CHANGE_SIZES)
    baseline = cfg.get("ixfr_baseline", BASELINE)

    await adapter.delete_zone(zone)
    await adapter.create_zone(zone)
    await adapter.bulk_import(zone, generate(baseline, cfg["seed"], zone))

    # Wait for the baseline zone to reach the secondary before reading serials: a
    # large baseline may not transfer within a fixed sleep, and reading a
    # pre-baseline serial would request IXFR from a serial with no delta history —
    # a spurious full-AXFR outlier. Poll the AXFR count until it covers the set.
    deadline = time.monotonic() + max(60, baseline / 500)
    prev = -1
    while time.monotonic() < deadline:
        _, count, _ = await loop.run_in_executor(
            None, dnsutil.axfr, zone, xe.host, xe.port, 300)
        if count >= baseline and count == prev:
            break
        prev = count
        await asyncio.sleep(1.0)

    rows = []
    change_pool = generate(sum(change_sizes) + baseline, cfg["seed"] + 50, zone)
    ci = 0
    for n in change_sizes:
        # Read the pre-change serial, retrying on a transient SOA-query miss.
        # Falling back to `base_serial or 1` would request IXFR from serial 1 — no
        # delta history — forcing a full AXFR and a spurious "huge IXFR" outlier.
        base_serial = None
        for _ in range(10):
            base_serial = await loop.run_in_executor(None, _serial, zone, xe.host, xe.port)
            if base_serial is not None:
                break
            await asyncio.sleep(0.5)
        if base_serial is None:
            print(f"  [SKIP] b05: could not read base serial for {n}-change IXFR")
            continue

        # Apply n new records.
        batch = []
        for _ in range(n):
            rec = dict(change_pool[ci % len(change_pool)])
            rec["name"] = f"ixfr{ci:07d}"
            batch.append(rec)
            ci += 1
        await adapter.bulk_import(zone, batch)

        # Wait for the serial to advance. If it never does (batch failed to apply,
        # or the secondary never transferred it), an IXFR from the unchanged
        # base_serial returns a tiny "up-to-date" SOA that would masquerade as an
        # efficient transfer — so record a failure instead of measuring.
        deadline = time.monotonic() + 120
        propagated = False
        while time.monotonic() < deadline:
            s = await loop.run_in_executor(None, _serial, zone, xe.host, xe.port)
            if s is not None and s > base_serial:
                propagated = True
                break
            await asyncio.sleep(0.5)
        if not propagated:
            print(f"  [FAIL] b05: serial did not advance within 120s for {n}-change IXFR")
            rows.append({
                "system": ctx["label"],
                "changes": n,
                "status": "FAILED",
                "error": "propagation timeout: serial did not advance within 120s",
            })
            continue

        secs, lines, nbytes = await loop.run_in_executor(
            None, dnsutil.ixfr, zone, xe.host, xe.port, base_serial)
        rows.append({
            "system": ctx["label"],
            "changes": n,
            "transfer_secs": round(secs, 4),
            "transfer_bytes": nbytes,
            "lines": lines,
            "records_per_sec": round(lines / secs, 1) if secs else 0,
            "true_ixfr": bool(adapter.supports_ixfr),
        })
    return rows
