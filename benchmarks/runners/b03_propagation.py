"""Benchmark 3 — End-to-End DNS Propagation.

For each sample: create a record via the API, then poll the resolver with `dig`
until the record is visible. Measures API latency and DNS-visible latency
(create -> answerable). This is where Bindizr's async control-plane model differs
most from integrated servers: for Bindizr the path is
API -> serial bump -> NOTIFY -> AXFR/IXFR -> secondary -> dig.
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib import dnsutil  # noqa: E402
from lib.metrics import LatencyRecorder  # noqa: E402


async def run(adapter, cfg, ctx) -> dict:
    zone = ctx["zone"]
    ep = adapter.dns_endpoint()
    p = cfg["propagation"]
    samples = p["samples"]

    await adapter.create_zone(zone)
    loop = asyncio.get_event_loop()

    # Warm up: the first record in a fresh zone pays a one-time secondary
    # bootstrap (for Bindizr: catalog discovery + initial AXFR), so do one
    # throwaway create to keep it out of the measured samples.
    warm = {"name": "warmup", "type": "A", "value": "10.0.0.1", "ttl": 60}
    try:
        await adapter.create_record(zone, warm)
        await loop.run_in_executor(
            None, dnsutil.poll_until_visible, f"warmup.{zone.rstrip('.')}", "A",
            "10.0.0.1", ep.host, ep.port, p["poll_interval_ms"], p["timeout_secs"])
    except Exception:
        pass

    api = LatencyRecorder()
    visible = LatencyRecorder()
    api.started_at = time.monotonic()
    timeouts = 0

    for i in range(samples):
        name = f"prop{i:05d}"
        ip = f"10.9.{i // 256 % 256}.{i % 256}"
        rec = {"name": name, "type": "A", "value": ip, "ttl": 60}
        fqdn = f"{name}.{zone.rstrip('.')}"

        t0 = time.monotonic()
        try:
            await adapter.create_record(zone, rec)
            api.record(time.monotonic() - t0, ok=True)
        except Exception:
            api.record(time.monotonic() - t0, ok=False)
            continue

        # Blocking poll runs in a thread so we don't stall the loop.
        secs = await loop.run_in_executor(
            None, dnsutil.poll_until_visible, fqdn, "A", ip, ep.host, ep.port,
            p["poll_interval_ms"], p["timeout_secs"])
        if secs is None:
            timeouts += 1
            visible.record(p["timeout_secs"], ok=False)
        else:
            visible.record(secs, ok=True)

    api.ended_at = visible.ended_at = time.monotonic()
    a, v = api.summary(), visible.summary()
    return {
        "system": ctx["label"],
        "samples": samples,
        "api_p50_ms": a["p50_ms"],
        "api_p95_ms": a["p95_ms"],
        "api_p99_ms": a["p99_ms"],
        "visible_p50_ms": v["p50_ms"],
        "visible_p95_ms": v["p95_ms"],
        "visible_p99_ms": v["p99_ms"],
        "visible_max_ms": v["max_ms"],
        "timeouts": timeouts,
    }
