"""Measure API latency and time until a created record is visible through host `dig`.

Bindizr's path is API -> serial bump -> NOTIFY -> AXFR/IXFR -> secondary -> dig.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib import dig  # noqa: E402
from lib.metrics import LatencyRecorder  # noqa: E402


async def run(adapter, config, context) -> dict:
    """Measure the delay from a record mutation to a visible DNS answer."""
    zone = context["zone"]
    endpoint = adapter.dns_endpoint()
    propagation_config = config["propagation"]
    samples = propagation_config["samples"]

    await adapter.create_zone(zone)

    # Warm up: the first record in a fresh zone pays a one-time secondary
    # bootstrap (for Bindizr: catalog discovery + initial AXFR), so do one
    # throwaway create to keep it out of the measured samples.
    warm = {"name": "warmup", "type": "A", "value": "10.0.0.1", "ttl": 60}

    try:
        await adapter.create_record(zone, warm)
        await dig.poll_until_visible(
            f"warmup.{zone.rstrip('.')}", "A", "10.0.0.1", endpoint.host, endpoint.port,
            propagation_config["poll_interval_ms"], propagation_config["timeout_secs"])
    except Exception:
        pass

    api = LatencyRecorder()
    visible = LatencyRecorder()
    api.started_at = visible.started_at = time.monotonic()
    timeouts = 0

    for i in range(samples):
        name = f"prop{i:05d}"
        ip = f"10.9.{i // 256 % 256}.{i % 256}"
        record = {"name": name, "type": "A", "value": ip, "ttl": 60}
        fqdn = f"{name}.{zone.rstrip('.')}"

        t0 = time.monotonic()

        try:
            await adapter.create_record(zone, record)
            api.track_latency(time.monotonic() - t0, ok=True)
        except Exception:
            api.track_latency(time.monotonic() - t0, ok=False)
            continue

        secs = await dig.poll_until_visible(
            fqdn, "A", ip, endpoint.host, endpoint.port,
            propagation_config["poll_interval_ms"], propagation_config["timeout_secs"])

        # Time from the create call, not from when polling started: a
        # synchronous apply sends the NOTIFY inside the API call itself.
        elapsed = time.monotonic() - t0

        if secs is None:
            timeouts += 1
            visible.track_latency(elapsed, ok=False)
        else:
            visible.track_latency(elapsed, ok=True)

    api.ended_at = visible.ended_at = time.monotonic()
    a, v = api.summary(), visible.summary()

    return {
        "system": context["label"],
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
