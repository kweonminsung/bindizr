"""Benchmark 8 — DNS Query Performance.

Loads a fixed A-record zone into the system, then hammers its resolver with UDP
queries for existing names, measuring QPS and latency percentiles.

Compare each Bindizr pairing with the same server run standalone (`Native
BIND9`, `Knot DNS`, `PowerDNS Authoritative`), since the secondary answers the
pairing's queries. The measured QPS difference determines the report's
query-overhead conclusion.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datasets.gen_dataset import generate  # noqa: E402
from lib import dnsquery, dnsutil  # noqa: E402


async def run(adapter, cfg, ctx) -> dict:
    """Measure DNS query throughput and latency for the benchmark system."""
    zone = ctx["zone"]
    q = cfg["query"]
    size = q["zone_size"]

    await adapter.create_zone(zone)
    # Use only A records so every queried name has an answer of a known type.
    records = [r for r in generate(size * 2, cfg["seed"], zone)
               if r["type"] == "A"][:size]
    await adapter.bulk_import(zone, records)

    names = [f'{r["name"]}.{zone.rstrip(".")}' for r in records]
    ep = adapter.dns_endpoint()

    # Exclude propagation wait from the query workload's warmup and measurements.
    p = cfg["propagation"]
    missing = await asyncio.get_event_loop().run_in_executor(
        None, dnsutil.first_unqueryable, records, zone, ep.host, ep.port,
        p["poll_interval_ms"], p["timeout_secs"])
    if missing is not None:
        print(f'  [FAIL] b08: zone not queryable within '
              f'{p["timeout_secs"]}s for {ctx["label"]}')
        return {
            "system": ctx["label"],
            "zone_records": len(records),
            "status": "FAILED",
            "error": "propagation timeout: imported zone not queryable",
        }

    # Warm the query path, then collect throughput and latency samples.
    rec = await dnsquery.query_load(
        ep.host, ep.port, names, dnsquery.QTYPE["A"],
        q["concurrency"], q["duration_secs"], warmup_secs=2.0)
    s = rec.summary()
    return {
        "system": ctx["label"],
        "zone_records": len(records),
        "qps": s["tps"],
        "avg_latency_ms": s["mean_ms"],
        "p95_ms": s["p95_ms"],
        "p99_ms": s["p99_ms"],
        "error_rate": s["error_rate"],
    }
