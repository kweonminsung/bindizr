"""Benchmark 8 — DNS Query Performance.

Loads a fixed A-record zone into the system, then hammers its resolver with UDP
queries for existing names, measuring QPS and latency percentiles.

The headline comparison is `Native BIND9` vs `Bindizr + BIND9`: since Bindizr is
outside the DNS data plane (queries are served by the BIND9 secondary), the two
should match — demonstrating zero query overhead.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datasets.gen_dataset import generate  # noqa: E402
from lib import dnsquery, dnsutil  # noqa: E402


async def run(adapter, cfg, ctx) -> dict:
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

    # Wait until the imported zone is queryable before measuring. For Bindizr the
    # bulk write only starts async transfer to the BIND9 secondary, so a fixed
    # sleep could load a half-populated secondary and count missing names as
    # errors (deflating QPS). Poll a few names including the last record, which
    # lands in the final (highest-serial) chunk, so once it resolves the whole
    # zone is present. Integrated systems return near-instantly.
    loop = asyncio.get_event_loop()
    p = cfg["propagation"]
    probe_idxs = sorted({0, len(records) // 2, len(records) - 1}) if records else []
    for idx in probe_idxs:
        r = records[idx]
        got = await loop.run_in_executor(
            None, dnsutil.poll_until_visible,
            f'{r["name"]}.{zone.rstrip(".")}', "A", r["value"],
            ep.host, ep.port, p["poll_interval_ms"], p["timeout_secs"])
        if got is None:
            print(f'  [FAIL] b08: zone not queryable within '
                  f'{p["timeout_secs"]}s for {ctx["label"]}')
            return {
                "system": ctx["label"],
                "zone_records": len(records),
                "status": "FAILED",
                "error": "propagation timeout: imported zone not queryable",
            }

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
