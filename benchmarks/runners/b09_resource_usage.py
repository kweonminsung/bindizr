"""Benchmark 9 — Resource Usage.

Populates a fixed zone, then applies a steady mixed query load while sampling
container CPU, memory, network, and block IO. Reports peak/avg for each.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datasets.gen_dataset import generate  # noqa: E402
from lib import dnsquery  # noqa: E402
from lib.resources import ResourceSampler  # noqa: E402

LOAD_SECS = 20


async def run(adapter, cfg, ctx) -> dict:
    zone = ctx["zone"]
    size = cfg["query"]["zone_size"]
    await adapter.create_zone(zone)
    records = [r for r in generate(size * 2, cfg["seed"], zone)
               if r["type"] == "A"][:size]
    await adapter.bulk_import(zone, records)
    names = [f'{r["name"]}.{zone.rstrip(".")}' for r in records]
    ep = adapter.dns_endpoint()
    await asyncio.sleep(3)

    ids = [i for i in (adapter.compose.container_id(s)
                       for s in adapter.resource_services) if i]
    sampler = ResourceSampler(ids, cfg["resources"]["sample_interval_secs"])
    sampler.start()
    rec = await dnsquery.query_load(ep.host, ep.port, names, dnsquery.QTYPE["A"],
                                    cfg["query"]["concurrency"], LOAD_SECS, warmup_secs=1.0)
    res = sampler.stop()
    s = rec.summary()
    return {
        "system": ctx["label"],
        "qps_during": s["tps"],
        "peak_cpu_pct": res.get("peak_cpu_pct", 0),
        "avg_cpu_pct": res.get("avg_cpu_pct", 0),
        "peak_mem_mb": res.get("peak_mem_mb", 0),
        "avg_mem_mb": res.get("avg_mem_mb", 0),
        "peak_net_tx_mb": res.get("peak_net_tx_mb", 0),
    }
