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
from lib import dnsquery, dnsutil  # noqa: E402
from lib.resources import sampler_for  # noqa: E402

# Sampled around the measured phase below, not by the orchestrator.
SELF_SAMPLES = True


async def run(adapter, cfg, ctx) -> dict:
    zone = ctx["zone"]
    size = cfg["query"]["zone_size"]
    await adapter.create_zone(zone)
    records = [r for r in generate(size * 2, cfg["seed"], zone)
               if r["type"] == "A"][:size]
    await adapter.bulk_import(zone, records)
    names = [f'{r["name"]}.{zone.rstrip(".")}' for r in records]
    ep = adapter.dns_endpoint()

    p = cfg["propagation"]
    missing = await asyncio.get_event_loop().run_in_executor(
        None, dnsutil.first_unqueryable, records, zone, ep.host, ep.port,
        p["poll_interval_ms"], p["timeout_secs"])
    if missing is not None:
        print(f'  [FAIL] b09: zone not queryable within '
              f'{p["timeout_secs"]}s for {ctx["label"]}')
        return {
            "system": ctx["label"],
            "status": "FAILED",
            "error": "propagation timeout: imported zone not queryable",
        }

    sampler = sampler_for(adapter, cfg)
    sampler.start()
    rec = await dnsquery.query_load(
        ep.host, ep.port, names, dnsquery.QTYPE["A"], cfg["query"]["concurrency"],
        cfg["query"]["duration_secs"], warmup_secs=1.0)
    res = sampler.stop()
    s = rec.summary()

    # Bindizr idles outside the query plane while BIND9 serves, so the split
    # shows where the stack's cost actually lands.
    def _service(name: str) -> str:
        # docker container names are "<project>-<service>-<index>".
        parts = name.rsplit("-", 2)
        return parts[-2] if len(parts) == 3 else name

    by_service = {_service(n): v for n, v in res.get("cpu_by_container", {}).items()}
    return {
        "system": ctx["label"],
        "qps_during": s["tps"],
        "cpu_total_pct": round(sum(by_service.values()), 2),
        "cpu_by_container": ", ".join(f"{n} {v}" for n, v in sorted(by_service.items())),
        "peak_mem_mb": res.get("peak_mem_mb", 0),
        "avg_mem_mb": res.get("avg_mem_mb", 0),
        "net_tx_mb": res.get("net_tx_mb", 0),
    }
