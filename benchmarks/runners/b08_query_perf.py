"""Benchmark 8: measure UDP QPS and latency for existing names in a fixed A-record zone.

Compare each Bindizr pairing with the same secondary server run standalone;
their measured QPS difference determines the report's query-overhead conclusion.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datasets.gen_dataset import generate  # noqa: E402
from lib import dnsquery, dig  # noqa: E402


async def run(adapter, config, context) -> dict:
    """Measure DNS query throughput and latency for the benchmark system."""
    zone = context["zone"]
    query_config = config["query"]
    size = query_config["zone_size"]

    await adapter.create_zone(zone)

    # Use only A records so every queried name has an answer of a known type.
    records = [record for record in generate(size * 2, config["seed"], zone)
               if record["type"] == "A"][:size]

    await adapter.import_records(zone, records)

    names = [f'{record["name"]}.{zone.rstrip(".")}' for record in records]
    endpoint = adapter.dns_endpoint()

    # Exclude propagation wait from the query workload's warmup and measurements.
    propagation_config = config["propagation"]

    missing = await asyncio.get_event_loop().run_in_executor(
        None, dig.first_unqueryable, records, zone, endpoint.host, endpoint.port,
        propagation_config["poll_interval_ms"], propagation_config["timeout_secs"])

    if missing is not None:
        print(f'  [FAIL] b08: zone not queryable within '
              f'{propagation_config["timeout_secs"]}s for {context["label"]}')
        return {
            "system": context["label"],
            "zone_records": len(records),
            "status": "FAILED",
            "error": "propagation timeout: imported zone not queryable",
        }

    # Warm the query path, then collect throughput and latency samples.
    recorder = await dnsquery.query_load(
        endpoint.host, endpoint.port, names, dnsquery.QTYPE["A"],
        query_config["concurrency"], query_config["duration_secs"], warmup_secs=2.0)

    summary = recorder.summary()

    return {
        "system": context["label"],
        "zone_records": len(records),
        "qps": summary["tps"],
        "avg_latency_ms": summary["mean_ms"],
        "p95_ms": summary["p95_ms"],
        "p99_ms": summary["p99_ms"],
        "error_rate": summary["error_rate"],
    }
