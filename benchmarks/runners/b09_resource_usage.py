"""Sample CPU, memory and network usage under steady A-record query load.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datasets.gen_dataset import generate  # noqa: E402
from lib import dnsquery, dig  # noqa: E402
from lib.resources import sampler_for  # noqa: E402

# Samples its own query phase, including warmup, rather than the orchestrator's full run.
SELF_SAMPLES = True


async def run(adapter, config, context) -> dict:
    """Measure system resource use under the configured benchmark workloads."""
    zone = context["zone"]
    size = config["query"]["zone_size"]

    await adapter.create_zone(zone)

    records = [record for record in generate(size * 2, config["seed"], zone)
               if record["type"] == "A"][:size]

    await adapter.import_records(zone, records)
    if adapter.bulk_errors:
        raise RuntimeError(f"preparing the resource workload failed for {adapter.bulk_errors} records")

    names = [f'{record["name"]}.{zone.rstrip(".")}' for record in records]
    endpoint = adapter.dns_endpoint()

    # Keep import and propagation costs outside the resource sampling window.
    propagation_config = config["propagation"]

    missing = await dig.first_unqueryable(
        records, zone, endpoint.host, endpoint.port,
        propagation_config["poll_interval_ms"], propagation_config["timeout_secs"])

    if missing is not None:
        print(f'  [FAIL] b09: zone not queryable within '
              f'{propagation_config["timeout_secs"]}s for {context["label"]}')
        return {
            "system": context["label"],
            "status": "FAILED",
            "error": "propagation timeout: imported zone not queryable",
        }

    # Resource samples include query warmup; throughput and latency samples exclude it.
    sampler = sampler_for(adapter, config)
    with sampler:
        recorder = await dnsquery.query_load(
            endpoint.host, endpoint.port, names, dnsquery.QTYPE["A"], config["query"]["concurrency"],
            config["query"]["duration_secs"], warmup_secs=1.0)
    resource_usage = sampler.summary()

    summary = recorder.summary()

    def _service(name: str) -> str:
        """Extract the service from a <project>-<service>-<index> container name."""
        parts = name.rsplit("-", 2)
        return parts[-2] if len(parts) == 3 else name

    # Bindizr idles outside the query plane while BIND9 serves, so the split
    # shows where the stack's cost actually lands.
    by_service = {_service(name): value for name, value in resource_usage.get("cpu_by_container", {}).items()}

    return {
        "system": context["label"],
        "qps_during": summary["tps"],
        "cpu_total_pct": round(sum(by_service.values()), 2),
        "cpu_by_container": ", ".join(f"{name} {value}" for name, value in sorted(by_service.items())),
        "peak_mem_mb": resource_usage.get("peak_mem_mb", 0),
        "avg_mem_mb": resource_usage.get("avg_mem_mb", 0),
        "net_tx_mb": resource_usage.get("net_tx_mb", 0),
    }
