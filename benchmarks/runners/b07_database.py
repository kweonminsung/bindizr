"""Compare CRUD TPS, latency, resources and bulk scaling across Bindizr backends.

Own adapter setup/teardown (`adapter=None`); report CRUD by backend and bulk by backend/size.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from adapters import registry  # noqa: E402
from datasets.gen_dataset import generate  # noqa: E402
from lib import loadgen  # noqa: E402
from lib.resources import sampler_for  # noqa: E402

# Sampled around the measured phase below, not by the orchestrator.
SELF_SAMPLES = True


def _mem_split(resource_usage: dict) -> tuple[float, float]:
    """Bindizr's own peak vs the DB server container's, from the per-container
    peaks. sqlite runs in-process, so its DB share is 0."""
    by_service = {}

    for name, mb in resource_usage.get("mem_by_container", {}).items():
        # docker container names are "<project>-<service>-<index>".
        parts = name.rsplit("-", 2)
        by_service[parts[-2] if len(parts) == 3 else name] = mb

    return (by_service.get("bindizr", 0),
            by_service.get("mysql", 0) + by_service.get("postgres", 0))


async def _bench_backend(adapter, config, zone, label, pairing) -> dict:
    """Measure create/read throughput, latency, and resource use for one backend."""
    crud_config = config["crud"]
    conc, dur, warm = crud_config["concurrency"], min(crud_config["duration_secs"], 15), crud_config["warmup_secs"]
    npool = min(crud_config["records_prepopulate"], 2000)

    # Populate the read workload's record pool before resource sampling starts.
    await adapter.create_zone(zone)

    pool = generate(npool, config["seed"] + 1)
    handles = []

    for i, record in enumerate(pool):
        record["name"] = f"pool{i:07d}"
        handles.append(await adapter.create_record(zone, record))

    # The resource window includes create-data preparation and both warmups.
    sampler = sampler_for(adapter, config)
    with sampler:
        create_records = generate(200_000, config["seed"] + 3)

        async def create_step(seq):
            """Create one uniquely named record for the measured workload."""
            record = dict(create_records[seq % len(create_records)])
            record["name"] = f"crt{seq:08d}"
            await adapter.create_record(zone, record)
            return True

        async def read_step(seq):
            """Read one existing record for the measured workload."""
            return await adapter.get_record(zone, handles[seq % len(handles)])

        # Measure create and read separately, each with its own unrecorded warmup.
        create_run = await loadgen.run_closed_loop(create_step, conc, dur, warm)
        read_run = await loadgen.run_closed_loop(read_step, conc, dur, warm)
    resource_usage = sampler.summary()

    cs, rs = create_run.summary(), read_run.summary()
    bindizr_mem, db_mem = _mem_split(resource_usage)

    return {
        "system": pairing,
        "backend": label,
        "create_tps": cs["tps"],
        "read_tps": rs["tps"],
        "create_p95_ms": cs["p95_ms"],
        "read_p95_ms": rs["p95_ms"],
        "error_rate": round(
            (create_run.errors + read_run.errors) / max(create_run.total + read_run.total, 1), 5
        ),
        "peak_mem_mb": resource_usage.get("peak_mem_mb", 0),
        "bindizr_peak_mem_mb": bindizr_mem,
        "db_peak_mem_mb": db_mem,
        "avg_cpu_pct": resource_usage.get("avg_cpu_pct", 0),
    }


async def _bulk_backend(adapter, config, zone, backend, size, pairing) -> dict:
    """Import `size` records into a fresh zone via the backend and time it,
    sampling the DB container's resource usage."""
    await adapter.delete_zone(zone)
    await adapter.create_zone(zone)

    records = generate(size, config["seed"], zone)

    sampler = sampler_for(adapter, config)
    with sampler:
        t0 = time.monotonic()

        await adapter.import_records(zone, records)

        elapsed = time.monotonic() - t0
    resource_usage = sampler.summary()

    # Adapters count failures instead of raising, so rate off what landed —
    # a fast total failure would otherwise top the chart.
    failed = getattr(adapter, "bulk_errors", 0)
    imported = max(size - failed, 0)

    bindizr_mem, db_mem = _mem_split(resource_usage)

    return {
        "system": pairing,
        "backend": backend,
        "size": size,
        "import_secs": round(elapsed, 3),
        "records_per_sec": round(imported / elapsed, 1) if elapsed else 0,
        "import_errors": failed,
        "peak_mem_mb": resource_usage.get("peak_mem_mb", 0),
        "bindizr_peak_mem_mb": bindizr_mem,
        "db_peak_mem_mb": db_mem,
        "avg_cpu_pct": resource_usage.get("avg_cpu_pct", 0),
    }


async def run(_adapter, config, context) -> list:
    """Compare CRUD and bulk import performance across database backends."""
    zone = context["zone"]
    pairing = context["label"]
    rows = []
    # The system key selects which secondary runs beside Bindizr; the backend
    # comparison is the same either way, so the four pairings should agree.
    system = context["system"]

    for backend in config["databases"]:
        proj = f"bench-{system.replace('_', '-')}-db-{backend}"
        # notify off: isolate database write throughput from NOTIFY/XFR cost.
        adapter = registry.build_adapter(system, config, proj, db_type=backend,
                                 notify_after_update=False)

        try:
            print(f"    backend {backend}: setup...", flush=True)

            await adapter.setup()
            row = await _bench_backend(adapter, config, zone, backend, pairing)

            rows.append(row)
            print(f"    backend {backend} (crud): {row}", flush=True)

            for size in config.get("db_bulk_sizes", []):
                brow = await _bulk_backend(adapter, config, zone, backend, size,
                                           pairing)
                rows.append(brow)
                print(f"    backend {backend} (bulk {size}): {brow}", flush=True)
        except Exception as error:
            print(f"    backend {backend} FAILED: {error}")
            # Report the failure faithfully instead of silently omitting it.
            rows.append({"system": pairing, "backend": backend,
                         "status": "FAILED", "error": str(error)[:120]})
        finally:
            await adapter.teardown()

    return rows
