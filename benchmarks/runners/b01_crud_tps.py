"""Measure record CRUD TPS, p95 latency and error rate with a closed-loop workload.

Reads/updates use a prepopulated pool; deletes target only records created in this run.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datasets.gen_dataset import generate  # noqa: E402
from lib import loadgen  # noqa: E402


async def run(adapter, config, context) -> dict:
    """Measure record creation, reading, updating, and deletion throughput."""
    zone = context["zone"]
    crud_config = config["crud"]
    concurrency = crud_config["concurrency"]
    duration_secs = crud_config["duration_secs"]
    warmup_secs = crud_config["warmup_secs"]
    pool_size = crud_config["records_prepopulate"]

    await adapter.create_zone(zone)

    # Prepopulate a non-destructive pool for READ/UPDATE.
    pool_records = generate(pool_size, config["seed"] + 1)

    for i, record in enumerate(pool_records):
        record["name"] = f"pool{i:07d}"

    pool_handles: list[str] = []

    for record in pool_records:
        pool_handles.append(await adapter.create_record(zone, record))

    create_records = generate(200_000, config["seed"] + 3)
    created: list[str] = []

    async def create_step(seq: int) -> bool:
        """Create one uniquely named record for the measured workload."""
        record = dict(create_records[seq % len(create_records)])
        record["name"] = f"crt{seq:08d}"
        handle = await adapter.create_record(zone, record)
        created.append(handle)
        return True

    create_recorder = await loadgen.run_closed_loop(create_step, concurrency, duration_secs, warmup_secs)

    async def read_step(seq: int) -> bool:
        """Read one existing record for the measured workload."""
        return await adapter.get_record(zone, pool_handles[seq % len(pool_handles)])

    read_recorder = await loadgen.run_closed_loop(read_step, concurrency, duration_secs, warmup_secs)

    async def update_step(seq: int) -> bool:
        """Update only TTL so record-group and ID-based APIs do comparable work."""
        idx = seq % len(pool_handles)
        record = dict(pool_records[idx])
        record["ttl"] = 1800
        return await adapter.update_record(zone, pool_handles[idx], record)

    update_recorder = await loadgen.run_closed_loop(update_step, concurrency, duration_secs, warmup_secs)

    async def delete_step(seq: int) -> bool:
        """Delete records from the CREATE phase, preserving the read/update pool."""
        return await adapter.delete_record(zone, created[seq])

    delete_recorder = (
        await loadgen.run_n(delete_step, concurrency, len(created))
        if created else None
    )

    create_summary, read_summary, update_summary = (
        create_recorder.summary(), read_recorder.summary(), update_recorder.summary()
    )
    delete_summary = delete_recorder.summary() if delete_recorder else {"tps": 0, "p95_ms": 0, "error_rate": 0}
    total_errors = (create_recorder.errors + read_recorder.errors + update_recorder.errors
                 + (delete_recorder.errors if delete_recorder else 0))
    total_requests = (create_recorder.total + read_recorder.total + update_recorder.total
                 + (delete_recorder.total if delete_recorder else 0))

    return {
        "system": context["label"],
        "create_tps": create_summary["tps"],
        "update_tps": update_summary["tps"],
        "delete_tps": delete_summary["tps"],
        "read_tps": read_summary["tps"],
        "create_p95_ms": create_summary["p95_ms"],
        "read_p95_ms": read_summary["p95_ms"],
        "update_p95_ms": update_summary["p95_ms"],
        "read_p50_ms": read_summary["p50_ms"],
        "read_p99_ms": read_summary["p99_ms"],
        "error_rate": round(total_errors / total_requests, 5) if total_requests else 0,
    }
