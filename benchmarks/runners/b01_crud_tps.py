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
    conc = crud_config["concurrency"]
    dur = crud_config["duration_secs"]
    warm = crud_config["warmup_secs"]
    npool = crud_config["records_prepopulate"]

    await adapter.create_zone(zone)

    # Prepopulate a non-destructive pool for READ/UPDATE.
    pool_records = generate(npool, config["seed"] + 1)

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
        h = await adapter.create_record(zone, record)
        created.append(h)
        return True

    create_rec = await loadgen.run_closed_loop(create_step, conc, dur, warm)

    async def read_step(seq: int) -> bool:
        """Read one existing record for the measured workload."""
        return await adapter.get_record(zone, pool_handles[seq % len(pool_handles)])

    read_rec = await loadgen.run_closed_loop(read_step, conc, dur, warm)

    async def update_step(seq: int) -> bool:
        """Update only TTL so record-group and ID-based APIs do comparable work."""
        idx = seq % len(pool_handles)
        record = dict(pool_records[idx])
        record["ttl"] = 1800
        return await adapter.update_record(zone, pool_handles[idx], record)

    update_rec = await loadgen.run_closed_loop(update_step, conc, dur, warm)

    async def delete_step(seq: int) -> bool:
        """Delete records from the CREATE phase, preserving the read/update pool."""
        return await adapter.delete_record(zone, created[seq])

    delete_rec = (
        await loadgen.run_n(delete_step, conc, len(created))
        if created else None
    )

    cs, rs, us = create_rec.summary(), read_rec.summary(), update_rec.summary()
    ds = delete_rec.summary() if delete_rec else {"tps": 0, "p95_ms": 0, "error_rate": 0}
    total_err = (create_rec.errors + read_rec.errors + update_rec.errors
                 + (delete_rec.errors if delete_rec else 0))
    total_req = (create_rec.total + read_rec.total + update_rec.total
                 + (delete_rec.total if delete_rec else 0))

    return {
        "system": context["label"],
        "create_tps": cs["tps"],
        "update_tps": us["tps"],
        "delete_tps": ds["tps"],
        "read_tps": rs["tps"],
        "create_p95_ms": cs["p95_ms"],
        "read_p95_ms": rs["p95_ms"],
        "update_p95_ms": us["p95_ms"],
        "read_p50_ms": rs["p50_ms"],
        "read_p99_ms": rs["p99_ms"],
        "error_rate": round(total_err / total_req, 5) if total_req else 0,
    }
