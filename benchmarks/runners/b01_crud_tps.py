"""Benchmark 1 — Record CRUD TPS.

Identical closed-loop workload across systems:
  1. prepopulate a pool of records (for READ/UPDATE, non-destructive)
  2. CREATE phase  — measure create TPS, accumulating handles
  3. READ phase    — GET random pool handle
  4. UPDATE phase  — PUT random pool handle
  5. DELETE phase  — delete exactly the handles created in step 2

Produces one row: Create/Update/Delete/Read TPS + p95 + error rate.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datasets.gen_dataset import generate  # noqa: E402
from lib import loadgen  # noqa: E402


async def run(adapter, cfg, ctx) -> dict:
    zone = ctx["zone"]
    c = cfg["crud"]
    conc = c["concurrency"]
    dur = c["duration_secs"]
    warm = c["warmup_secs"]
    npool = c["records_prepopulate"]

    await adapter.create_zone(zone)

    # Prepopulate a non-destructive pool for READ/UPDATE.
    pool_recs = generate(npool, cfg["seed"] + 1)
    for i, rec in enumerate(pool_recs):
        rec["name"] = f"pool{i:07d}"
    pool_handles: list[str] = []
    for rec in pool_recs:
        pool_handles.append(await adapter.create_record(zone, rec))

    create_recs = generate(200_000, cfg["seed"] + 3)
    created: list[str] = []

    async def create_step(seq: int) -> bool:
        rec = dict(create_recs[seq % len(create_recs)])
        rec["name"] = f"crt{seq:08d}"
        h = await adapter.create_record(zone, rec)
        created.append(h)
        return True

    create_rec = await loadgen.run_closed_loop(create_step, conc, dur, warm)

    async def read_step(seq: int) -> bool:
        return await adapter.get_record(zone, pool_handles[seq % len(pool_handles)])

    read_rec = await loadgen.run_closed_loop(read_step, conc, dur, warm)

    # --- UPDATE (type-safe: same name/type/value, change TTL) so it maps cleanly
    # onto RRset-based systems like PowerDNS as well as id-based ones like Bindizr.
    async def update_step(seq: int) -> bool:
        idx = seq % len(pool_handles)
        rec = dict(pool_recs[idx])
        rec["ttl"] = 1800
        return await adapter.update_record(zone, pool_handles[idx], rec)

    update_rec = await loadgen.run_closed_loop(update_step, conc, dur, warm)

    # --- DELETE (exactly the handles created above) ---
    async def delete_step(seq: int) -> bool:
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
        "system": ctx["label"],
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
