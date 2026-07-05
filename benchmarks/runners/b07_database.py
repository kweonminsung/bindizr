"""Benchmark 7 — Database Performance (Bindizr backends).

Runs the same CRUD-lite workload against Bindizr backed by SQLite, MySQL, and
PostgreSQL in turn, comparing create/read TPS, latency, and resource use.

This runner is special: it builds and tears down its own Bindizr adapters (one
per backend), so the orchestrator invokes it with `adapter=None`.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from adapters import registry  # noqa: E402
from datasets.gen_dataset import generate  # noqa: E402
from lib import loadgen  # noqa: E402
from lib.resources import ResourceSampler  # noqa: E402


async def _bench_backend(adapter, cfg, zone, label) -> dict:
    c = cfg["crud"]
    conc, dur, warm = c["concurrency"], min(c["duration_secs"], 15), c["warmup_secs"]
    npool = min(c["records_prepopulate"], 2000)

    await adapter.create_zone(zone)
    pool = generate(npool, cfg["seed"] + 1)
    handles = []
    for i, rec in enumerate(pool):
        rec["name"] = f"pool{i:07d}"
        handles.append(await adapter.create_record(zone, rec))

    ids = [i for i in (adapter.compose.container_id(s)
                       for s in adapter.resource_services) if i]
    sampler = ResourceSampler(ids, cfg["resources"]["sample_interval_secs"])
    sampler.start()

    create_recs = generate(200_000, cfg["seed"] + 3)

    async def create_step(seq):
        rec = dict(create_recs[seq % len(create_recs)])
        rec["name"] = f"crt{seq:08d}"
        await adapter.create_record(zone, rec)
        return True

    async def read_step(seq):
        return await adapter.get_record(zone, handles[seq % len(handles)])

    cr = await loadgen.run_closed_loop(create_step, conc, dur, warm)
    rr = await loadgen.run_closed_loop(read_step, conc, dur, warm)
    res = sampler.stop()
    cs, rs = cr.summary(), rr.summary()
    return {
        "backend": label,
        "create_tps": cs["tps"],
        "read_tps": rs["tps"],
        "create_p95_ms": cs["p95_ms"],
        "read_p95_ms": rs["p95_ms"],
        "error_rate": round((cr.errors + rr.errors) / max(cr.total + rr.total, 1), 5),
        "peak_mem_mb": res.get("peak_mem_mb", 0),
        "avg_cpu_pct": res.get("avg_cpu_pct", 0),
    }


async def run(_adapter, cfg, ctx) -> list:
    zone = ctx["zone"]
    rows = []
    for backend in cfg["databases"]:
        proj = f"bench-bindizr-db-{backend}"
        # notify off: isolate database write throughput from NOTIFY/XFR cost.
        adapter = registry.build("bindizr", cfg, proj, db_type=backend,
                                 notify_after_update=False)
        try:
            print(f"    backend {backend}: setup...", flush=True)
            await adapter.setup()
            row = await _bench_backend(adapter, cfg, zone, backend)
            rows.append(row)
            print(f"    backend {backend}: {row}", flush=True)
        except Exception as e:
            print(f"    backend {backend} FAILED: {e}")
            # Report the failure faithfully instead of silently omitting it.
            rows.append({"backend": backend, "status": "FAILED",
                         "error": str(e)[:120]})
        finally:
            await adapter.teardown()
    return rows
