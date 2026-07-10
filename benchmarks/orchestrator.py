#!/usr/bin/env python3
"""Bindizr benchmark orchestrator.

Runs selected benchmarks against selected systems, one system at a time (to keep
the host uncontended), collecting structured results and writing the final
report. Each system is fully set up, exercised, and torn down in isolation.

Usage:
    python orchestrator.py                          # all enabled, all benchmarks
    python orchestrator.py -b b01_crud_tps -s bindizr
    python orchestrator.py --list
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import os
import traceback
from pathlib import Path

from adapters import registry
from lib import env as envmod
from lib import report, settings
from lib.resources import ResourceSampler
from lib import dockerutil

ZONE = "bench.example."

RUNNERS = {
    "b01_crud_tps": "runners.b01_crud_tps",
    "b02_bulk_import": "runners.b02_bulk_import",
    "b03_propagation": "runners.b03_propagation",
    "b04_axfr": "runners.b04_axfr",
    "b05_ixfr": "runners.b05_ixfr",
    "b06_large_zone": "runners.b06_large_zone",
    "b07_database": "runners.b07_database",
    "b08_query_perf": "runners.b08_query_perf",
    "b09_resource_usage": "runners.b09_resource_usage",
}


# NOTIFY is disabled only where propagation would confound the measurement.
# Elsewhere Bindizr keeps it on, so it does the same propagation work its
# integrated competitors always do.
NOTIFY_OFF_BENCHMARKS = {"b07_database"}


def bindizr_notify_for(bench: str) -> bool:
    override = os.environ.get("BENCH_BINDIZR_NOTIFY")
    if override is not None:
        return override.lower() == "true"
    return bench not in NOTIFY_OFF_BENCHMARKS


def project_name(bench: str, system: str) -> str:
    return f"bench-{system}".replace("_", "-")


async def run_one(bench: str, system: str, cfg: dict) -> dict | None:
    label = settings.system_label(cfg, system)
    print(f"\n=== {bench} :: {label} ({system}) ===", flush=True)
    proj = project_name(bench, system)

    # b07 manages its own adapters (one per DB backend) — skip generic setup.
    if bench == "b07_database":
        try:
            mod = importlib.import_module(RUNNERS[bench])
            ctx = {"zone": ZONE, "label": label, "system": system, "project": proj}
            result = await mod.run(None, cfg, ctx)
            rows = result if isinstance(result, list) else [result]
            for row in rows:
                report.save_result(bench, row)
            print(f"  OK: {rows}", flush=True)
            return rows
        except Exception as e:
            print(f"  [FAIL] {bench}: {e}")
            traceback.print_exc()
            return None

    kwargs = {}
    if system == "bindizr":
        kwargs["notify_after_update"] = bindizr_notify_for(bench)
    try:
        adapter = registry.build(system, cfg, proj, **kwargs)
    except Exception as e:
        print(f"  [SKIP] cannot build adapter: {e}")
        return None

    sampler = None
    try:
        print("  setup...", flush=True)
        await adapter.setup()
        ids = [adapter.compose.container_id(s) for s in adapter.resource_services]
        ids = [i for i in ids if i]
        sampler = ResourceSampler(ids, cfg["resources"]["sample_interval_secs"])
        sampler.start()

        mod = importlib.import_module(RUNNERS[bench])
        ctx = {"zone": ZONE, "label": label, "system": system, "project": proj}
        result = await mod.run(adapter, cfg, ctx)

        res = sampler.stop() if sampler else {}
        sampler = None
        rows = result if isinstance(result, list) else [result]
        for row in rows:
            row.setdefault("peak_mem_mb", res.get("peak_mem_mb", 0))
            row.setdefault("avg_cpu_pct", res.get("avg_cpu_pct", 0))
            report.save_result(bench, row)
        print(f"  OK: {rows}", flush=True)
        return rows
    except Exception as e:
        print(f"  [FAIL] {bench}/{system}: {e}")
        traceback.print_exc()
        print("  --- container logs (tail) ---")
        for s in adapter.resource_services:
            print(adapter.compose.logs(s, tail=30))
        return None
    finally:
        if sampler:
            sampler.stop()
        print("  teardown...", flush=True)
        try:
            await adapter.teardown()
        except Exception as e:
            print(f"  teardown error: {e}")


async def main_async(args) -> None:
    cfg = settings.load()
    repeats = int(cfg.get("repeats", 1))
    benches = args.benchmarks or list(RUNNERS.keys())

    # Clear only the raw files for the benchmarks about to run, so repeated
    # invocations never accumulate stale/duplicate rows, while a subset re-run
    # (e.g. -b b07_database) preserves the other benchmarks' existing results.
    report.RAW_DIR.mkdir(parents=True, exist_ok=True)
    for bench in benches:
        f = report.RAW_DIR / f"{bench}.json"
        if f.exists():
            f.unlink()
    for bench in benches:
        systems = args.systems or cfg["benchmarks"].get(bench, [])
        systems = [s for s in systems
                   if s == "bind9_native" or cfg["systems"].get(s, {}).get("enabled")]
        for system in systems:
            for rep in range(repeats):
                if repeats > 1:
                    print(f"\n----- repeat {rep + 1}/{repeats} -----", flush=True)
                await run_one(bench, system, cfg)

    print("\n=== building report ===")
    report.build_report(envmod.collect(cfg), cfg)
    print(f"Report written to {settings.RESULTS_DIR}")
    print(f"To re-run a subset into this same directory:\n"
          f"  BENCH_RESULTS_DIR={settings.RESULTS_DIR.name} python3 orchestrator.py -b <bench>")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-b", "--benchmarks", nargs="*", help="benchmark keys (default: all)")
    ap.add_argument("-s", "--systems", nargs="*", help="system keys (default: per-benchmark)")
    ap.add_argument("--list", action="store_true", help="list benchmarks and exit")
    args = ap.parse_args()
    if args.list:
        for k in RUNNERS:
            print(k)
        return
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
