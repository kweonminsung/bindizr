#!/usr/bin/env python3
"""Run selected workloads one system at a time, with isolated setup/teardown, then report.

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

from adapters import registry
from lib import env as envmod
from lib import report, settings
from lib.resources import ResourceSampler

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


# Management-plane benchmarks isolate raw write throughput, so Bindizr runs them
# with notify_after_update=false; propagation is measured separately in B3/B4/B5.
# b07_database forces NOTIFY off in its own adapters, so it is not listed here.
NOTIFY_OFF_BENCHMARKS = {"b01_crud_tps", "b02_bulk_import"}


def is_bindizr_notify_enabled(bench: str) -> bool:
    """Choose whether this workload needs bindizr to send NOTIFY."""
    override = os.environ.get("BENCH_BINDIZR_NOTIFY")
    if override is not None:
        return override.lower() == "true"
    return bench not in NOTIFY_OFF_BENCHMARKS


def project_name(system: str) -> str:
    """Build the Compose project name for a benchmark run."""
    return f"bench-{system}".replace("_", "-")


async def run_one(bench: str, system: str, config: dict) -> dict | None:
    """Set up one system, run its selected workload, and collect the result."""
    label = settings.system_label(config, system)
    print(f"\n=== {bench} :: {label} ({system}) ===", flush=True)
    proj = project_name(system)

    # b07 manages its own adapters (one per DB backend) — skip generic setup.
    if bench == "b07_database":
        try:
            mod = importlib.import_module(RUNNERS[bench])
            context = {"zone": ZONE, "label": label, "system": system, "project": proj}

            result = await mod.run(None, config, context)

            rows = result if isinstance(result, list) else [result]

            for row in rows:
                report.write_result(bench, row)

            print(f"  OK: {rows}", flush=True)

            return rows
        except Exception as error:
            print(f"  [FAIL] {bench}: {error}")
            traceback.print_exc()
            return None

    kwargs = {}

    if registry.is_bindizr(system):
        kwargs["notify_after_update"] = is_bindizr_notify_enabled(bench)

    try:
        adapter = registry.build_adapter(system, config, proj, **kwargs)
    except Exception as error:
        print(f"  [SKIP] cannot build adapter: {error}")
        return None

    sampler = None

    try:
        print("  setup...", flush=True)

        await adapter.setup()

        mod = importlib.import_module(RUNNERS[bench])

        # A runner that samples its own measured phase sets SELF_SAMPLES; a
        # second sampler would only add `docker stats` load to the same run.
        if not getattr(mod, "SELF_SAMPLES", False):
            ids = [adapter.compose.resolve_container_id(s) for s in adapter.resource_services]
            ids = [i for i in ids if i]
            sampler = ResourceSampler(ids, config["resources"]["sample_interval_secs"])
            sampler.start()

        context = {"zone": ZONE, "label": label, "system": system, "project": proj}

        result = await mod.run(adapter, config, context)

        resource_usage = sampler.stop() if sampler else {}
        sampler = None
        rows = result if isinstance(result, list) else [result]

        for row in rows:
            # Attach only metrics this wrapper actually sampled.
            if resource_usage.get("samples"):
                row.setdefault("peak_mem_mb", resource_usage["peak_mem_mb"])
                row.setdefault("avg_cpu_pct", resource_usage["avg_cpu_pct"])
            report.write_result(bench, row)

        print(f"  OK: {rows}", flush=True)

        return rows
    except Exception as error:
        print(f"  [FAIL] {bench}/{system}: {error}")
        traceback.print_exc()
        print("  --- container logs (tail) ---")
        for s in adapter.resource_services:
            print(adapter.compose.read_logs(s, tail=30))
        return None
    finally:
        # Workload failures must still stop observation and remove the test stack.
        if sampler:
            sampler.stop()
        print("  teardown...", flush=True)
        try:
            await adapter.teardown()
        except Exception as error:
            print(f"  teardown error: {error}")


async def main_async(args) -> None:
    """Run the selected systems and benchmarks and write their report."""
    config = settings.load()
    repeats = int(config.get("repeats", 1))
    benches = args.benchmarks or list(RUNNERS.keys())

    # Systems whose required CLI tool is missing (set by benchmark.sh preflight,
    # e.g. bind9_nsupdate when `nsupdate` is absent) are dropped from every
    # benchmark's matrix rather than attempted and failed.
    disabled = {s for s in os.environ.get("BENCH_DISABLE_SYSTEMS", "").split(",") if s}

    if disabled:
        print(f"Skipping systems (required tools unavailable): "
              f"{', '.join(sorted(disabled))}", flush=True)

    # Clear only the raw files for the benchmarks about to run, so repeated
    # invocations never accumulate stale/duplicate rows, while a subset re-run
    # (e.g. -b b07_database) preserves the other benchmarks' existing results.
    report.RAW_DIR.mkdir(parents=True, exist_ok=True)

    for bench in benches:
        f = report.RAW_DIR / f"{bench}.json"
        if f.exists():
            f.unlink()

    for bench in benches:
        systems = args.systems or config["benchmarks"].get(bench, [])
        systems = [s for s in systems
                   if (s == "bind9_native" or config["systems"].get(s, {}).get("enabled"))
                   and s not in disabled]

        for system in systems:
            for rep in range(repeats):
                if repeats > 1:
                    print(f"\n----- repeat {rep + 1}/{repeats} -----", flush=True)
                await run_one(bench, system, config)

    print("\n=== building report ===")
    report.write_report(envmod.collect(config), config)
    print(f"Report written to {settings.RESULTS_DIR}")
    print(f"To re-run a subset into this same directory:\n"
          f"  BENCH_RESULTS_DIR={settings.RESULTS_DIR.name} python3 orchestrator.py -b <bench>")


def main() -> None:
    """Parse benchmark CLI options and start the async orchestrator."""
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
