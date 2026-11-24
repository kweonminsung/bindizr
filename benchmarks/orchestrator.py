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
import shlex
import signal
import traceback

from adapters import registry
from lib import docker
from lib import env as envmod
from lib import report, settings
from lib.resources import load_sampler

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
    """Return whether this workload needs bindizr to send NOTIFY."""
    override = os.environ.get("BENCH_BINDIZR_NOTIFY")
    if override is not None:
        return override.lower() == "true"
    return bench not in NOTIFY_OFF_BENCHMARKS


async def run_one(bench: str, system: str, config: dict) -> list[dict]:
    """Set up one system, run its selected workload, and collect the result."""
    label = settings.system_label(config, system)
    print(f"\n=== {bench} :: {label} ({system}) ===", flush=True)
    context = {"zone": ZONE, "label": label, "system": system, "project": docker.project_name(system)}
    adapter = None
    rows: list[dict] = []
    phase = "setup"

    try:
        runner = importlib.import_module(RUNNERS[bench])
        # B07 owns setup and teardown for each of its DB backends.
        if bench != "b07_database":
            kwargs = {}
            if registry.is_bindizr(system):
                kwargs["notify_after_update"] = is_bindizr_notify_enabled(bench)
            adapter = registry.build_adapter(system, config, context["project"], **kwargs)
            print("  setup...", flush=True)
            await adapter.setup()

        phase = "measurement"
        # A runner that samples its own measured phase sets SELF_SAMPLES; a
        # second sampler would only add `docker stats` load to the same run.
        resource_usage = {}
        if adapter is not None and not getattr(runner, "SELF_SAMPLES", False):
            with load_sampler(adapter, config) as sampler:
                result = await runner.run(adapter, config, context)
            resource_usage = sampler.summary()
        else:
            result = await runner.run(adapter, config, context)
        rows = result if isinstance(result, list) else [result]

        for row in rows:
            if row.get("status") != "FAILED" and resource_usage.get("samples"):
                row.setdefault("peak_mem_mb", resource_usage["peak_mem_mb"])
                row.setdefault("avg_cpu_pct", resource_usage["avg_cpu_pct"])
    except Exception as error:
        print(f"  [FAIL] {bench}/{system} during {phase}: {error}")
        traceback.print_exc()
        rows = [{"system": label, "status": "FAILED", "phase": phase, "error": str(error)}]
        if adapter is not None:
            print("  --- container logs (tail) ---")
            for service in adapter.resource_services:
                try:
                    print(adapter.compose.read_logs(service, tail=30))
                except Exception as log_error:
                    print(f"  couldn't read {service} logs: {log_error}")
    finally:
        if adapter is not None:
            print("  teardown...", flush=True)
            try:
                await adapter.teardown()
            except Exception as error:
                print(f"  [FAIL] {bench}/{system} during teardown: {error}")
                rows.append({"system": label, "status": "FAILED",
                             "phase": "teardown", "error": str(error)})

    print(f"  Result: {rows}", flush=True)

    return rows


async def main_async(args) -> None:
    """Run the selected systems and benchmarks and write their report."""
    config = settings.load()
    repeats = int(config.get("repeats", 1))
    benches = args.benchmarks or list(RUNNERS.keys())

    # Systems whose required CLI tool is missing (set by benchmark.sh preflight,
    # e.g. bind9_nsupdate when `nsupdate` is absent) are dropped from every
    # benchmark's matrix rather than attempted and failed.
    disabled = {system for system in os.environ.get("BENCH_DISABLE_SYSTEMS", "").split(",") if system}

    if disabled:
        print(f"Skipping systems (required tools unavailable): "
              f"{', '.join(sorted(disabled))}", flush=True)

    with settings.results_directory() as results_dir:
        # Keep the previous reports and raw rows usable if interrupted.
        results: dict[str, list[dict]] = {bench: [] for bench in benches}
        for bench, rows in results.items():
            systems = args.systems or config["benchmarks"].get(bench, [])
            systems = [system for system in systems
                       if (system == "bind9_native" or config["systems"].get(system, {}).get("enabled"))
                       and system not in disabled]

            for system in systems:
                for rep in range(repeats):
                    if repeats > 1:
                        print(f"\n----- repeat {rep + 1}/{repeats} -----", flush=True)
                    rows.extend(await run_one(bench, system, config))

        print("\n=== building report ===")
        environment = envmod.collect(config)
        for bench, rows in results.items():
            report.replace_results(results_dir, bench, rows)
        report.write_report(results_dir, environment, config)
        print(f"Report written to {results_dir}")
        quoted = shlex.quote(str(results_dir))
        print(f"To re-run a subset into this same directory:\n"
              f"  BENCH_RESULTS_DIR={quoted} python3 orchestrator.py -b <bench>")


async def run_until_stopped(args) -> int:
    """Cancel once on an interrupt and wait for the active adapter to tear down."""
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    stop_signal = None

    def stop(signum: signal.Signals) -> None:
        """Request cancellation only once so later signals cannot interrupt teardown."""
        nonlocal stop_signal
        if stop_signal is None:
            stop_signal = signum
            task.cancel()

    signals = (signal.SIGINT, signal.SIGTERM)
    for signum in signals:
        loop.add_signal_handler(signum, stop, signum)
    try:
        await main_async(args)
    except asyncio.CancelledError:
        if stop_signal is None:
            raise
        return 128 + stop_signal
    finally:
        for signum in signals:
            loop.remove_signal_handler(signum)
    return 0


def main() -> None:
    """Parse benchmark CLI options and start the async orchestrator."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--benchmarks", nargs="*", choices=RUNNERS,
                        help="benchmark keys (default: all)")
    parser.add_argument("-s", "--systems", nargs="*", help="system keys (default: per-benchmark)")
    parser.add_argument("--list", action="store_true", help="list benchmarks and exit")
    args = parser.parse_args()

    if args.list:
        for benchmark in RUNNERS:
            print(benchmark)
        return

    raise SystemExit(asyncio.run(run_until_stopped(args)))


if __name__ == "__main__":
    main()
