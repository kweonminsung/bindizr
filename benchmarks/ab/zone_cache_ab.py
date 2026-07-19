#!/usr/bin/env python3
"""A/B the Bindizr `zone_cache` (rendered-zone-by-serial cache) on the AXFR path.

The suite's Benchmark 4 pulls AXFR from the BIND9 *secondary*, so it never
exercises Bindizr's own XFR server. Here we AXFR straight at Bindizr from inside
the bind9 container — the only client its secondary ACL admits — so the cache is
actually on the path.

At a fixed serial the first AXFR is a cache miss (reads the DB) and every
subsequent one should hit. We report cold (1st) vs warm (rest) transfer times
with the cache off and on.
"""
from __future__ import annotations

import asyncio
import re
import statistics
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from adapters import registry  # noqa: E402
from datasets.gen_dataset import generate  # noqa: E402

ZONE = "bench.example."
RECORDS = 10_000
AXFRS = 8

QUERY_TIME = re.compile(r";; Query time: (\d+) msec")


def axfr_from_bind9(cid: str) -> tuple[float | None, int]:
    """Run dig AXFR inside the bind9 container; return (query_ms, record_lines)."""
    p = subprocess.run(
        ["docker", "exec", cid, "dig", "@bindizr", "-p", "53",
         ZONE.rstrip("."), "AXFR", "+tcp", "+time=60"],
        capture_output=True, text=True, timeout=120,
    )
    ms = None
    times = QUERY_TIME.findall(p.stdout)
    if times:
        # AXFR may span messages; dig prints one Query time — take the last.
        ms = float(times[-1])
    lines = [ln for ln in p.stdout.splitlines() if ln and not ln.startswith(";")]
    return ms, len(lines)


async def run_variant(zone_cache: bool) -> dict:
    label = "on" if zone_cache else "off"
    proj = f"bench-zc-{label}"
    adapter = registry.build("bindizr", {"resources": {"sample_interval_secs": 1}}, proj,
                             notify_after_update=False, zone_cache=zone_cache)
    try:
        print(f"[zone_cache={label}] setup...", flush=True)
        await adapter.setup()
        await adapter.create_zone(ZONE)
        print(f"[zone_cache={label}] importing {RECORDS} records...", flush=True)
        await adapter.bulk_import(ZONE, generate(RECORDS, 1337, ZONE))

        bind9_cid = adapter.compose.container_id("bind9")
        if not bind9_cid:
            raise RuntimeError("bind9 container not found")

        samples: list[float] = []
        counts: list[int] = []
        for i in range(AXFRS):
            ms, n = axfr_from_bind9(bind9_cid)
            if ms is None:
                raise RuntimeError(f"AXFR failed / refused (got {n} record lines)")
            samples.append(ms)
            counts.append(n)
            print(f"  axfr #{i + 1}: {ms:.0f} ms ({n} lines)", flush=True)

        cold, warm = samples[0], samples[1:]
        return {
            "zone_cache": label,
            "records": counts[0],
            "cold_ms": cold,
            "warm_mean_ms": statistics.fmean(warm),
            "warm_median_ms": statistics.median(warm),
            "warm_min_ms": min(warm),
            "all_ms": samples,
        }
    finally:
        await adapter.teardown()


async def main() -> None:
    results = [await run_variant(False), await run_variant(True)]
    off, on = results
    print("\n=== zone_cache A/B (AXFR from bind9 -> bindizr, "
          f"{off['records']} record lines, {AXFRS} transfers) ===")
    print(f"{'metric':<18}{'off':>12}{'on':>12}{'delta':>12}")
    print("-" * 54)
    for k in ("cold_ms", "warm_mean_ms", "warm_median_ms", "warm_min_ms"):
        a, b = off[k], on[k]
        delta = f"{(b - a) / a * 100:+.1f}%" if a else "n/a"
        print(f"{k:<18}{a:>12.1f}{b:>12.1f}{delta:>12}")
    print(f"\noff samples: {[round(x) for x in off['all_ms']]}")
    print(f"on  samples: {[round(x) for x in on['all_ms']]}")


if __name__ == "__main__":
    asyncio.run(main())
