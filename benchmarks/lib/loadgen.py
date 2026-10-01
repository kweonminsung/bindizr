"""Run `step(seq)` with fixed concurrency, measuring latency after an unmeasured warmup.

A closed loop gives systems with different endpoints and payloads the same
bounded client load for `duration_secs`.
"""
from __future__ import annotations

import asyncio
import itertools
import time
from typing import Awaitable, Callable

from .metrics import LatencyRecorder

Step = Callable[[int], Awaitable[bool]]


async def run_closed_loop(
    step: Step,
    concurrency: int,
    duration_secs: float,
    warmup_secs: float = 0.0,
) -> LatencyRecorder:
    """Measure an async workload with fixed concurrency and an unmeasured warmup."""
    rec = LatencyRecorder()
    counter = itertools.count()
    clock = time.monotonic
    warmup_until = clock() + warmup_secs
    measure_start = warmup_until
    measure_end = measure_start + duration_secs
    rec.started_at = measure_start

    async def worker() -> None:
        """Run workload steps and record their latency and success."""
        while True:
            now = clock()
            if now >= measure_end:
                return
            seq = next(counter)
            t0 = clock()
            try:
                ok = await step(seq)
            except Exception:
                ok = False
            t1 = clock()
            if t1 >= warmup_until:
                rec.record(t1 - t0, ok=ok)

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
    await asyncio.gather(*workers)
    rec.ended_at = clock()
    return rec


async def run_n(step: Step, concurrency: int, total: int) -> LatencyRecorder:
    """Run exactly `total` steps across `concurrency` workers (for bulk import)."""
    rec = LatencyRecorder()
    clock = time.monotonic
    queue: asyncio.Queue[int] = asyncio.Queue()
    for i in range(total):
        queue.put_nowait(i)
    rec.started_at = clock()

    async def worker() -> None:
        """Run workload steps and record their latency and success."""
        while True:
            try:
                seq = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            t0 = clock()
            try:
                ok = await step(seq)
            except Exception:
                ok = False
            rec.record(clock() - t0, ok=ok)

    await asyncio.gather(*[worker() for _ in range(concurrency)])
    rec.ended_at = clock()
    return rec
