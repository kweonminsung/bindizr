"""Closed-loop async load generator.

A fixed pool of `concurrency` workers repeatedly invoke an async `step(seq)`
coroutine as fast as they can for `duration_secs`. Latency of each call is timed
and recorded; a leading `warmup_secs` window is executed but not measured.

Closed-loop (fixed concurrency) is chosen over open-loop because the systems
under test have wildly different endpoints/payloads and we compare them under an
identical, bounded client load rather than chasing each system's raw ceiling.
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
    rec = LatencyRecorder()
    counter = itertools.count()
    clock = time.monotonic
    warmup_until = clock() + warmup_secs
    measure_start = warmup_until
    measure_end = measure_start + duration_secs
    rec.started_at = measure_start

    async def worker() -> None:
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
            if t1 >= warmup_until:  # only record post-warmup
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
