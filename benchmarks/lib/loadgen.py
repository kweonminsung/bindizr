"""Measure `step(seq)` under fixed concurrency after an unmeasured warmup.

A closed loop keeps client load bounded for `duration_secs` across all systems.
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
    recorder = LatencyRecorder()
    counter = itertools.count()
    clock = time.monotonic
    warmup_until = clock() + warmup_secs
    measure_start = warmup_until
    measure_end = measure_start + duration_secs
    recorder.started_at = measure_start

    async def worker() -> None:
        """Run workload steps and record their latency and success."""
        while True:
            now = clock()

            if now >= measure_end:
                return

            seq = next(counter)
            started = clock()

            try:
                ok = await step(seq)
            except Exception:
                ok = False

            # Warmup work runs normally but contributes no measured samples.
            finished = clock()

            if finished >= warmup_until:
                recorder.track_latency(finished - started, ok=ok)

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]

    await asyncio.gather(*workers)

    recorder.ended_at = clock()

    return recorder


async def run_n(step: Step, concurrency: int, total: int) -> LatencyRecorder:
    """Run exactly `total` steps across `concurrency` workers (for bulk import)."""
    recorder = LatencyRecorder()
    clock = time.monotonic
    queue: asyncio.Queue[int] = asyncio.Queue()

    for i in range(total):
        queue.put_nowait(i)

    recorder.started_at = clock()

    async def worker() -> None:
        """Run workload steps and record their latency and success."""
        while True:
            try:
                seq = queue.get_nowait()
            except asyncio.QueueEmpty:
                return

            started = clock()

            try:
                ok = await step(seq)
            except Exception:
                ok = False

            recorder.track_latency(clock() - started, ok=ok)

    await asyncio.gather(*[worker() for _ in range(concurrency)])

    recorder.ended_at = clock()

    return recorder
