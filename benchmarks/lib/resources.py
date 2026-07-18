"""Background sampler for container CPU / memory / net / block IO.

Used by Benchmark 9 and as an inline observer during other benchmarks. Parses
`docker stats` percentage/byte strings into numeric samples and reports peak +
average.
"""
from __future__ import annotations

import re
import threading
import time

from . import dockerutil


def _to_bytes(s: str) -> float:
    s = s.strip()
    m = re.match(r"([\d.]+)\s*([KMGT]?i?B)", s)
    if not m:
        return 0.0
    val, unit = float(m.group(1)), m.group(2)
    scale = {
        "B": 1,
        "KiB": 1024,
        "MiB": 1024**2,
        "GiB": 1024**3,
        "TiB": 1024**4,
        "KB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "TB": 1000**4,
    }
    return val * scale.get(unit, 1)


class ResourceSampler:
    def __init__(self, container_ids: list[str], interval: float = 1.0):
        self.ids = container_ids
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.samples: list[dict] = []

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        # One `docker stats` snapshot per tick covers every container at once, so
        # stamp each sample with its tick to let summary() total a stack across
        # containers per interval (see summary()).
        tick = 0
        while not self._stop.is_set():
            for row in dockerutil.stats(self.ids):
                cpu = float(row.get("CPUPerc", "0%").rstrip("%") or 0)
                mem_use = _to_bytes(row.get("MemUsage", "0B").split("/")[0])
                net = row.get("NetIO", "0B / 0B").split("/")
                blk = row.get("BlockIO", "0B / 0B").split("/")
                self.samples.append(
                    {
                        "tick": tick,
                        "name": row.get("Name", ""),
                        "cpu_pct": cpu,
                        "mem_bytes": mem_use,
                        "net_rx": _to_bytes(net[0]),
                        "net_tx": _to_bytes(net[1]) if len(net) > 1 else 0,
                        "blk_r": _to_bytes(blk[0]),
                        "blk_w": _to_bytes(blk[1]) if len(blk) > 1 else 0,
                    }
                )
            tick += 1
            self._stop.wait(self.interval)

    def stop(self) -> dict:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        return self.summary()

    def summary(self) -> dict:
        if not self.samples:
            return {"peak_cpu_pct": 0, "avg_cpu_pct": 0, "peak_mem_mb": 0, "avg_mem_mb": 0}
        cpus = [s["cpu_pct"] for s in self.samples]

        # Per-container average CPU. `avg_cpu_pct` above pools every container into
        # one mean, which understates a multi-container stack (e.g. Bindizr's near-
        # idle control plane averaged with the BIND9 that actually serves queries).
        # Keep the pooled value for back-compat but expose the breakdown too.
        by_container: dict[str, list[float]] = {}
        for s in self.samples:
            by_container.setdefault(s["name"], []).append(s["cpu_pct"])
        cpu_by_container = {
            name: round(sum(v) / len(v), 2) for name, v in by_container.items()
        }

        # Memory peak/avg are the whole stack's total, not one container. Taking
        # max()/mean() over the flat sample list would report only the largest
        # single container (peak) and the stack total divided by container count
        # (avg), understating a multi-container stack. Sum each tick across
        # containers first, then peak = max tick total, avg = mean tick total.
        # Single-container systems have one sample per tick, so this collapses to
        # the original values.
        mem_by_tick: dict[int, float] = {}
        for s in self.samples:
            mem_by_tick[s["tick"]] = mem_by_tick.get(s["tick"], 0.0) + s["mem_bytes"]
        mem_totals = list(mem_by_tick.values())

        return {
            "peak_cpu_pct": round(max(cpus), 2),
            "avg_cpu_pct": round(sum(cpus) / len(cpus), 2),
            "cpu_by_container": cpu_by_container,
            "peak_mem_mb": round(max(mem_totals) / 1024**2, 2),
            "avg_mem_mb": round(sum(mem_totals) / len(mem_totals) / 1024**2, 2),
            "peak_net_tx_mb": round(max(s["net_tx"] for s in self.samples) / 1024**2, 2),
            "samples": len(self.samples),
        }
