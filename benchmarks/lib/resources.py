"""Background sampler for container CPU / memory / net / block IO.

Used by Benchmark 9 and as an inline observer during other benchmarks. Parses
`docker stats` percentage/byte strings into numeric samples and reports peak +
average.
"""
from __future__ import annotations

import re
import threading

from . import dockerutil


def _to_bytes(s: str) -> float:
    s = s.strip()
    # Docker uses a lowercase SI 'k' for NET/BLOCK IO (e.g. "2.48kB") and binary
    # MiB/GiB for memory; accept both.
    m = re.match(r"([\d.]+)\s*([kKMGT]?i?B)", s)
    if not m:
        return 0.0
    val, unit = float(m.group(1)), m.group(2)
    scale = {
        "B": 1,
        "KiB": 1024,
        "MiB": 1024**2,
        "GiB": 1024**3,
        "TiB": 1024**4,
        "kB": 1000,
        "KB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "TB": 1000**4,
    }
    return val * scale.get(unit, 1)


def sampler_for(adapter, cfg: dict) -> "ResourceSampler":
    """Sampler over the containers an adapter declares measurable."""
    ids = [adapter.compose.container_id(s) for s in adapter.resource_services]
    return ResourceSampler([i for i in ids if i],
                           cfg["resources"]["sample_interval_secs"])


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
        # One `docker stats` snapshot per tick covers every container; stamp each
        # sample with its tick so summary() can total the stack per interval.
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

    def _by_tick(self, field: str) -> list[float]:
        """Stack total per tick. Averaging the flat sample list instead would
        divide a multi-container stack's cost by its container count."""
        totals: dict[int, float] = {}
        for s in self.samples:
            totals[s["tick"]] = totals.get(s["tick"], 0.0) + s[field]
        return list(totals.values())

    def _by_container(self, field: str) -> dict[str, list[float]]:
        out: dict[str, list[float]] = {}
        for s in self.samples:
            out.setdefault(s["name"], []).append(s[field])
        return out

    def summary(self) -> dict:
        if not self.samples:
            return {"peak_cpu_pct": 0, "avg_cpu_pct": 0, "cpu_by_container": {},
                    "peak_mem_mb": 0, "avg_mem_mb": 0, "net_tx_mb": 0, "samples": 0}

        cpu_totals = self._by_tick("cpu_pct")
        mem_totals = self._by_tick("mem_bytes")

        # net_tx is Docker's cumulative counter, so the window's traffic is the
        # per-container rise across it — an absolute max would also count the
        # setup/import/propagation bytes sent before sampling started.
        net_tx = sum(v[-1] - v[0] for v in self._by_container("net_tx").values())

        return {
            "peak_cpu_pct": round(max(cpu_totals), 2),
            "avg_cpu_pct": round(sum(cpu_totals) / len(cpu_totals), 2),
            # Per-container split, so a stack total can be attributed.
            "cpu_by_container": {name: round(sum(v) / len(v), 2)
                                 for name, v in self._by_container("cpu_pct").items()},
            "peak_mem_mb": round(max(mem_totals) / 1024**2, 2),
            "mem_by_container": {name: round(max(v) / 1024**2, 2)
                                 for name, v in self._by_container("mem_bytes").items()},
            "avg_mem_mb": round(sum(mem_totals) / len(mem_totals) / 1024**2, 2),
            "net_tx_mb": round(net_tx / 1024**2, 2),
            "samples": len(self.samples),
        }
