"""Latency/throughput measurement primitives.

`LatencyRecorder` collects per-request latencies (in seconds) and success/error
counts, then computes TPS, requests/sec, and p50/p95/p99 percentiles — the
metrics required by Benchmarks 1, 3, 9.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field


@dataclass
class LatencyRecorder:
    latencies_ms: list[float] = field(default_factory=list)
    errors: int = 0
    started_at: float | None = None
    ended_at: float | None = None

    def record(self, latency_secs: float, ok: bool = True) -> None:
        if ok:
            self.latencies_ms.append(latency_secs * 1000.0)
        else:
            self.errors += 1

    @property
    def count(self) -> int:
        return len(self.latencies_ms)

    @property
    def total(self) -> int:
        return self.count + self.errors

    @property
    def elapsed_secs(self) -> float:
        if self.started_at is None or self.ended_at is None:
            return 0.0
        return max(self.ended_at - self.started_at, 1e-9)

    def percentile(self, p: float) -> float:
        if not self.latencies_ms:
            return 0.0
        data = sorted(self.latencies_ms)
        k = (len(data) - 1) * (p / 100.0)
        lo = int(k)
        hi = min(lo + 1, len(data) - 1)
        return data[lo] + (data[hi] - data[lo]) * (k - lo)

    def summary(self) -> dict[str, float]:
        tps = self.count / self.elapsed_secs if self.elapsed_secs else 0.0
        return {
            "count": self.count,
            "errors": self.errors,
            "tps": round(tps, 2),
            "rps": round(self.total / self.elapsed_secs, 2) if self.elapsed_secs else 0.0,
            "error_rate": round(self.errors / self.total, 5) if self.total else 0.0,
            "p50_ms": round(self.percentile(50), 3),
            "p95_ms": round(self.percentile(95), 3),
            "p99_ms": round(self.percentile(99), 3),
            "max_ms": round(max(self.latencies_ms), 3) if self.latencies_ms else 0.0,
            "mean_ms": round(statistics.fmean(self.latencies_ms), 3) if self.latencies_ms else 0.0,
        }
