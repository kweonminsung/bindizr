"""Preserve latency summary values while sorting one snapshot per summary."""
from pathlib import Path
import sys
from unittest import TestCase
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.metrics import LatencyRecorder


class MetricsTests(TestCase):
    def test_summary_reuses_one_sorted_snapshot_without_mutating_samples(self):
        """Verify that percentiles exclude failed requests and retain sample order."""
        recorder = LatencyRecorder(latencies_ms=[9.0, 1.0, 5.0, 3.0], errors=1, started_at=0, ended_at=1)
        with patch("lib.metrics.sorted", wraps=sorted, create=True) as sort:
            summary = recorder.summary()
        self.assertEqual(sort.call_count, 1)
        self.assertEqual(recorder.latencies_ms, [9.0, 1.0, 5.0, 3.0])
        self.assertEqual(summary, {
            "count": 4, "errors": 1, "tps": 4.0, "rps": 5.0, "error_rate": 0.2,
            "p50_ms": 4.0, "p95_ms": 8.4, "p99_ms": 8.88, "max_ms": 9.0, "mean_ms": 4.5,
        })

    def test_summary_preserves_empty_and_single_sample_percentiles(self):
        """Verify that empty measurements stay zero and one sample defines every percentile."""
        for samples, expected in [([], 0.0), ([2.0], 2.0)]:
            with self.subTest(samples=samples):
                summary = LatencyRecorder(latencies_ms=samples, errors=1, started_at=0, ended_at=1).summary()
                for key in ("p50_ms", "p95_ms", "p99_ms", "max_ms", "mean_ms"):
                    self.assertEqual(summary[key], expected, key)
