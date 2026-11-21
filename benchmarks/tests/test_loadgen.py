"""Keep warmup samples out while draining requests accepted during measurement."""
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import loadgen


class LoadgenTests(IsolatedAsyncioTestCase):
    async def test_warmup_started_requests_are_excluded_for_success_and_failure(self):
        """Verify that warmup-started requests stay excluded even when they finish during measurement."""
        for ok in (True, False):
            now = 0.0

            async def step(seq):
                """Finish the warmup request after the measurement window starts."""
                nonlocal now
                now = 2.0
                return ok

            with self.subTest(ok=ok), patch.object(
                    loadgen, "time", SimpleNamespace(monotonic=lambda: now)):
                recorder = await loadgen.run_closed_loop(step, 1, 1.0, warmup_secs=1.0)
            self.assertEqual(recorder.total, 0)

    async def test_boundary_started_request_is_measured_and_drained_after_deadline(self):
        """Verify that a boundary-started request is measured and drained after the deadline."""
        now = 0.0
        starts = []

        async def step(seq):
            """Finish one warmup request at the boundary, then drain a measured request."""
            nonlocal now
            starts.append(now)
            now += 1.0 if seq == 0 else 2.0
            return True

        with patch.object(loadgen, "time", SimpleNamespace(monotonic=lambda: now)):
            recorder = await loadgen.run_closed_loop(step, 1, 1.0, warmup_secs=1.0)
        self.assertEqual(starts, [0.0, 1.0])
        self.assertEqual(recorder.count, 1)
        self.assertEqual(recorder.latencies_ms, [2000.0])
        self.assertEqual(recorder.elapsed_secs, 2.0)
