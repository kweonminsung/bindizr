"""A size-labelled creation workload requires successful prepopulation."""
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ab import largezone_sweep


class SweepTests(IsolatedAsyncioTestCase):
    async def test_partial_and_total_prepopulation_failure_stop_before_measurement(self):
        """Do not label an undersized zone with the requested prepopulation count."""
        for errors in (1, 3):
            adapter = SimpleNamespace(delete_zone=AsyncMock(), create_zone=AsyncMock(),
                                      import_records=AsyncMock(), bulk_errors=errors)
            with self.subTest(errors=errors), \
                    patch.object(largezone_sweep, "generate", return_value=[{"name": "a"} for _ in range(3)]), \
                    patch.object(largezone_sweep.loadgen, "run_closed_loop", AsyncMock()) as workload:
                with self.assertRaisesRegex(RuntimeError, f"prepopulating 3 records failed for {errors} records"):
                    await largezone_sweep.measure(adapter, 3)
                workload.assert_not_awaited()

    async def test_successful_prepopulation_keeps_the_measured_result(self):
        """Run the existing creation workload when the prepared zone is complete."""
        adapter = SimpleNamespace(delete_zone=AsyncMock(), create_zone=AsyncMock(),
                                  import_records=AsyncMock(), bulk_errors=0)
        recorder = SimpleNamespace(errors=2, summary=lambda: dict(tps=10, p95_ms=3, p99_ms=4))
        with patch.object(largezone_sweep, "generate", return_value=[{"name": "a"}]), \
                patch.object(largezone_sweep.loadgen, "run_closed_loop", AsyncMock(return_value=recorder)) as workload:
            self.assertEqual(await largezone_sweep.measure(adapter, 3),
                             dict(prepop=3, create_tps=10, p95_ms=3, p99_ms=4, errors=2))
        workload.assert_awaited_once()
