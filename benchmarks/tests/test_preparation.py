"""Prepared-zone workloads must stop when bulk import reports rejected records."""
from contextlib import ExitStack
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import dig
from runners import b04_axfr, b05_ixfr, b06_large_zone, b08_query_perf, b09_resource_usage


class PreparationTests(IsolatedAsyncioTestCase):
    config = dict(seed=1, sizes=[5], ixfr_baseline=5, ixfr_change_sizes=[5],
                  query=dict(zone_size=5, concurrency=1, duration_secs=1),
                  propagation=dict(poll_interval_ms=0, timeout_secs=1))
    context = dict(zone="bench.example.", label="test")

    async def test_partial_and_total_preparation_failure_prevent_measurement(self):
        """Even queryable samples or complete XFR probes cannot repair a rejected import."""
        for module in (b04_axfr, b05_ixfr, b06_large_zone, b08_query_perf, b09_resource_usage):
            for errors in (1, 5):
                adapter = SimpleNamespace(
                    delete_zone=AsyncMock(), create_zone=AsyncMock(), import_records=AsyncMock(),
                    bulk_errors=errors, xfr_endpoint=lambda: SimpleNamespace(host="127.0.0.1", port=1))
                sampler = Mock(__enter__=Mock(), __exit__=Mock(return_value=False))
                with self.subTest(runner=module.__name__, errors=errors), ExitStack() as stack:
                    stack.enter_context(patch.object(dig, "zone_is_cleared", AsyncMock(return_value=True)))
                    count = stack.enter_context(patch.object(dig, "count_axfr_records", AsyncMock(return_value=7)))
                    axfr = stack.enter_context(patch.object(dig, "axfr", AsyncMock()))
                    ixfr = stack.enter_context(patch.object(dig, "ixfr", AsyncMock()))
                    visible = stack.enter_context(patch.object(dig, "first_unqueryable", AsyncMock(return_value=None)))
                    query = stack.enter_context(patch.object(b08_query_perf.dnsquery, "query_load", AsyncMock()))
                    stack.enter_context(patch.object(b06_large_zone, "sampler_for", return_value=sampler))
                    resource_sampler = stack.enter_context(patch.object(b09_resource_usage, "sampler_for"))
                    with self.assertRaisesRegex(RuntimeError, f"failed for {errors} records"):
                        await module.run(adapter, self.config, self.context)
                    adapter.import_records.assert_awaited_once()
                    count.assert_not_awaited()
                    axfr.assert_not_awaited()
                    ixfr.assert_not_awaited()
                    visible.assert_not_awaited()
                    query.assert_not_awaited()
                    resource_sampler.assert_not_called()
                    if module is b06_large_zone:
                        sampler.__exit__.assert_called_once()

    async def test_failed_ixfr_change_batch_stops_before_propagation_or_transfer(self):
        """A successful baseline cannot make a partially applied change batch valid."""
        for errors in (1, 5):
            adapter = SimpleNamespace(
                delete_zone=AsyncMock(), create_zone=AsyncMock(), bulk_errors=0,
                xfr_endpoint=lambda: SimpleNamespace(host="127.0.0.1", port=1))
            imports = 0

            async def import_records(*args):
                """Accept the baseline and reject part or all of the change batch."""
                nonlocal imports
                imports += 1
                adapter.bulk_errors = errors if imports == 2 else 0

            adapter.import_records = AsyncMock(side_effect=import_records)
            with self.subTest(errors=errors), \
                    patch.object(dig, "count_axfr_records", AsyncMock(return_value=8)) as count, \
                    patch.object(b05_ixfr, "_query_serial", AsyncMock(return_value=1)) as serial, \
                    patch.object(dig, "ixfr", AsyncMock()) as transfer, \
                    patch.object(b05_ixfr.asyncio, "sleep", AsyncMock()):
                with self.assertRaisesRegex(RuntimeError, f"IXFR change batch failed for {errors} records"):
                    await b05_ixfr.run(adapter, self.config, self.context)
                self.assertEqual(adapter.import_records.await_count, 2)
                self.assertEqual(count.await_count, 2)  # Baseline probes only.
                serial.assert_awaited_once()
                transfer.assert_not_awaited()
