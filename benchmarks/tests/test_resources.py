"""Resource ownership regressions; no Docker daemon or benchmark stack required."""
import asyncio
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import importlib
import io
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import docker, resources


class SamplerTests(unittest.TestCase):
    def test_observation_error_preserves_workload_failure_and_cancellation(self):
        for failure in (ValueError("workload failed"), asyncio.CancelledError()):
            with self.subTest(failure=type(failure).__name__):
                sampler = resources.ResourceSampler(["test"], 0.01)
                with patch.object(docker, "read_stats", side_effect=OSError("observation failed")), \
                        self.assertLogs("lib.resources", level="ERROR"), \
                        self.assertRaises(type(failure)) as caught:
                    with sampler:
                        sampler._thread.join(1)
                        raise failure
                self.assertIs(caught.exception, failure)
                self.assertFalse(sampler._thread.is_alive())

    def test_stop_waits_for_the_snapshot_before_returning(self):
        entered, release, returned = (threading.Event() for _ in range(3))

        def snapshot(ids):
            entered.set()
            release.wait(10)
            return []

        sampler = resources.ResourceSampler(["test"], 0.01)
        stopper = threading.Thread(target=lambda: (sampler.stop(), returned.set()))
        with patch.object(docker, "read_stats", side_effect=snapshot):
            sampler.start()
            try:
                self.assertTrue(entered.wait(1))
                stopper.start()
                # The old five-second join returned while its observer was still alive.
                self.assertFalse(returned.wait(5.1))
            finally:
                release.set()
                if stopper.ident is not None:
                    stopper.join(2)
                sampler.stop()
            self.assertTrue(returned.is_set())
            self.assertFalse(sampler._thread.is_alive())

    def test_docker_timeout_stops_the_child_and_reaches_the_owner(self):
        run = subprocess.run

        def slow_docker(command, **kwargs):
            return run([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)

        sampler = resources.ResourceSampler(["test"], 0.01)
        with patch.object(docker, "STATS_TIMEOUT_SECS", 0.05), \
                patch.object(docker.subprocess, "run", side_effect=slow_docker):
            sampler.start()
            sampler._thread.join(2)
            with self.assertRaises(subprocess.TimeoutExpired) as failure:
                sampler.stop()
        self.assertEqual(failure.exception.timeout, 0.05)
        self.assertFalse(sampler._thread.is_alive())


class RunnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_every_self_sampling_scope_stops_on_failure_and_cancellation(self):
        modules = {name: importlib.import_module("runners." + name) for name in
                   ("b02_bulk_import", "b06_large_zone", "b07_database", "b09_resource_usage")}
        config = {
            "resources": {"sample_interval_secs": 0.01}, "sizes": [1], "seed": 1,
            "query": {"zone_size": 1, "concurrency": 1, "duration_secs": 0.01},
            "propagation": {"poll_interval_ms": 1, "timeout_secs": 1},
            "crud": {"concurrency": 1, "duration_secs": 0.01,
                     "warmup_secs": 0, "records_prepopulate": 1},
        }
        context = {"zone": "test.example.", "label": "test"}
        adapter = SimpleNamespace(
            config=config, create_zone=AsyncMock(), delete_zone=AsyncMock(),
            import_records=AsyncMock(), bulk_errors=0, create_record=AsyncMock(return_value="record"),
            xfr_endpoint=lambda: SimpleNamespace(host="127.0.0.1", port=1),
            dns_endpoint=lambda: SimpleNamespace(host="127.0.0.1", port=1),
        )
        samplers = []

        def sampler_for(*args):
            sampler = resources.ResourceSampler([], 0.01)
            samplers.append(sampler)
            self.addCleanup(sampler.stop)
            return sampler

        record = {"name": "a", "type": "A", "value": "192.0.2.1"}
        with ExitStack() as patches:
            for module in modules.values():
                patches.enter_context(patch.object(module, "sampler_for", side_effect=sampler_for))
            for name in ("b07_database", "b09_resource_usage"):
                patches.enter_context(patch.object(modules[name], "generate", return_value=[record]))
            patches.enter_context(patch.object(modules["b09_resource_usage"].dig,
                                               "first_unqueryable", return_value=None))
            for failure in (RuntimeError("workload failed"), asyncio.CancelledError()):
                load = AsyncMock(side_effect=failure)
                patches.enter_context(patch.object(modules["b07_database"].loadgen,
                                                   "run_closed_loop", load))
                patches.enter_context(patch.object(modules["b09_resource_usage"].dnsquery,
                                                   "query_load", load))
                cases = [
                    lambda: modules["b02_bulk_import"]._measure(
                        adapter, context["zone"], 1, "test", load, lambda: 0),
                    lambda: modules["b06_large_zone"].run(adapter, config, context),
                    lambda: modules["b07_database"]._bench_backend(
                        adapter, config, context["zone"], "sqlite", "test"),
                    lambda: modules["b07_database"]._bulk_backend(
                        adapter, config, context["zone"], "sqlite", 1, "test"),
                    lambda: modules["b09_resource_usage"].run(adapter, config, context),
                ]
                for index, execute in enumerate(cases):
                    with self.subTest(scope=index, failure=type(failure).__name__):
                        adapter.delete_zone.side_effect = failure if index == 1 else None
                        adapter.import_records.side_effect = failure if index == 3 else None
                        with self.assertRaises(type(failure)):
                            await execute()
                        self.assertFalse(samplers[-1]._thread.is_alive())

    async def test_observation_failure_cannot_skip_adapter_teardown(self):
        import orchestrator

        adapter = SimpleNamespace(setup=AsyncMock(), teardown=AsyncMock(),
                                  resource_services=[], compose=Mock())
        sampler = Mock()
        sampler.stop.side_effect = OSError("observation failed")
        module = SimpleNamespace(SELF_SAMPLES=False, run=AsyncMock(side_effect=ValueError("workload failed")))
        with patch.object(orchestrator.registry, "is_bindizr", return_value=False), \
                patch.object(orchestrator.registry, "build_adapter", return_value=adapter), \
                patch.object(orchestrator.importlib, "import_module", return_value=module), \
                patch.object(orchestrator, "ResourceSampler", return_value=sampler), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = await orchestrator.run_one("b01_crud_tps", "test", {
                "systems": {"test": {"label": "test"}},
                "resources": {"sample_interval_secs": 0.01},
            })
        self.assertIsNone(result)
        adapter.teardown.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
