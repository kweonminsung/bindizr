"""Verify benchmark result and Compose project ownership from the normal entry points."""
import asyncio
from contextlib import redirect_stdout
from datetime import datetime
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import orchestrator
from lib import docker, report, settings


class OwnershipTests(TestCase):
    def test_same_second_reserves_distinct_result_directories(self):
        """Verify that same-second invocations reserve their own default directories."""
        stamp = datetime(2026, 7, 10, 23, 38, 56)
        with TemporaryDirectory() as directory, patch.object(settings, "ROOT", Path(directory)), \
                patch.dict(os.environ, {"BENCH_RESULTS_DIR": ""}), patch.object(settings, "datetime") as clock:
            clock.now.return_value = stamp
            with settings.results_directory() as first, settings.results_directory() as second:
                self.assertNotEqual(first, second)
                self.assertEqual(first.name, "results_20260710_233856")
                self.assertRegex(second.name, r"^results_\d{8}_\d{6}$")
                self.assertTrue(first.is_dir() and second.is_dir())

    def test_override_is_exclusive_until_reporting_finishes(self):
        """Verify that two writers cannot share the same explicit results directory."""
        with TemporaryDirectory() as directory, patch.dict(os.environ, {"BENCH_RESULTS_DIR": directory}):
            with settings.results_directory():
                with self.assertRaisesRegex(RuntimeError, "already using"):
                    with settings.results_directory():
                        self.fail("a second writer acquired the directory")
            with settings.results_directory() as path:
                self.assertEqual(path, Path(directory))

    def test_launcher_leaves_other_projects_alone(self):
        """Verify that the shell entry point never lists or cleans unrelated projects."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            docker_stub = root / "docker"
            python_stub = root / "python-stub"
            docker_stub.write_text(
                '#!/bin/bash\nprintf "%s\\n" "$*" >> "$BENCH_TEST_DOCKER_LOG"\n'
                '[[ "$*" == "compose ls -q" ]] && printf "%s\\n" "bench-other-run"\nexit 0\n')
            python_stub.write_text("#!/bin/bash\nexit 0\n")
            for executable in (docker_stub, python_stub):
                executable.chmod(0o700)
            log = root / "docker.log"
            subprocess.run(
                ["bash", str(settings.ROOT / "benchmark.sh")], check=True, capture_output=True,
                env={**os.environ, "PYTHON": str(python_stub), "BENCH_TEST_DOCKER_LOG": str(log),
                     "PATH": f'{root}:{os.environ["PATH"]}'},
            )
            self.assertEqual(log.read_text().splitlines(), ["info"])

    def test_signal_during_compose_always_finishes_teardown(self):
        """Verify that SIGTERM during either Compose phase leaves no unfinished teardown."""
        script = """
import asyncio
import os
from pathlib import Path
import signal
import orchestrator
from lib.docker import Compose

async def stop_during_compose():
    log = Path(os.environ["BENCH_TEST_DOCKER_LOG"])
    phase = os.environ["BENCH_TEST_PHASE"]
    while not log.is_file() or f" {phase} " not in log.read_text():
        await asyncio.sleep(0.01)
    os.kill(os.getpid(), signal.SIGTERM)

async def workload(args):
    compose = Compose(Path("compose.yml"), "bench-this-run")
    asyncio.create_task(stop_during_compose())
    try:
        await compose.up("powerdns")
    finally:
        await compose.down()

orchestrator.main_async = workload
raise SystemExit(asyncio.run(orchestrator.run_until_stopped(None)))
"""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            docker_stub = root / "docker"
            docker_stub.write_text(
                '#!/bin/bash\nprintf "%s\\n" "$*" >> "$BENCH_TEST_DOCKER_LOG"\n'
                'if [[ "$BENCH_TEST_PHASE" == up && "$*" == *" up "* ]]; then\n'
                '  "$BENCH_TEST_PYTHON" -c "import time; time.sleep(30)"\n'
                'elif [[ "$*" == *" down "* ]]; then\n'
                '  "$BENCH_TEST_PYTHON" -c "import time; time.sleep(0.1)"\n'
                '  printf "%s\\n" "teardown complete" >> "$BENCH_TEST_DOCKER_LOG"\n'
                'fi\n')
            docker_stub.chmod(0o700)
            log = root / "docker.log"
            environment = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path),
                           "BENCH_TEST_DOCKER_LOG": str(log), "BENCH_TEST_PYTHON": sys.executable,
                           "PATH": f'{root}:{os.environ["PATH"]}'}
            for phase in ("up", "down"):
                with self.subTest(phase=phase):
                    log.unlink(missing_ok=True)
                    result = subprocess.run(
                        [sys.executable, "-c", script], cwd=settings.ROOT,
                        env={**environment, "BENCH_TEST_PHASE": phase},
                        capture_output=True, text=True, timeout=5,
                    )
                    self.assertEqual(result.returncode, 143, result.stderr)
                    self.assertEqual(log.read_text().splitlines(), [
                        "compose -f compose.yml -p bench-this-run up -d --build --wait powerdns",
                        "compose -f compose.yml -p bench-this-run down -v --remove-orphans",
                        "teardown complete",
                    ])


class RunTests(IsolatedAsyncioTestCase):
    async def test_compose_tears_down_only_after_acquiring_a_project(self):
        """Verify that teardown skips unused instances and covers a partial startup failure."""
        project = docker.project_name("bind9_rndc")
        self.assertNotEqual(project, docker.project_name("bind9_rndc"))
        compose = docker.Compose(Path("compose.yml"), project)
        failure = subprocess.CalledProcessError(1, "compose up")
        with patch.object(docker.process, "run", AsyncMock(side_effect=[failure, subprocess.CompletedProcess([], 0)])) as run:
            await compose.down()
            run.assert_not_called()
            with self.assertRaises(subprocess.CalledProcessError):
                await compose.up("bind9")
            await compose.down()
            await compose.down()
        self.assertEqual(run.call_count, 2)
        self.assertEqual(list(run.call_args.args[-5:]), ["-p", project, "down", "-v", "--remove-orphans"])

    async def test_subset_replaces_only_its_own_raw_data(self):
        """Verify that a subset rerun persists current failures and keeps unrelated raw data."""
        benchmark = "b08_query_perf"
        other = "b01_crud_tps"
        failure = {"system": "mock", "status": "FAILED"}
        config = {"benchmarks": {benchmark: ["mock"]}, "systems": {"mock": {"enabled": True}}}
        with TemporaryDirectory() as directory, patch.dict(os.environ, {"BENCH_RESULTS_DIR": directory}):
            root = Path(directory)
            report.replace_results(root, benchmark, [{"qps": 2}])
            report.replace_results(root, other, [{"record_rate": 3}])
            with patch.object(settings, "load", return_value=config), \
                    patch.object(orchestrator, "run_one", AsyncMock(return_value=[failure])), \
                    patch.object(orchestrator.envmod, "collect", return_value={}), \
                    patch.object(report, "write_report") as render, redirect_stdout(io.StringIO()):
                await orchestrator.main_async(SimpleNamespace(benchmarks=[benchmark], systems=None))
            self.assertEqual(json.loads((root / "raw" / f"{benchmark}.json").read_text())["results"], [failure])
            self.assertEqual(json.loads((root / "raw" / f"{other}.json").read_text())["results"], [{"record_rate": 3}])
            render.assert_called_once_with(root, {}, config)

    async def test_interrupted_subset_keeps_the_last_completed_report(self):
        """Verify that cancelled workloads leave the previous report and raw rows usable."""
        benchmark = "b08_query_perf"
        config = {"benchmarks": {benchmark: ["mock"]}, "systems": {"mock": {"enabled": True}}}
        with TemporaryDirectory() as directory, patch.dict(os.environ, {"BENCH_RESULTS_DIR": directory}):
            root = Path(directory)
            report.replace_results(root, benchmark, [{"qps": 2}])
            raw = root / "raw" / f"{benchmark}.json"
            previous = raw.read_bytes()
            summary = root / "performance.json"
            summary.write_text("previous report")
            with patch.object(settings, "load", return_value=config), \
                    patch.object(orchestrator, "run_one", AsyncMock(side_effect=asyncio.CancelledError)), \
                    self.assertRaises(asyncio.CancelledError):
                await orchestrator.main_async(SimpleNamespace(benchmarks=[benchmark], systems=None))
            self.assertEqual(raw.read_bytes(), previous)
            self.assertEqual(summary.read_text(), "previous report")
