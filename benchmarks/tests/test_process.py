"""Exercise actual local child ownership on success, timeout and cancellation."""
import asyncio
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import process


class ProcessTests(IsolatedAsyncioTestCase):
    async def test_input_output_and_nonzero_exit_reach_the_caller(self):
        """Preserve stdin, captured output, and a nonzero exit status."""
        result = await process.run(sys.executable, "-c",
                                   "import sys; print(sys.stdin.read()); "
                                   "print('failure detail',file=sys.stderr); sys.exit(7)",
                                   input=b"payload")
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b"payload\n")
        self.assertEqual(result.stderr, b"failure detail\n")

    async def test_timeout_kills_and_reaps_the_child(self):
        """Return a timeout only after the OS child has exited."""
        children = []
        spawn = asyncio.create_subprocess_exec

        async def capture(*args, **kwargs):
            """Keep the spawned child available for lifecycle assertions."""
            child = await spawn(*args, **kwargs)
            children.append(child)
            return child

        with patch.object(asyncio, "create_subprocess_exec", side_effect=capture):
            with self.assertRaises(subprocess.TimeoutExpired) as failure:
                await process.run(sys.executable, "-c", "import time; time.sleep(30)", timeout=0.05)
        self.assertEqual(failure.exception.timeout, 0.05)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)

    async def test_cancellation_reaps_the_child_before_returning(self):
        """Cancellation must reap the child before reaching its caller."""
        children = []
        spawn = asyncio.create_subprocess_exec

        async def capture(*args, **kwargs):
            """Keep the spawned child available for lifecycle assertions."""
            child = await spawn(*args, **kwargs)
            children.append(child)
            return child

        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            script = f"import pathlib,time; pathlib.Path({str(ready)!r}).touch(); time.sleep(30)"
            with patch.object(asyncio, "create_subprocess_exec", side_effect=capture):
                task = asyncio.create_task(process.run(sys.executable, "-c", script))
                try:
                    async with asyncio.timeout(2):
                        while not ready.exists():
                            await asyncio.sleep(0.005)
                finally:
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)

    async def test_repeated_cancel_during_spawn_still_reaps_the_child(self):
        """Cancellation during spawn must not abandon the eventual child."""
        spawn = asyncio.create_subprocess_exec
        acquired, release = asyncio.Event(), asyncio.Event()
        children = []

        async def delayed(*args, **kwargs):
            """Delay process acquisition so cancellation reaches the spawn boundary."""
            child = await spawn(*args, **kwargs)
            children.append(child)
            acquired.set()
            await release.wait()
            return child

        with patch.object(asyncio, "create_subprocess_exec", side_effect=delayed):
            task = asyncio.create_task(process.run(sys.executable, "-c", "import time; time.sleep(30)"))
            try:
                await asyncio.wait_for(acquired.wait(), 2)
                task.cancel()
                await asyncio.sleep(0)
                task.cancel()
            finally:
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
        self.assertIsNotNone(children[0].returncode)

    async def test_spawn_failure_is_preserved(self):
        """Preserve the original error when no child could be spawned."""
        error = FileNotFoundError("missing command")
        with patch.object(asyncio, "create_subprocess_exec", side_effect=error):
            with self.assertRaises(FileNotFoundError) as failure:
                await process.run("missing-command")
        self.assertIs(failure.exception, error)

    async def test_cleanup_failure_does_not_replace_the_original_error(self):
        """A cleanup error must not hide the communication failure."""
        error = ValueError("communication failed")
        child = SimpleNamespace(returncode=None, communicate=AsyncMock(side_effect=error),
                                kill=Mock(side_effect=OSError("cleanup failed")))
        with patch.object(asyncio, "create_subprocess_exec", AsyncMock(return_value=child)), \
                self.assertLogs("lib.process", level="ERROR"), \
                self.assertRaises(ValueError) as failure:
            await process.run("unit-command")
        self.assertIs(failure.exception, error)
