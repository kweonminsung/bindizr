"""Run bounded async commands and reap their local children.

Commands inside a Docker container may outlive the local CLI.
"""
from __future__ import annotations

import asyncio
import logging
import subprocess


async def run(*command: str, input: bytes | None = None,
              stdout: int = subprocess.PIPE, stderr: int = subprocess.PIPE,
              timeout: float = 30.0) -> subprocess.CompletedProcess:
    """Run a command, reaping its child on timeout or cancellation."""
    started = asyncio.create_task(asyncio.create_subprocess_exec(
        *command, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=stdout, stderr=stderr))
    exchange = None

    try:
        # Cancellation after fork must still leave a child we can reap.
        child = await asyncio.shield(started)
        exchange = asyncio.create_task(child.communicate(input))
        stdout_bytes, stderr_bytes = await asyncio.wait_for(asyncio.shield(exchange), timeout)
        return subprocess.CompletedProcess(command, child.returncode, stdout_bytes, stderr_bytes)
    except BaseException as error:
        cleanup = asyncio.create_task(_stop(started, exchange))
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                # Repeated cancellation cannot abandon the same child again.
                continue
            except Exception:
                break
        try:
            cleanup.result()
        except Exception:
            logging.getLogger(__name__).error("command cleanup failed", exc_info=True)

        if isinstance(error, TimeoutError):
            raise subprocess.TimeoutExpired(command, timeout) from error
        raise


async def _stop(started: asyncio.Task, exchange: asyncio.Task | None) -> None:
    """Acquire an in-flight spawn, stop its child, and finish draining its pipes."""
    try:
        child = await started
    except Exception:
        # A failed spawn owns no child; the original error reaches run's caller.
        return

    if child.returncode is None:
        try:
            child.kill()
        except ProcessLookupError:
            pass

    if exchange is not None:
        try:
            await exchange
        finally:
            await child.wait()
    else:
        await child.communicate()
