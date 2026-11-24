"""Manage Docker Compose projects and read container resource usage."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
from pathlib import Path
from uuid import uuid4

from . import process

COMPOSE_INSPECT_TIMEOUT_SECS = 10.0


def run(cmd: list[str], check: bool = True, capture: bool = True,
        timeout: float | None = None) -> subprocess.CompletedProcess:
    """Run a command with optional output capture and exit-status checking."""
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        timeout=timeout,
    )


def is_arm_override_enabled() -> bool:
    """Return whether BENCH_ARM asks for each system's `compose.arm.yml`."""
    return os.environ.get("BENCH_ARM", "").lower() in ("1", "true", "yes")


def project_name(label: str) -> str:
    """Return a unique Compose project name for this workload's resources."""
    return f"bench-{label.replace('_', '-')}-{uuid4().hex[:16]}"


class Compose:
    """One Docker Compose project and its services."""

    def __init__(self, file: Path, project: str, env: dict[str, str] | None = None):
        """Store the Compose project and layer `compose.arm.yml` when BENCH_ARM is enabled."""
        self.file = Path(file)
        self.project = project
        self._started = False
        self.env = env or {}
        self.files = [self.file]
        arm_override = self.file.with_name("compose.arm.yml")

        if is_arm_override_enabled() and arm_override.exists():
            self.files.append(arm_override)

    def _build_command_prefix(self) -> list[str]:
        """Build the Docker Compose command prefix for this project."""
        cmd = ["docker", "compose"]
        for file in self.files:
            cmd += ["-f", str(file)]
        return cmd + ["-p", self.project]

    async def up(self, *services: str, wait: bool = True) -> None:
        """Start the requested Compose services and optionally wait for readiness."""
        # --build so a system built from this repository is measured as it
        # stands now rather than from a stale image.
        cmd = self._build_command_prefix() + ["up", "-d", "--build"]

        if wait:
            cmd.append("--wait")

        cmd += list(services)
        # Even an unsuccessful `up` can have created some resources.
        self._started = True
        result = await process.run(
            *cmd, stdout=None, stderr=None, timeout=None, env={**os.environ, **self.env}, own_process_group=True,
        )
        result.check_returncode()

    async def down(self) -> None:
        """Remove resources acquired by this instance, including partial starts."""
        if not self._started:
            return

        cleanup = asyncio.create_task(self._down())
        cancellation = None
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError as error:
                cancellation = error
            except Exception:
                break
        try:
            cleanup.result()
        except Exception:
            if cancellation is None:
                raise
            logging.getLogger(__name__).exception("failed to remove Compose project %s", self.project)
        if cancellation is not None:
            raise cancellation

    async def _down(self) -> None:
        """Run the bounded cleanup command with every applicable profile."""
        # All profiles, so `down` also removes the optional database and
        # secondary services and their volumes. A profile missing here leaves
        # its containers running into the next system's run.
        env = {**os.environ, **self.env}
        profiles = ["mysql", "postgres", *self.env.get("COMPOSE_PROFILES", "").split(",")]
        env["COMPOSE_PROFILES"] = ",".join(dict.fromkeys(profile for profile in profiles if profile))
        result = await process.run(
            *self._build_command_prefix(), "down", "-v", "--remove-orphans",
            env=env, stdout=subprocess.DEVNULL, stderr=None, timeout=60, own_process_group=True,
        )
        result.check_returncode()
        self._started = False

    def read_logs(self, service: str, tail: int = 50) -> str:
        """Collect recent output from a Compose service."""
        result = run(
            self._build_command_prefix() + ["logs", "--tail", str(tail), service],
            check=False, timeout=COMPOSE_INSPECT_TIMEOUT_SECS,
        )
        return (result.stdout or "") + (result.stderr or "")

    def resolve_container_id(self, service: str) -> str | None:
        """Resolve a Compose service name to its running container ID."""
        result = run(
            self._build_command_prefix() + ["ps", "-q", service],
            timeout=COMPOSE_INSPECT_TIMEOUT_SECS,
        )
        container_id = (result.stdout or "").strip()
        return container_id or None


STATS_TIMEOUT_SECS = 3.0


def read_stats(container_ids: list[str]) -> list[dict]:
    """Read one bounded snapshot so a stalled Docker CLI cannot hold the sampler."""
    if not container_ids:
        return []

    result = run(
        ["docker", "stats", "--no-stream", "--format", "{{json .}}", *container_ids],
        timeout=STATS_TIMEOUT_SECS,
    )
    rows = []

    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))

    if len(rows) != len(container_ids):
        raise RuntimeError(f"Docker reported {len(rows)} of {len(container_ids)} container samples")
    return rows
