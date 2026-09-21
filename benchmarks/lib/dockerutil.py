"""Thin helpers around docker / docker compose used by the harness."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a command with optional output capture and exit-status checking."""
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def arm_overrides_enabled() -> bool:
    """Whether BENCH_ARM asks for each system's `compose.arm.yml`."""
    return os.environ.get("BENCH_ARM", "").lower() in ("1", "true", "yes")


class Compose:
    """Wrapper for a single docker compose project."""

    def __init__(self, file: Path, project: str, env: dict[str, str] | None = None):
        """Store the Compose file, project name, and environment overrides. A
        system's `compose.arm.yml` is layered on top when BENCH_ARM is set."""
        self.file = Path(file)
        self.project = project
        self.env = env or {}
        self.files = [self.file]
        arm_override = self.file.with_name("compose.arm.yml")
        if arm_overrides_enabled() and arm_override.exists():
            self.files.append(arm_override)

    def _base(self) -> list[str]:
        """Build the Docker Compose command prefix for this project."""
        cmd = ["docker", "compose"]
        for file in self.files:
            cmd += ["-f", str(file)]
        return cmd + ["-p", self.project]

    def up(self, *services: str, wait: bool = True) -> None:
        """Start the requested Compose services and optionally wait for readiness."""
        # --build so a system built from this repository is measured as it
        # stands now rather than from a stale image.
        cmd = self._base() + ["up", "-d", "--build"]
        if wait:
            cmd.append("--wait")
        cmd += list(services)
        subprocess.run(cmd, check=True, text=True, env={**os.environ, **self.env})

    def down(self) -> None:
        """Remove the project containers, volumes, and orphaned services."""

        # All profiles, so `down` also removes the optional database and
        # secondary services and their volumes. A profile missing here leaves
        # its containers running into the next system's run.
        env = {**os.environ, **self.env}
        profiles = ["mysql", "postgres", *self.env.get("COMPOSE_PROFILES", "").split(",")]
        env["COMPOSE_PROFILES"] = ",".join(dict.fromkeys(p for p in profiles if p))
        subprocess.run(
            self._base() + ["down", "-v", "--remove-orphans"],
            check=False, text=True, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def read_logs(self, service: str, tail: int = 50) -> str:
        """Collect recent output from a Compose service."""
        p = run(self._base() + ["logs", "--tail", str(tail), service], check=False)
        return (p.stdout or "") + (p.stderr or "")

    def resolve_container_id(self, service: str) -> str | None:
        """Resolve a Compose service name to its running container ID."""
        p = run(self._base() + ["ps", "-q", service], check=False)
        out = (p.stdout or "").strip()
        return out or None


def read_stats(container_ids: list[str]) -> list[dict]:
    """One-shot `docker stats` snapshot for the given containers."""
    if not container_ids:
        return []
    p = run(
        ["docker", "stats", "--no-stream", "--format", "{{json .}}", *container_ids],
        check=False,
    )
    rows = []
    for line in (p.stdout or "").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows
