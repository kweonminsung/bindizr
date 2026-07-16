"""Thin helpers around docker / docker compose used by the harness."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path


def run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


class Compose:
    """Wrapper for a single docker compose project."""

    def __init__(self, file: Path, project: str, env: dict[str, str] | None = None):
        self.file = Path(file)
        self.project = project
        self.env = env or {}

    def _base(self) -> list[str]:
        return ["docker", "compose", "-f", str(self.file), "-p", self.project]

    def up(self, *services: str, wait: bool = True) -> None:
        cmd = self._base() + ["up", "-d"]
        if wait:
            cmd.append("--wait")
        cmd += list(services)
        import os

        env = {**os.environ, **self.env}
        subprocess.run(cmd, check=True, text=True, env=env)

    def down(self) -> None:
        import os

        # Force COMPOSE_PROFILES to include all backends so `down` also stops
        # profiled DB services (Bindizr's optional mysql/postgres) and removes
        # their volumes, never leaving a container with stale data between runs.
        env = {**os.environ, **self.env}
        env["COMPOSE_PROFILES"] = "mysql,postgres"
        subprocess.run(
            self._base() + ["down", "-v", "--remove-orphans"],
            check=False, text=True, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def logs(self, service: str, tail: int = 50) -> str:
        p = run(self._base() + ["logs", "--tail", str(tail), service], check=False)
        return (p.stdout or "") + (p.stderr or "")

    def ps(self) -> str:
        return run(self._base() + ["ps"], check=False).stdout or ""

    def container_id(self, service: str) -> str | None:
        p = run(self._base() + ["ps", "-q", service], check=False)
        out = (p.stdout or "").strip()
        return out or None


def stats(container_ids: list[str]) -> list[dict]:
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
