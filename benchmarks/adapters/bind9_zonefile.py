"""Shared BIND9 record operations using zone files and rndc reload."""
from __future__ import annotations

import asyncio

from .base import Endpoint
from .zonefile import ZoneFileAdapter
from lib import process, zonefile


class Bind9ZoneFileAdapter(ZoneFileAdapter):
    """Store records, write the primary's zone file, and reload it through RNDC."""

    server_name = "BIND9"

    def __init__(self, config: dict, project: str, endpoint: Endpoint, zone: str,
                 zone_path: str):
        """Initialize the primary endpoint, zone file, and record state."""
        super().__init__(config, project, endpoint, zone)
        self._zone_path = zone_path
        self.serial = 2
        self.cid: str | None = None

    async def _run(self, *cmd: str, input: bytes | None = None) -> bool:
        """Run a container command with optional input and report its exit status."""
        proc = await process.run(*cmd, input=input, timeout=60,
                                 stdout=asyncio.subprocess.DEVNULL,
                                 stderr=asyncio.subprocess.DEVNULL)
        return proc.returncode == 0

    async def _flush_and_reload(self, records: dict[str, dict]) -> bool:
        """Write a candidate snapshot and accept it after the RNDC reload succeeds."""
        self.serial += 1
        text = zonefile.build_zone_file(self._zone, self.serial, records.values())

        # Write inside the container so BIND sees each file modification time.
        ok = await self._run("docker", "exec", "-i", self.cid, "tee", self._zone_path,
                             input=text.encode())

        if not ok:
            return False

        if not await self._run("docker", "exec", self.cid, "rndc", "reload", self._zone):
            return False
        return True
