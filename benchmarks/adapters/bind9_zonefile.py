"""Shared BIND9 record operations using zone files and rndc reload."""
from __future__ import annotations

import asyncio

from .base import Endpoint
from .zonefile import ZoneFileAdapter
from lib import process, zonefile


class Bind9ZoneFileAdapter(ZoneFileAdapter):
    """Store records, write the primary's zone file, and reload it through RNDC."""

    server_name = "BIND9"

    def __init__(self, config: dict, project: str, endpoint: Endpoint, zone_name: str,
                 zone_path: str):
        """Initialize the primary endpoint, zone file, and record state."""
        super().__init__(config, project, endpoint, zone_name)
        self._zone_path = zone_path
        self.serial = 2
        self.container_id: str | None = None

    async def setup(self) -> None:
        """Start BIND9 and wait for its configured zone to answer."""
        await self.compose.up("bind9", wait=False)
        self.container_id = self.compose.resolve_container_id("bind9")
        if not self.container_id:
            raise RuntimeError(f"{self.server_name} container could not be resolved")
        await self._wait_dns()

    async def _wait_dns(self, timeout: int = 60) -> None:
        """Wait until the configured zone answers SOA queries."""
        for _ in range(timeout * 2):
            result = await process.run(
                "dig", f"@{self._endpoint.host}", "-p", str(self._endpoint.port),
                self._zone_name, "SOA", "+short", "+tries=1", "+time=3",
                timeout=5, stderr=asyncio.subprocess.DEVNULL)

            if result.returncode == 0 and result.stdout.decode().strip():
                return
            await asyncio.sleep(0.5)

        raise RuntimeError(f"{self.server_name} did not become ready")

    async def teardown(self) -> None:
        """Stop the benchmark system and release its resources."""
        await self.compose.down()

    async def create_zone(self, zone_name: str) -> None:
        """Use the primary zone already defined in the BIND9 configuration."""
        return

    async def _run(self, *cmd: str, input: bytes | None = None) -> bool:
        """Run a container command with optional input and report its exit status."""
        result = await process.run(*cmd, input=input, timeout=60,
                                 stdout=asyncio.subprocess.DEVNULL,
                                 stderr=asyncio.subprocess.DEVNULL)
        return result.returncode == 0

    async def _flush_and_reload(self, records: dict[str, dict]) -> bool:
        """Write a candidate snapshot and accept it after the RNDC reload succeeds."""
        self.serial += 1
        text = zonefile.build_zone_file(self._zone_name, self.serial, records.values())

        # Write inside the container so BIND sees each file modification time.
        ok = await self._run("docker", "exec", "-i", self.container_id, "tee", self._zone_path,
                             input=text.encode())

        if not ok:
            return False

        if not await self._run("docker", "exec", self.container_id, "rndc", "reload", self._zone_name):
            return False
        return True
