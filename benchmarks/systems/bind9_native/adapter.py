"""Provide the standalone BIND9 primary baseline for Benchmark 8 QPS comparisons.

Bulk-load a zone file and reload as in the rndc adapter; per-record CRUD is secondary.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from adapters.base import Endpoint  # noqa: E402
from adapters.bind9_zonefile import Bind9ZoneFileAdapter  # noqa: E402
from lib import docker, process  # noqa: E402

DNS_PORT = 15358
ZONE = "bench.example"
SERVER = "127.0.0.1"
ZONE_PATH = "/var/cache/bind/bench.example.zone"


class Bind9NativeAdapter(Bind9ZoneFileAdapter):
    key = "bind9_native"
    resource_services = ["bind9"]

    def __init__(self, config: dict, project: str):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(config, project, Endpoint(SERVER, DNS_PORT), ZONE, ZONE_PATH)
        self.compose = docker.Compose(HERE / "compose.yml", project)

    async def setup(self) -> None:
        """Start the benchmark system and wait for it to become ready."""
        self.compose.down()
        self.compose.up("bind9", wait=False)
        self.cid = self.compose.resolve_container_id("bind9")
        await self._wait_dns()

    async def _wait_dns(self, timeout: int = 60) -> None:
        """Wait until the system answers DNS queries."""
        for _ in range(timeout * 2):
            proc = await process.run(
                "dig", f"@{SERVER}", "-p", str(DNS_PORT), ZONE, "SOA", "+short",
                "+tries=1", "+time=3",
                timeout=5, stderr=asyncio.subprocess.DEVNULL)

            if proc.stdout.decode().strip():
                return

            await asyncio.sleep(0.5)

        raise RuntimeError("Native BIND9 did not become ready")

    async def teardown(self) -> None:
        """Stop the benchmark system and release its resources."""
        self.compose.down()

    async def create_zone(self, zone: str) -> None:
        """Create the zone used by the benchmark."""
        return
