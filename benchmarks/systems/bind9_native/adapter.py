"""Native BIND9 adapter — a plain authoritative primary, the DNS-query baseline.

Used by Benchmark 8 to establish the reference QPS that "Bindizr + BIND9" is
compared against: if Bindizr adds no query-path overhead, the two should match.
Records are bulk-loaded by writing the zone file and reloading (same mechanism
as the rndc adapter); per-record CRUD is not the focus here.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from adapters.base import Endpoint  # noqa: E402
from adapters.bind9_zonefile import Bind9ZoneFileAdapter  # noqa: E402
from lib import dockerutil  # noqa: E402

DNS_PORT = 15358
ZONE = "bench.example"
SERVER = "127.0.0.1"
ZONE_PATH = "/var/cache/bind/bench.example.zone"


class Bind9NativeAdapter(Bind9ZoneFileAdapter):
    key = "bind9_native"
    resource_services = ["bind9"]

    def __init__(self, cfg: dict, project: str):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(cfg, project, Endpoint(SERVER, DNS_PORT), ZONE, ZONE_PATH)
        self.compose = dockerutil.Compose(HERE / "compose.yml", project)

    async def setup(self) -> None:
        """Start the benchmark system and wait for it to become ready."""
        self.compose.down()  # clean slate: remove any leftovers from a prior run
        self.compose.up("bind9", wait=False)
        self.cid = self.compose.resolve_container_id("bind9")
        await self._wait_dns()

    async def _wait_dns(self, timeout: int = 60) -> None:
        """Wait until the system answers DNS queries."""
        for _ in range(timeout * 2):
            proc = await asyncio.create_subprocess_exec(
                "dig", f"@{SERVER}", "-p", str(DNS_PORT), ZONE, "SOA", "+short",
                "+tries=1", "+time=3",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await proc.communicate()
            if out.decode().strip():
                return
            await asyncio.sleep(0.5)
        raise RuntimeError("Native BIND9 did not become ready")

    async def teardown(self) -> None:
        """Stop the benchmark system and release its resources."""
        self.compose.down()

    async def create_zone(self, zone: str) -> None:
        """Create the zone used by the benchmark."""
        return

    async def delete_zone(self, zone: str) -> None:
        """Remove the benchmark zone and its records."""
        return
